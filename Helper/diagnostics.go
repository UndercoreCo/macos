package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Only numeric counters leave the engine. Never forward its raw UAPI: it has keys.
func transportCounters(engine engineStateReader) string {
	state, err := engine.IpcGet()
	if err != nil {
		return ""
	}
	counters := map[string]uint64{}
	for _, line := range strings.Split(state, "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			continue
		}
		switch pair[0] {
		case "last_handshake_time_sec", "tx_bytes", "rx_bytes":
			value, err := strconv.ParseUint(pair[1], 10, 64)
			if err != nil {
				return ""
			}
			counters[pair[0]] = value
		}
	}
	handshake := 0
	if counters["last_handshake_time_sec"] > 0 {
		handshake = 1
	}
	return fmt.Sprintf("stats=%d,%d,%d", handshake, counters["tx_bytes"], counters["rx_bytes"])
}

func probeOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "timeout"
	}
	return "failed"
}

// Fixed test destinations, no HTTP requests or user traffic capture. A failed
// provider is tolerated when the other provider establishes verified TLS.
type healthProbe struct{ route, internet, dns bool }
type healthTracker struct{ failures int }

func (h *healthTracker) observe(p healthProbe) string {
	if !p.route {
		h.failures++
		return "health=route"
	}
	if p.internet && p.dns {
		h.failures = 0
		return "health=ok"
	}
	h.failures++
	if h.failures < 2 {
		return "health=checking"
	}
	if p.internet {
		return "health=dns"
	}
	return "health=degraded"
}
func monitorConnectionHealth(ctx context.Context, out io.Writer, tunnel, endpoint, physical string, dns []netip.Addr, requests <-chan string) {
	monitorHealth(ctx, out, func(ctx context.Context) healthProbe {
		return probeConnection(ctx, out, tunnel, endpoint, physical, dns)
	}, 4*time.Second, 60*time.Second, 5*time.Second, requests)
}
func monitorHealth(ctx context.Context, out io.Writer, probe func(context.Context) healthProbe, initial, healthy, retry time.Duration, triggers ...<-chan string) {
	var requests <-chan string
	if len(triggers) > 0 {
		requests = triggers[0]
	}
	timer := time.NewTimer(initial)
	defer timer.Stop()
	tracker := healthTracker{}
	previous := ""
	var results chan healthProbe
	var cancelProbe context.CancelFunc
	stopProbe := func() {
		if cancelProbe != nil {
			cancelProbe()
			<-results
			cancelProbe = nil
			results = nil
		}
	}
	defer stopProbe()
	startProbe := func(request string) {
		stopProbe()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if request != "" {
			tracker = healthTracker{}
			previous = "health=checking"
			fmt.Fprintln(out, "check_started="+request)
			fmt.Fprintln(out, previous)
		}
		probeCtx, cancel := context.WithCancel(ctx)
		cancelProbe = cancel
		result := make(chan healthProbe, 1)
		results = result
		go func() { result <- probe(probeCtx) }()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-requests:
			if ctx.Err() != nil {
				return
			}
			startProbe(request)
		case <-timer.C:
			if ctx.Err() != nil {
				return
			}
			startProbe("")
		case result := <-results:
			cancelProbe()
			cancelProbe = nil
			results = nil
			if ctx.Err() != nil {
				return
			}
			status := tracker.observe(result)
			if status != previous {
				fmt.Fprintln(out, status)
				previous = status
			}
			delay := retry
			if status == "health=ok" {
				delay = healthy
			} else if tracker.failures >= 2 {
				delay = 15 * time.Second
			}
			timer.Reset(delay)
		}
	}
}
func probeConnection(parent context.Context, out io.Writer, tunnel, endpoint, physical string, dns []netip.Addr) healthProbe {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	emit := func(name string, err error) {
		if ctx.Err() == nil {
			fmt.Fprintf(out, "probe_%s=%s\n", name, probeOutcome(err))
		}
	}
	run := func(path string, args ...string) (string, error) { return commandContext(ctx, path, args...) }
	if err := verifyEndpointRoute(run, endpoint, physical); err != nil {
		emit("route", err)
		return healthProbe{}
	}
	targets := []struct{ address, name string }{{"1.1.1.1", "one.one.one.one"}, {"8.8.8.8", "dns.google"}}
	for _, target := range targets {
		text, err := run("/sbin/route", "-n", "get", "-inet", target.address)
		if err != nil || routeFields(text)["interface"] != tunnel {
			emit("route", errors.New("route"))
			return healthProbe{}
		}
	}
	emit("route", nil)
	var group sync.WaitGroup
	results := make(chan bool, 2)
	for i, target := range targets {
		group.Add(1)
		go func(i int, address, name string) {
			defer group.Done()
			probeCtx, done := context.WithTimeout(ctx, 6*time.Second)
			defer done()
			socket, err := (&net.Dialer{}).DialContext(probeCtx, "tcp4", address+":443")
			label := "tcp"
			tlsLabel := "tls"
			if i == 1 {
				label = "fallback_tcp"
				tlsLabel = "fallback_tls"
			}
			emit(label, err)
			if err != nil {
				results <- false
				return
			}
			defer socket.Close()
			secure := tls.Client(socket, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
			err = secure.HandshakeContext(probeCtx)
			emit(tlsLabel, err)
			results <- err == nil
		}(i, target.address, target.name)
	}
	var systemDNS bool
	group.Add(1)
	go func() {
		defer group.Done()
		probeCtx, done := context.WithTimeout(ctx, 6*time.Second)
		defer done()
		_, err := net.DefaultResolver.LookupNetIP(probeCtx, "ip4", "example.com")
		emit("system_dns", err)
		systemDNS = err == nil
	}()
	// Direct DNS gives useful diagnostic separation without deciding health by itself.
	group.Add(1)
	go func() {
		defer group.Done()
		if len(dns) == 0 {
			return
		}
		server := dns[0]
		for _, address := range dns {
			if address.Is4() {
				server = address
				break
			}
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server.String(), "53"))
		}}
		probeCtx, done := context.WithTimeout(ctx, 6*time.Second)
		defer done()
		_, err := resolver.LookupNetIP(probeCtx, "ip4", "example.com")
		emit("direct_dns", err)
	}()
	group.Wait()
	close(results)
	internet := false
	for result := range results {
		internet = internet || result
	}
	emit("complete", nil)
	return healthProbe{route: true, internet: internet, dns: systemDNS}
}
