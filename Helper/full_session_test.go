package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"net"
	"os"
	"testing"
	"time"
)

// Explicit diagnostic of the production setup. Briefly changes routes/DNS;
// always closes the session before reporting. Never part of normal test runs.
func TestFullSessionTransport(t *testing.T) {
	path := os.Getenv("UNDERCORE_TEST_PROFILE")
	if os.Getenv("UNDERCORE_FULL_SESSION") != "1" || path == "" || os.Geteuid() != 0 {
		t.Skip("explicit full-tunnel diagnostic only")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("profile unavailable")
	}
	p, err := parseProfile(data)
	clear(data)
	if err != nil {
		t.Fatal("invalid profile")
	}

	for attempt := 0; attempt < 2; attempt++ {
		t.Run(fmt.Sprintf("connection_%d", attempt+1), func(t *testing.T) {
			// Force the real Darwin cache condition behind the regression before setup.
			probe, err := net.DialTimeout("udp4", p.endpoint, time.Second)
			if err != nil {
				t.Fatal("cache warmup unavailable")
			}
			probe.Write([]byte{0})
			probe.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			s, err := startSession(ctx, p, "bounded-diagnostic")
			if err != nil {
				switch err.Error() {
				case "endpoint bypass route unavailable", "endpoint bypass route lost", "endpoint physical route changed", "endpoint gateway unavailable", "dns failed":
					t.Fatal(err.Error())
				default:
					t.Fatal("session setup failed (other)")
				}
			}
			defer s.close()

			socket, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp4", "1.1.1.1:443")
			t.Log("tcp=" + probeOutcome(err))
			if err == nil {
				socket.SetDeadline(time.Now().Add(5 * time.Second))
				secure := tls.Client(socket, &tls.Config{ServerName: "one.one.one.one", MinVersion: tls.VersionTLS12})
				err = secure.HandshakeContext(ctx)
				socket.Close()
				t.Log("tls=" + probeOutcome(err))
			}
			if err != nil {
				t.Error("full-tunnel HTTPS failed")
			}
			dnsCtx, cancelDNS := context.WithTimeout(ctx, 5*time.Second)
			_, dnsErr := net.DefaultResolver.LookupNetIP(dnsCtx, "ip4", "example.com")
			cancelDNS()
			t.Log("system_dns=" + probeOutcome(dnsErr))
			if dnsErr != nil {
				t.Error("system DNS failed")
			}
			t.Log(transportCounters(s.engine), s.diagnostics.summary())
			if cleanup := s.close(); cleanup != nil {
				t.Error("network cleanup failed")
			}
		})
	}
}
