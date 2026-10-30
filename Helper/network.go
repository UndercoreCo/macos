package main

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type commandRunner func(string, ...string) (string, error)

func command(path string, args ...string) (string, error) {
	return commandContext(context.Background(), path, args...)
}
func commandContext(parent context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	b, e := c.Output()
	return string(b), e
}

type undoStack struct{ actions []func() error }

func (s *undoStack) add(f func() error) { s.actions = append(s.actions, f) }
func (s *undoStack) close() error {
	var failures []error
	var retry []func() error
	for i := len(s.actions) - 1; i >= 0; i-- {
		if e := s.actions[i](); e != nil {
			failures = append(failures, e)
			retry = append(retry, s.actions[i])
		}
	}
	// Keep only failed cleanup actions; a final retry must not repeat successful ones.
	for left, right := 0, len(retry)-1; left < right; left, right = left+1, right-1 {
		retry[left], retry[right] = retry[right], retry[left]
	}
	s.actions = retry
	return errors.Join(failures...)
}
func interfaceForEndpoint(run commandRunner, endpoint string) (string, error) {
	text, e := run("/sbin/route", "-n", "get", "-inet", endpoint)
	if e != nil {
		return "", e
	}
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "interface:" {
			name := parts[1]
			if strings.HasPrefix(name, "utun") || name == "lo0" {
				return "", errors.New("existing tunnel")
			}
			intf, e := net.InterfaceByName(name)
			if e != nil || intf.Flags&net.FlagUp == 0 {
				return "", errors.New("no interface")
			}
			return name, nil
		}
	}
	return "", errors.New("no interface")
}
func configureNetwork(run commandRunner, name string, p profile, undo *undoStack) error {
	for _, a := range p.addresses {
		var args []string
		if a.Addr().Is4() {
			args = []string{name, "inet", a.Addr().String(), a.Addr().String(), "alias"}
		} else {
			args = []string{name, "inet6", a.String(), "alias"}
		}
		if _, e := run("/sbin/ifconfig", args...); e != nil {
			return e
		}
	}
	if _, e := run("/sbin/ifconfig", name, "mtu", strconv.Itoa(p.mtu), "up"); e != nil {
		return e
	}
	// Leave the original default route intact. Interface-bound transport uses it.
	// IPv6 is captured too: without an IPv6 peer route the engine drops it, avoiding fallback.
	for _, route := range [][2]string{{"-inet", "0.0.0.0/1"}, {"-inet", "128.0.0.0/1"}, {"-inet6", "::/1"}, {"-inet6", "8000::/1"}} {
		family, destination := route[0], route[1]
		if _, e := run("/sbin/route", "-n", "add", family, "-net", destination, "-interface", name); e != nil {
			return e
		}
		undo.add(func() error {
			// Do not remove a route replaced by another network manager meanwhile.
			current, e := run("/sbin/route", "-n", "get", family, destination)
			if e != nil {
				return nil
			} // Interface teardown may already have removed it.
			owned := false
			for _, line := range strings.Split(current, "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "interface:" && fields[1] == name {
					owned = true
				}
			}
			if !owned {
				return nil
			}
			_, e = run("/sbin/route", "-n", "delete", family, "-net", destination, "-interface", name)
			return e
		})
	}
	return nil
}
