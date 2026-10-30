package main

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func testLink(t *testing.T, values ...string) physicalInterface {
	t.Helper()
	link := physicalInterface{index: 6, flags: net.FlagUp | net.FlagRunning}
	for _, value := range values {
		ip, subnet, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatal(err)
		}
		subnet.IP = ip
		link.addresses = append(link.addresses, subnet)
	}
	return link
}

const defaultRouteFixture = "destination: default\ngateway: 192.0.2.1\ninterface: en0\nflags: <UP,GATEWAY,DONE>\n"

func TestPhysicalNetworkIgnoresVPNRoutesAndAddressOrder(t *testing.T) {
	tunnelInstalled := false
	run := func(path string, args ...string) (string, error) {
		// Destination lookups are no longer a physical-network fingerprint:
		// they may change to utun as soon as the VPN's /1 routes are installed.
		if !reflect.DeepEqual(args, []string{"-n", "get", "-inet", "-ifscope", "en0", "default"}) {
			if tunnelInstalled {
				return "interface: utun42\n", nil
			}
			return defaultRouteFixture, nil
		}
		if path != "/sbin/route" {
			t.Fatal("unexpected executable")
		}
		return defaultRouteFixture, nil
	}
	link := testLink(t, "192.0.2.20/24", "192.0.2.21/24", "2001:db8::1/64")
	read := func(string) (physicalInterface, error) { return link, nil }
	before, err := physicalSignatureWith(run, read, "en0")
	if err != nil {
		t.Fatal(err)
	}
	tunnelInstalled = true
	link = testLink(t, "2001:db8::123/64", "192.0.2.21/24", "192.0.2.20/24")
	after, err := physicalSignatureWith(run, read, "en0")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("own VPN routes, address order or IPv6 rotation triggered a network change")
	}
}

func TestPhysicalNetworkDetectsRealChanges(t *testing.T) {
	route := defaultRouteFixture
	link := testLink(t, "192.0.2.20/24")
	run := func(string, ...string) (string, error) { return route, nil }
	read := func(string) (physicalInterface, error) { return link, nil }
	baseline, err := physicalSignatureWith(run, read, "en0")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"gateway", "address", "index", "interface", "down", "no-address", "malformed", "route-error", "interface-error"} {
		t.Run(change, func(t *testing.T) {
			route = defaultRouteFixture
			link = testLink(t, "192.0.2.20/24")
			runner, reader := run, read
			switch change {
			case "gateway":
				route = strings.Replace(route, "192.0.2.1", "192.0.2.254", 1)
			case "address":
				link = testLink(t, "192.0.2.22/24")
			case "index":
				link.index = 7
			case "interface":
				route = strings.Replace(route, "en0", "en1", 1)
			case "down":
				link.flags = net.FlagUp
			case "no-address":
				link = testLink(t, "2001:db8::1/64")
			case "malformed":
				route = ""
			case "route-error":
				runner = func(string, ...string) (string, error) { return "", errors.New("unavailable") }
			case "interface-error":
				reader = func(string) (physicalInterface, error) { return physicalInterface{}, errors.New("unavailable") }
			}
			current, err := physicalSignatureWith(runner, reader, "en0")
			if err == nil && current == baseline {
				t.Fatal("real network change was ignored")
			}
		})
	}
}
