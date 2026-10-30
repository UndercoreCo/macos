package main

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type physicalInterface struct {
	index     int
	flags     net.Flags
	addresses []net.Addr
}

type interfaceReader func(string) (physicalInterface, error)

func readPhysicalInterface(name string) (physicalInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return physicalInterface{}, err
	}
	addresses, err := iface.Addrs()
	return physicalInterface{iface.Index, iface.Flags, addresses}, err
}

func physicalSignature(run commandRunner, iface string) (string, error) {
	return physicalSignatureWith(run, readPhysicalInterface, iface)
}

func physicalSignatureWith(run commandRunner, read interfaceReader, iface string) (string, error) {
	// The encrypted socket is bound to this physical interface. A destination
	// lookup changes when our own /1 tunnel routes are installed (and may resolve
	// to a cloned host route). Monitor the underlying scoped default instead.
	text, err := run("/sbin/route", "-n", "get", "-inet", "-ifscope", iface, "default")
	if err != nil {
		return "", err
	}
	fields := routeFields(text)
	gateway, err := netip.ParseAddr(fields["gateway"])
	if err != nil || !gateway.Is4() || fields["interface"] != iface || fields["destination"] != "default" {
		return "", errors.New("physical default route unavailable")
	}
	link, err := read(iface)
	if err != nil {
		return "", err
	}
	if link.index <= 0 || link.flags&net.FlagUp == 0 || link.flags&net.FlagRunning == 0 {
		return "", errors.New("physical interface unavailable")
	}
	var addresses []string
	for _, address := range link.addresses {
		prefix, err := netip.ParsePrefix(address.String())
		// Transport is IPv4-only. IPv6 privacy-address rotation must not end it.
		if err == nil && prefix.Addr().Is4() {
			addresses = append(addresses, prefix.String())
		}
	}
	if len(addresses) == 0 {
		return "", errors.New("physical IPv4 address unavailable")
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	return strings.Join(append([]string{iface, strconv.Itoa(link.index), gateway.String()}, addresses...), "|"), nil
}

func routeFields(text string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		pair := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(pair) == 2 {
			fields[pair[0]] = strings.TrimSpace(pair[1])
		}
	}
	return fields
}
