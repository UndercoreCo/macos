package main

import (
	"errors"
	"net/netip"
	"strings"
)

// The encrypted endpoint must stay outside our /1 tunnel routes. Socket binding
// alone is not a replacement for a specific physical route on macOS.
func ensureEndpointRoute(run commandRunner, endpoint, physical string, undo *undoStack) error {
	ip, err := netip.ParseAddr(endpoint)
	if err != nil || !ip.Is4() {
		return errors.New("invalid endpoint address")
	}
	lookup := func() (map[string]string, error) {
		text, err := run("/sbin/route", "-n", "get", "-inet", endpoint)
		return routeFields(text), err
	}
	current, err := lookup()
	if err != nil {
		return err
	}
	if current["interface"] != physical {
		return errors.New("endpoint physical route changed")
	}
	// A cached WASCLONED host route is not a bypass: macOS invalidates it
	// when our more specific /1 routes are installed. RTM_ADD safely replaces
	// protocol-generated clones while preserving independently owned routes.
	// Preserve real host routes, including direct LAN neighbors.
	if current["destination"] == endpoint && !routeHasFlag(current, "WASCLONED") {
		return nil
	}
	gateway, err := netip.ParseAddr(current["gateway"])
	if err != nil || !gateway.Is4() {
		return errors.New("endpoint gateway unavailable")
	}
	gatewayText := gateway.String()
	matches := func(fields map[string]string) bool {
		return fields["destination"] == endpoint && fields["interface"] == physical && fields["gateway"] == gatewayText
	}
	if _, err := run("/sbin/route", "-n", "add", "-inet", "-host", endpoint, gatewayText); err != nil {
		// A concurrent network manager may have added an equivalent route.
		// Reuse it without claiming ownership or deleting it later.
		existing, lookupErr := lookup()
		if lookupErr == nil && matches(existing) && !routeHasFlag(existing, "WASCLONED") {
			return nil
		}
		return err
	}
	undo.add(func() error {
		fields, err := lookup()
		if err != nil {
			return err
		}
		if !matches(fields) {
			return nil
		}
		_, err = run("/sbin/route", "-n", "delete", "-inet", "-host", endpoint, gatewayText)
		return err
	})
	// A scoped cache entry can still shadow our new global route until the
	// /1 routes invalidate that cache. Validate its physical path here; validate
	// the durable exception again after full-tunnel setup.
	installed, err := lookup()
	if err != nil {
		return err
	}
	if !matches(installed) {
		return errors.New("endpoint bypass route unavailable")
	}
	return nil
}

func routeHasFlag(fields map[string]string, flag string) bool {
	for _, value := range strings.Split(strings.Trim(fields["flags"], "<>"), ",") {
		if strings.TrimSpace(value) == flag {
			return true
		}
	}
	return false
}

// Check after adding full-tunnel routes: an ephemeral route can look correct
// before that point but disappear when the routing table changes.
func verifyEndpointRoute(run commandRunner, endpoint, physical string) error {
	text, err := run("/sbin/route", "-n", "get", "-inet", endpoint)
	if err != nil {
		return err
	}
	fields := routeFields(text)
	if fields["destination"] != endpoint || fields["interface"] != physical {
		return errors.New("endpoint bypass route lost")
	}
	return nil
}
