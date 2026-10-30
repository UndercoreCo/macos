package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const endpointFixture = "198.51.100.20"
const endpointHostFixture = "destination: 198.51.100.20\ngateway: 192.0.2.1\ninterface: en0\n"

func TestEndpointBypassLifecycle(t *testing.T) {
	current := defaultRouteFixture
	var mutations []string
	run := func(path string, args ...string) (string, error) {
		if path != "/sbin/route" {
			t.Fatal("unexpected executable")
		}
		switch args[1] {
		case "get":
			return current, nil
		case "add":
			if !reflect.DeepEqual(args, []string{"-n", "add", "-inet", "-host", endpointFixture, "192.0.2.1"}) {
				t.Fatal("incorrect bypass route")
			}
			current = endpointHostFixture
			mutations = append(mutations, "add")
		case "delete":
			if !reflect.DeepEqual(args, []string{"-n", "delete", "-inet", "-host", endpointFixture, "192.0.2.1"}) {
				t.Fatal("incorrect route cleanup")
			}
			current = defaultRouteFixture
			mutations = append(mutations, "delete")
		default:
			t.Fatal("unexpected route operation")
		}
		return "", nil
	}
	var undo undoStack
	if err := ensureEndpointRoute(run, endpointFixture, "en0", &undo); err != nil {
		t.Fatal(err)
	}
	// Simulate failure later during TUN/DNS setup. The endpoint route must be
	// removed along with successful earlier setup, exactly once.
	if err := undo.close(); err != nil {
		t.Fatal(err)
	}
	if err := undo.close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mutations, []string{"add", "delete"}) {
		t.Fatal("route cleanup was incomplete")
	}
}

func TestEndpointBypassPreservesOtherRoutes(t *testing.T) {
	for _, scenario := range []string{"preexisting", "concurrent", "replaced", "other-interface", "invalid-gateway", "failed-add"} {
		t.Run(scenario, func(t *testing.T) {
			current := defaultRouteFixture
			if scenario == "preexisting" {
				current = endpointHostFixture
			}
			if scenario == "other-interface" {
				current = strings.Replace(current, "en0", "utun42", 1)
			}
			if scenario == "invalid-gateway" {
				current = strings.Replace(current, "192.0.2.1", "invalid", 1)
			}
			run := func(_ string, args ...string) (string, error) {
				switch args[1] {
				case "get":
					return current, nil
				case "add":
					if scenario == "concurrent" {
						current = endpointHostFixture
						return "", errors.New("already exists")
					}
					if scenario == "failed-add" {
						return "", errors.New("failed")
					}
					current = endpointHostFixture
					return "", nil
				case "delete":
					t.Fatal("removed a foreign or unowned route")
				}
				return "", nil
			}
			var undo undoStack
			err := ensureEndpointRoute(run, endpointFixture, "en0", &undo)
			mustFail := scenario == "other-interface" || scenario == "invalid-gateway" || scenario == "failed-add"
			if (err != nil) != mustFail {
				t.Fatal("unexpected route validation result")
			}
			if scenario == "replaced" {
				current = strings.Replace(current, "192.0.2.1", "192.0.2.254", 1)
			}
			if err := undo.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type fakeEngineState struct {
	state string
	err   error
}

func (s fakeEngineState) IpcGet() (string, error) { return s.state, s.err }

func TestConnectedRequiresHandshake(t *testing.T) {
	for _, test := range []struct {
		name, state string
		elapsed     time.Duration
		err         error
		want        string
	}{
		{"created", "last_handshake_time_sec=0\n", 3 * time.Second, nil, "connecting"},
		{"timeout", "last_handshake_time_sec=0\n", 20 * time.Second, nil, "server_unreachable"},
		{"confirmed", "private_key=SECRET\nlast_handshake_time_sec=123456\n", time.Second, nil, "connected"},
		{"late confirmation", "last_handshake_time_sec=123456\n", 30 * time.Second, nil, "connected"},
		{"malformed", "last_handshake_time_sec=invalid\n", time.Second, nil, "connecting"},
		{"engine error", "last_handshake_time_sec=123456\n", time.Second, errors.New("SECRET"), "connecting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := transportStatus(fakeEngineState{test.state, test.err}, test.elapsed); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestCountersDoNotExposeEngineState(t *testing.T) {
	state := "private_key=SECRET\nendpoint=PRIVATE_HOST:123\npublic_key=SECRET\nlast_handshake_time_sec=123\ntx_bytes=456\nrx_bytes=789\n"
	if got := transportCounters(fakeEngineState{state: state}); got != "stats=1,456,789" {
		t.Fatal("unexpected diagnostic output")
	}
	if got := transportCounters(fakeEngineState{state: "tx_bytes=SECRET\n"}); got != "" {
		t.Fatal("malformed state leaked")
	}
	if got := transportCounters(fakeEngineState{err: errors.New("SECRET")}); got != "" {
		t.Fatal("engine error leaked")
	}
}

func TestEndpointBypassReplacesCachedRoute(t *testing.T) {
	current := endpointHostFixture + "flags: <UP,GATEWAY,HOST,WASCLONED,IFSCOPE>\n"
	adds, deletes := 0, 0
	run := func(_ string, args ...string) (string, error) {
		switch args[1] {
		case "get":
			return current, nil
		case "add":
			adds++
			current = endpointHostFixture + "flags: <UP,GATEWAY,HOST,STATIC>\n"
		case "delete":
			deletes++
			current = defaultRouteFixture
		}
		return "", nil
	}
	var undo undoStack
	if err := ensureEndpointRoute(run, endpointFixture, "en0", &undo); err != nil {
		t.Fatal(err)
	}
	if adds != 1 {
		t.Fatal("cached host route was mistaken for a durable bypass")
	}
	if err := verifyEndpointRoute(run, endpointFixture, "en0"); err != nil {
		t.Fatal(err)
	}
	if err := undo.close(); err != nil {
		t.Fatal(err)
	}
	if deletes != 1 {
		t.Fatal("owned static bypass not cleaned up")
	}
}

func TestEndpointVerificationRejectsTunnelRoute(t *testing.T) {
	run := func(_ string, _ ...string) (string, error) { return "destination: 0.0.0.0\ninterface: utun7\n", nil }
	if verifyEndpointRoute(run, endpointFixture, "en0") == nil {
		t.Fatal("routing loop accepted")
	}
}

func TestEndpointCacheCanShadowNewStaticRoute(t *testing.T) {
	cached := endpointHostFixture + "flags: <UP,GATEWAY,HOST,WASCLONED,IFSCOPE>\n"
	adds, deletes := 0, 0
	run := func(_ string, args ...string) (string, error) {
		switch args[1] {
		case "get":
			return cached, nil
		case "add":
			adds++ // The scoped cache survives until /1 routes are added.
		case "delete":
			deletes++
		}
		return "", nil
	}
	var undo undoStack
	if err := ensureEndpointRoute(run, endpointFixture, "en0", &undo); err != nil {
		t.Fatal(err)
	}
	if err := undo.close(); err != nil {
		t.Fatal(err)
	}
	if adds != 1 || deletes != 1 {
		t.Fatal("owned bypass must survive cache shadowing and be removed")
	}
}
func TestFailedEndpointAddCannotReuseCache(t *testing.T) {
	cached := endpointHostFixture + "flags: <UP,GATEWAY,HOST,WASCLONED,IFSCOPE>\n"
	run := func(_ string, args ...string) (string, error) {
		if args[1] == "get" {
			return cached, nil
		}
		if args[1] == "delete" {
			t.Fatal("unowned route removed")
		}
		return "", errors.New("already exists")
	}
	var undo undoStack
	if ensureEndpointRoute(run, endpointFixture, "en0", &undo) == nil {
		t.Fatal("cache accepted without a durable bypass")
	}
	if err := undo.close(); err != nil {
		t.Fatal(err)
	}
}
