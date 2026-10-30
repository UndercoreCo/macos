package main

import (
	"strconv"
	"strings"
	"time"
)

type engineStateReader interface{ IpcGet() (string, error) }

// UAPI includes secrets. Extract only the handshake timestamp in memory; never
// send the raw state or parser errors to the app, logs or diagnostics.
func transportStatus(engine engineStateReader, elapsed time.Duration) string {
	state, err := engine.IpcGet()
	if err == nil && hasHandshake(state) {
		return "connected"
	}
	if elapsed >= 20*time.Second {
		return "server_unreachable"
	}
	return "connecting"
}

func hasHandshake(state string) bool {
	for _, line := range strings.Split(state, "\n") {
		value, found := strings.CutPrefix(line, "last_handshake_time_sec=")
		if found {
			seconds, err := strconv.ParseUint(value, 10, 64)
			return err == nil && seconds > 0
		}
	}
	return false
}
