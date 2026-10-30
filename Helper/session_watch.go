package main

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Handshake polling is cheap. Shell route checks and saved counters run at 15s,
// not every tick; transient route-read failures require confirmation.
func watchSession(ctx context.Context, out io.Writer, changed chan<- struct{}, s *session, started time.Time) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastStatus := "connecting"
	ticks := 0
	physicalFailures := 0
	run := func(path string, args ...string) (string, error) { return commandContext(ctx, path, args...) }
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := transportStatus(s.engine, time.Since(started))
			if status != lastStatus {
				fmt.Fprintln(out, status)
				lastStatus = status
			}
			if ticks%5 == 0 {
				if counters := transportCounters(s.engine); counters != "" {
					fmt.Fprintln(out, counters)
				}
				fmt.Fprintln(out, s.diagnostics.event())
				signature, err := physicalSignature(run, s.physical)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					physicalFailures++
				} else {
					physicalFailures = 0
				}
				if physicalFailures >= 2 || (err == nil && signature != s.signature) {
					select {
					case changed <- struct{}{}:
					case <-ctx.Done():
					}
					return
				}
			}
			ticks++
		}
	}
}
