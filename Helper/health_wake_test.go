package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type healthTestWriter struct{ lines chan string }

func (w healthTestWriter) Write(p []byte) (int, error) { w.lines <- string(p); return len(p), nil }

func TestWakeCancelsOldProbeAndReportsFreshSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	requests := make(chan string, 1)
	started := make(chan int32, 4)
	finished := make(chan struct{})
	out := healthTestWriter{make(chan string, 32)}
	var calls, active atomic.Int32
	var overlap atomic.Bool
	go func() {
		defer close(finished)
		monitorHealth(ctx, out, func(ctx context.Context) healthProbe {
			if active.Add(1) > 1 {
				overlap.Store(true)
			}
			defer active.Add(-1)
			call := calls.Add(1)
			started <- call
			if call == 1 {
				<-ctx.Done()
			}
			// Even a cancelled old probe returning success must never be published.
			return healthProbe{true, true, true}
		}, time.Hour, time.Hour, time.Hour, requests)
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("monitor did not stop")
		}
	}()
	requests <- "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("wake did not trigger immediate probe")
	}
	requests <- "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old probe was not cancelled")
	}
	var events []string
	for {
		select {
		case line := <-out.lines:
			events = append(events, line)
			if strings.TrimSpace(line) == "health=ok" {
				joined := strings.Join(events, "")
				if !strings.Contains(joined, "check_started=BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB\nhealth=checking\nhealth=ok") {
					t.Fatal("success published before fresh generation", joined)
				}
				if overlap.Load() {
					t.Fatal("probes overlapped")
				}
				return
			}
		case <-time.After(time.Second):
			t.Fatal("fresh result missing")
		}
	}
}
func TestHealthCommandRejectsArbitraryPayloads(t *testing.T) {
	if _, ok := healthCheckCommand("check 12345678-ABCD-1234-5678-123456789ABC\n"); !ok {
		t.Fatal("valid request rejected")
	}
	for _, command := range []string{"check secret\n", "check 12345678-ABCD-1234-5678-123456789ABC\nstop\n", "check 12345678-ABCD-1234-5678-123456789ABC", "exec whoami\n"} {
		if _, ok := healthCheckCommand(command); ok {
			t.Fatal("invalid command accepted")
		}
	}
}
