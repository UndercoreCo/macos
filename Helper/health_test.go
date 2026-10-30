package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
	"time"
)

func TestHealthFailureAndRecovery(t *testing.T) {
	h := healthTracker{}
	healthy := healthProbe{true, true, true}
	if h.observe(healthy) != "health=ok" {
		t.Fatal("healthy connection rejected")
	}
	failed := healthProbe{true, false, false}
	if h.observe(failed) != "health=checking" {
		t.Fatal("single failed probe must be confirmed")
	}
	if h.observe(failed) != "health=degraded" {
		t.Fatal("persistent failure hidden")
	}
	if h.observe(healthy) != "health=ok" {
		t.Fatal("recovery missing")
	}
	if h.observe(healthProbe{}) != "health=route" {
		t.Fatal("known routing failure hidden")
	}
}
func TestDNSFailureIsSeparateFromTunnel(t *testing.T) {
	h := healthTracker{}
	p := healthProbe{true, true, false}
	h.observe(p)
	if h.observe(p) != "health=dns" {
		t.Fatal("DNS failure mislabeled")
	}
}
func TestProbeCancellationDoesNotEmitLateHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}), make(chan struct{})
	var out bytes.Buffer
	go func() {
		defer close(done)
		monitorHealth(ctx, &out, func(ctx context.Context) healthProbe {
			close(started)
			<-ctx.Done()
			return healthProbe{}
		}, time.Millisecond, time.Second, time.Second)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not stop before cleanup")
	}
	if out.Len() != 0 {
		t.Fatal("late health update after cancellation")
	}
}
func TestSetupErrorsNeverLogRawDetails(t *testing.T) {
	var out bytes.Buffer
	emitStep(&out, "transport", time.Now(), fmt.Errorf("SECRET endpoint: %w", unix.ENETUNREACH))
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), "step_transport=failed,") || !strings.HasSuffix(out.String(), ",51\n") {
		t.Fatal("unsafe or incomplete stage event")
	}
}
func TestCleanupRetriesOnlyFailedActions(t *testing.T) {
	var undo undoStack
	success, failing := 0, 0
	undo.add(func() error { success++; return nil })
	undo.add(func() error {
		failing++
		if failing == 1 {
			return errors.New("temporary failure")
		}
		return nil
	})
	if undo.close() == nil {
		t.Fatal("cleanup failure hidden")
	}
	if undo.close() != nil {
		t.Fatal("retry did not recover")
	}
	undo.close()
	if success != 1 || failing != 2 {
		t.Fatal("successful cleanup repeated or failed cleanup lost")
	}
}
