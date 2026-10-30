package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeManagedSession struct {
	workers     atomic.Int32
	closed      atomic.Int32
	overlap     *atomic.Bool
	failCleanup bool
}

func (s *fakeManagedSession) close() error {
	if s.workers.Load() != 0 {
		s.overlap.Store(true)
	}
	s.closed.Add(1)
	if s.failCleanup {
		return errors.New("test cleanup failure")
	}
	return nil
}
func awaitSupervisorEvent(t *testing.T, out healthTestWriter, expected string) {
	t.Helper()
	timeout := time.After(time.Second)
	for {
		select {
		case line := <-out.lines:
			if strings.TrimSpace(line) == expected {
				return
			}
		case <-timeout:
			t.Fatalf("missing event %s", expected)
		}
	}
}
func awaitSupervisorExit(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
		return nil
	}
}

func TestSupervisorReusesAuthorizationAndJoinsWorkersBeforeCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := healthTestWriter{make(chan string, 100)}
	commands := make(chan string, 8)
	sessions := make(chan *fakeManagedSession, 4)
	networkChanges := make(chan chan<- struct{}, 4)
	done := make(chan error, 1)
	var starts atomic.Int32
	var overlap atomic.Bool
	go func() {
		done <- superviseSession(ctx, out, commands, func(context.Context) (managedSession, error) {
			starts.Add(1)
			s := &fakeManagedSession{overlap: &overlap}
			sessions <- s
			return s, nil
		}, func(ctx context.Context, current managedSession, changed chan<- struct{}, _ <-chan string) {
			s := current.(*fakeManagedSession)
			s.workers.Add(1)
			defer s.workers.Add(-1)
			networkChanges <- changed
			<-ctx.Done()
		}, time.Minute)
	}()
	first := <-sessions
	change := <-networkChanges
	change <- struct{}{}
	awaitSupervisorEvent(t, out, "recovery_ready")
	if first.closed.Load() != 1 || starts.Load() != 1 {
		t.Fatal("must clean up and wait for common retry policy")
	}
	commands <- "reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA\n"
	awaitSupervisorEvent(t, out, "check_started=AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
	second := <-sessions
	<-networkChanges
	cancel()
	if err := awaitSupervisorExit(t, done); err != nil {
		t.Fatal(err)
	}
	if overlap.Load() || second.closed.Load() != 1 || starts.Load() != 2 {
		t.Fatal("session overlap or incomplete cleanup")
	}
}

func TestSupervisorFailedRestartCanRetryWithoutReplacingControlSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := healthTestWriter{make(chan string, 100)}
	commands := make(chan string, 8)
	done := make(chan error, 1)
	var starts atomic.Int32
	var overlap atomic.Bool
	go func() {
		done <- superviseSession(ctx, out, commands, func(context.Context) (managedSession, error) {
			if starts.Add(1) == 2 {
				return nil, errors.New("network unavailable")
			}
			return &fakeManagedSession{overlap: &overlap}, nil
		}, func(ctx context.Context, _ managedSession, _ chan<- struct{}, _ <-chan string) { <-ctx.Done() }, time.Minute)
	}()
	awaitSupervisorEvent(t, out, "connecting")
	commands <- "reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA\n"
	awaitSupervisorEvent(t, out, "recovery_failed")
	commands <- "reconnect BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB\n"
	awaitSupervisorEvent(t, out, "check_started=BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")
	cancel()
	if err := awaitSupervisorExit(t, done); err != nil {
		t.Fatal(err)
	}
	if starts.Load() != 3 {
		t.Fatal("wrong retry count")
	}
}

func TestSupervisorNeverRestartsAfterCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := healthTestWriter{make(chan string, 100)}
	commands := make(chan string, 8)
	var starts atomic.Int32
	var overlap atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- superviseSession(ctx, out, commands, func(context.Context) (managedSession, error) {
			starts.Add(1)
			return &fakeManagedSession{overlap: &overlap, failCleanup: true}, nil
		}, func(ctx context.Context, _ managedSession, _ chan<- struct{}, _ <-chan string) { <-ctx.Done() }, time.Minute)
	}()
	awaitSupervisorEvent(t, out, "connecting")
	commands <- "reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA\n"
	if err := awaitSupervisorExit(t, done); err == nil {
		t.Fatal("cleanup failure swallowed")
	}
	if starts.Load() != 1 {
		t.Fatal("started over leftover network settings")
	}
}

func TestSupervisorStopDuringRestartCleansLateResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := healthTestWriter{make(chan string, 100)}
	commands := make(chan string, 8)
	started := make(chan struct{})
	done := make(chan error, 1)
	var count atomic.Int32
	var overlap atomic.Bool
	late := &fakeManagedSession{overlap: &overlap}
	go func() {
		done <- superviseSession(ctx, out, commands, func(ctx context.Context) (managedSession, error) {
			if count.Add(1) == 2 {
				close(started)
				<-ctx.Done()
				return late, nil
			}
			return &fakeManagedSession{overlap: &overlap}, nil
		}, func(ctx context.Context, _ managedSession, _ chan<- struct{}, _ <-chan string) { <-ctx.Done() }, time.Minute)
	}()
	awaitSupervisorEvent(t, out, "connecting")
	commands <- "reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA\n"
	<-started
	cancel()
	if err := awaitSupervisorExit(t, done); err != nil {
		t.Fatal(err)
	}
	if late.closed.Load() != 1 {
		t.Fatal("cancelled startup leaked a tunnel")
	}
}

func TestSupervisorOfflineAuthorizationExpires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := healthTestWriter{make(chan string, 100)}
	done := make(chan error, 1)
	var overlap atomic.Bool
	go func() {
		done <- superviseSession(ctx, out, make(chan string), func(context.Context) (managedSession, error) {
			return &fakeManagedSession{overlap: &overlap}, nil
		}, func(ctx context.Context, _ managedSession, changed chan<- struct{}, _ <-chan string) {
			changed <- struct{}{}
			<-ctx.Done()
		}, 10*time.Millisecond)
	}()
	awaitSupervisorEvent(t, out, "recovery_expired")
	if err := awaitSupervisorExit(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectCommandAcceptsOnlyFixedVerbAndUUID(t *testing.T) {
	for _, invalid := range []string{"reconnect\n", "reconnect /bin/sh\n", "reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA extra\n", "ping\n"} {
		if _, ok := reconnectCommand(invalid); ok {
			t.Fatalf("accepted %q", invalid)
		}
	}
	if _, ok := reconnectCommand("reconnect AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA\n"); !ok {
		t.Fatal("valid command rejected")
	}
}
