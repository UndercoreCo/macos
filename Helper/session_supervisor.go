package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var errSessionCleanup = errors.New("session cleanup incomplete")

type managedSession interface{ close() error }
type sessionStarter func(context.Context) (managedSession, error)
type sessionWorkers func(context.Context, managedSession, chan<- struct{}, <-chan string)

// The authenticated owner retains one authorization, never a persistent daemon.
// Cancellation/EOF stops workers before undoing routes, including during startup.
func superviseSession(ctx context.Context, out io.Writer, commands <-chan string, start sessionStarter, run sessionWorkers, idleLimit time.Duration) (result error) {
	var current managedSession
	var stop context.CancelFunc
	var done chan struct{}
	var changed chan struct{}
	var requests chan string
	var idle *time.Timer
	var idleC <-chan time.Time
	clearIdle := func() {
		if idle != nil {
			idle.Stop()
		}
		idleC = nil
	}
	waitIdle := func() {
		if idleC == nil {
			idle = time.NewTimer(idleLimit)
			idleC = idle.C
		}
	}
	closeCurrent := func() error {
		if stop != nil {
			stop()
			<-done
			stop = nil
		}
		if current == nil {
			return nil
		}
		started := time.Now()
		err := current.close()
		emitStep(out, "cleanup", started, err)
		if err == nil {
			current = nil
		}
		return err
	}
	defer func() {
		clearIdle()
		err := closeCurrent()
		if result != nil || err != nil {
			fmt.Fprintln(out, "cleanup_error")
		} else {
			fmt.Fprintln(out, "disconnected")
		}
		result = errors.Join(result, err)
	}()
	launch := func(request string) error {
		next, err := start(ctx)
		if err != nil {
			return err
		}
		current = next
		if ctx.Err() != nil {
			return ctx.Err()
		}
		workerCtx, cancel := context.WithCancel(ctx)
		stop = cancel
		done = make(chan struct{})
		changed = make(chan struct{}, 1)
		requests = make(chan string, 1)
		if request != "" {
			fmt.Fprintf(out, "check_started=%s\n", request)
		}
		fmt.Fprintln(out, "connecting")
		go func() { defer close(done); run(workerCtx, next, changed, requests) }()
		clearIdle()
		return nil
	}
	if err := launch(""); err != nil {
		fmt.Fprintln(out, "error")
		if errors.Is(err, errSessionCleanup) {
			return err
		}
		return nil // Initial errors require a deliberate user retry.
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-idleC:
			fmt.Fprintln(out, "recovery_expired")
			return nil
		case <-changed:
			if err := closeCurrent(); err != nil {
				return err
			}
			changed = nil
			fmt.Fprintln(out, "network_changed")
			fmt.Fprintln(out, "recovery_ready")
			waitIdle()
		case command, ok := <-commands:
			if !ok {
				return nil
			}
			if request, ok := healthCheckCommand(command); ok {
				if current != nil {
					select {
					case <-requests:
					default:
					}
					requests <- request
				}
				continue
			}
			request, ok := reconnectCommand(command)
			if !ok {
				fmt.Fprintln(out, "control_error")
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(out, "reasserting")
			if err := closeCurrent(); err != nil {
				return err
			}
			changed = nil
			if err := launch(request); err != nil {
				if errors.Is(err, errSessionCleanup) {
					return err
				}
				if ctx.Err() != nil {
					return nil
				}
				fmt.Fprintln(out, "recovery_failed")
				waitIdle()
			}
		}
	}
}

func reconnectCommand(command string) (string, bool) {
	if !strings.HasPrefix(command, "reconnect ") {
		return "", false
	}
	return healthCheckCommand("check " + strings.TrimPrefix(command, "reconnect "))
}

// Read independently of tunnel creation so Stop and heartbeat loss cancel setup.
func readSessionCommands(ctx context.Context, cancel context.CancelFunc, client *net.UnixConn, reader *bufio.Reader, out io.Writer, commands chan<- string) {
	defer cancel()
	for {
		client.SetReadDeadline(time.Now().Add(18 * time.Second))
		line, err := reader.ReadSlice('\n')
		if err != nil {
			code := "control_error"
			var timeout net.Error
			if errors.Is(err, io.EOF) {
				code = "client_closed"
			} else if errors.As(err, &timeout) && timeout.Timeout() {
				code = "heartbeat_timeout"
			}
			if ctx.Err() == nil {
				fmt.Fprintln(out, code)
			}
			return
		}
		command := string(line)
		if command == "stop\n" {
			return
		}
		if command == "ping\n" {
			continue
		}
		_, check := healthCheckCommand(command)
		_, reconnect := reconnectCommand(command)
		if !check && !reconnect {
			fmt.Fprintln(out, "control_error")
			return
		}
		select {
		case commands <- command:
		case <-ctx.Done():
			return
		default:
			fmt.Fprintln(out, "control_error")
			return // Bounded control queue; no floods.
		}
	}
}
