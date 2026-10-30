package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"sync"
	"time"
)

// Bounded, serialized writes keep a stalled UI from holding cleanup forever.
type eventWriter struct {
	socket *net.UnixConn
	mu     sync.Mutex
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.socket.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return w.socket.Write(p)
}
func emitStep(out io.Writer, step string, started time.Time, err error) {
	result := "ok"
	code := uint64(0)
	if err != nil {
		result = "failed"
		var errno unix.Errno
		if errors.As(err, &errno) {
			code = uint64(errno)
		}
	}
	elapsed := time.Since(started).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > 86400000 {
		elapsed = 86400000
	}
	fmt.Fprintf(out, "step_%s=%s,%d,%d\n", step, result, elapsed, code)
}
