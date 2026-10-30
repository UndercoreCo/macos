package main

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

// Counts only events and system error numbers. Never stores packets, peer names,
// UAPI, or formatted engine messages (which may contain connection details).
type transportDiagnostics struct {
	read, written, unknownIP, errors, sendErrors atomic.Uint64
	sendErrno                                    atomic.Int64
}

func (d *transportDiagnostics) logger() *device.Logger {
	return &device.Logger{Verbosef: func(format string, _ ...any) {
		if format == "Received packet with unknown IP version" {
			d.unknownIP.Add(1)
		}
	}, Errorf: func(format string, args ...any) {
		d.errors.Add(1)
		if !strings.Contains(format, "Failed to send") {
			return
		}
		d.sendErrors.Add(1)
		for _, arg := range args {
			if err, ok := arg.(error); ok {
				var errno unix.Errno
				if errors.As(err, &errno) {
					d.sendErrno.Store(int64(errno))
				}
			}
		}
	}}
}
func (d *transportDiagnostics) summary() string {
	return fmt.Sprintf("tun_read=%d tun_written=%d unknown_ip=%d engine_errors=%d send_errors=%d send_errno=%d", d.read.Load(), d.written.Load(), d.unknownIP.Load(), d.errors.Load(), d.sendErrors.Load(), d.sendErrno.Load())
}

type diagnosticTUN struct {
	tun.Device
	diagnostics *transportDiagnostics
}

func (t *diagnosticTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(buffers, sizes, offset)
	if n > 0 {
		t.diagnostics.read.Add(uint64(n))
	}
	return n, err
}
func (t *diagnosticTUN) Write(buffers [][]byte, offset int) (int, error) {
	n, err := t.Device.Write(buffers, offset)
	if n > 0 {
		t.diagnostics.written.Add(uint64(n))
	}
	return n, err
}

func (d *transportDiagnostics) event() string {
	return fmt.Sprintf("flow=%d,%d,%d,%d,%d,%d", d.read.Load(), d.written.Load(), d.unknownIP.Load(), d.errors.Load(), d.sendErrors.Load(), d.sendErrno.Load())
}
