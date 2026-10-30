package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

func main() {
	uid := flag.Int("uid", -1, "owning user")
	pid := flag.Int("pid", 0, "owning app process")
	socket := flag.String("socket", "", "private session socket")
	check := flag.Bool("check", false, "validate profile from stdin without privileges or network changes")
	version := flag.Bool("version", false, "print helper protocol version")
	flag.Parse()
	if *version {
		fmt.Println("Undercore helper protocol 1 / AWG 3.1")
		return
	}
	if *check {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
		if e == nil {
			_, e = parseProfile(b)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "invalid_profile")
			os.Exit(1)
		}
		fmt.Println("valid")
		return
	}
	if os.Geteuid() != 0 || *uid < 501 || *pid <= 1 || !regexp.MustCompile(`^/private/var/run/undercore-[0-9a-f-]{36}/control\.sock$`).MatchString(*socket) {
		os.Exit(2)
	}
	// The app's authorization wrapper creates this directory. Never accept user-owned parents.
	info, e := os.Lstat(filepath.Dir(*socket))
	if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	if e := serve(ctx, *socket, *uid, *pid); e != nil {
		fmt.Fprintln(os.Stderr, "helper_failed")
		os.Exit(1)
	}
}
func serve(ctx context.Context, path string, uid, pid int) error {
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chmod(path, 0600); e != nil {
		return e
	}
	if e = os.Chown(path, uid, -1); e != nil {
		return e
	}
	listener.SetDeadline(time.Now().Add(30 * time.Second))
	go func() { <-ctx.Done(); listener.Close() }()
	var client *net.UnixConn
	for {
		c, e := listener.AcceptUnix()
		if e != nil {
			return e
		}
		if authorized(c, uid, pid) {
			client = c
			break
		}
		c.Close()
	}
	defer client.Close()
	listener.Close()
	go func() { <-ctx.Done(); client.Close() }()
	// Lock only after authenticating. The root-owned lock contains no data or credentials.
	fd, e := unix.Open("/private/var/run/undercore-standalone.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("lock invalid")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		fmt.Fprintln(client, "busy")
		return nil
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(client, 131072)
	line, e := reader.ReadSlice('\n')
	if e != nil || len(line) > 100000 {
		return errors.New("request invalid")
	}
	var request struct {
		Configuration []byte `json:"configuration"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		fmt.Fprintln(client, "invalid_profile")
		return nil
	}
	p, e := parseProfile(request.Configuration)
	clear(request.Configuration)
	if e != nil {
		fmt.Fprintln(client, "invalid_profile")
		return nil
	}
	events := &eventWriter{socket: client}
	controlCtx, cancelControl := context.WithCancel(ctx)
	defer cancelControl()
	commands := make(chan string, 8)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		readSessionCommands(controlCtx, cancelControl, client, reader, events, commands)
	}()
	defer func() { cancelControl(); client.CloseRead(); <-readerDone }()
	return superviseSession(controlCtx, events, commands, func(ctx context.Context) (managedSession, error) {
		return startSessionWithEvents(ctx, p, filepath.Base(filepath.Dir(path)), events)
	}, func(ctx context.Context, current managedSession, changed chan<- struct{}, requests <-chan string) {
		s := current.(*session)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			monitorConnectionHealth(ctx, events, s.tunnel, s.endpoint, s.physical, p.dns, requests)
		}()
		go func() { defer workers.Done(); watchSession(ctx, events, changed, s, time.Now()) }()
		workers.Wait()
	}, 3*time.Minute)
}

func authorized(c *net.UnixConn, uid, pid int) bool {
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	ok := false
	raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), 0, unix.LOCAL_PEERCRED)
		if e != nil || int(cred.Uid) != uid {
			return
		}
		peer, e := unix.GetsockoptInt(int(fd), 0, unix.LOCAL_PEERPID)
		ok = e == nil && peer == pid
	})
	return ok
}

type session struct {
	diagnostics                   *transportDiagnostics
	tunnel                        string
	engine                        *device.Device
	undo                          undoStack
	physical, endpoint, signature string
}

func (s *session) close() error { return s.undo.close() }
func startSession(ctx context.Context, p profile, name string) (*session, error) {
	return startSessionWithEvents(ctx, p, name, io.Discard)
}
func startSessionWithEvents(ctx context.Context, p profile, name string, events io.Writer) (result *session, err error) {
	s := &session{}
	stage := "resolve"
	stageStarted := time.Now()
	next := func(name string) { emitStep(events, stage, stageStarted, nil); stage = name; stageStarted = time.Now() }
	defer func() {
		if err != nil {
			emitStep(events, stage, stageStarted, err)
			cleanupStarted := time.Now()
			cleanupErr := s.close()
			emitStep(events, "cleanup", cleanupStarted, cleanupErr)
			if cleanupErr != nil {
				err = errors.Join(err, errSessionCleanup)
			}
		}
	}()
	host, port, _ := net.SplitHostPort(p.endpoint)
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, e := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", host)
	if e != nil || len(addresses) == 0 {
		return nil, errors.New("endpoint unavailable")
	}
	s.endpoint = addresses[0].String()
	next("physical")
	s.physical, e = interfaceForEndpoint(command, s.endpoint)
	if e != nil {
		return nil, e
	}
	s.signature, e = physicalSignature(command, s.physical)
	if e != nil {
		return nil, e
	}
	physical, e := net.InterfaceByName(s.physical)
	if e != nil {
		return nil, e
	}
	next("tunnel")
	t, e := tun.CreateTUN("utun", p.mtu)
	if e != nil {
		return nil, e
	}
	intf, e := t.Name()
	if e != nil {
		t.Close()
		return nil, e
	}
	s.tunnel = intf
	next("engine")
	bind := conn.NewDefaultBind()
	s.diagnostics = &transportDiagnostics{}
	engine := device.NewDevice(&diagnosticTUN{Device: t, diagnostics: s.diagnostics}, bind, s.diagnostics.logger())
	s.engine = engine
	s.undo.add(func() error { engine.Close(); return nil })
	if e = engine.IpcSet(p.uapi(net.JoinHostPort(s.endpoint, port))); e != nil {
		return nil, e
	}
	next("endpoint_route")
	if e = ensureEndpointRoute(command, s.endpoint, s.physical, &s.undo); e != nil {
		return nil, e
	}
	next("transport")
	if e = engine.Up(); e != nil {
		return nil, e
	}
	sockets, ok := bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return nil, errors.New("bind unavailable")
	}
	socket, e := sockets.PeekLookAtSocketFd4()
	if e != nil {
		return nil, e
	}
	// Bind encrypted transport to the physical interface before installing VPN routes.
	if e = unix.SetsockoptInt(socket, unix.IPPROTO_IP, unix.IP_BOUND_IF, physical.Index); e != nil {
		return nil, e
	}
	next("routes")
	if e = configureNetwork(command, intf, p, &s.undo); e != nil {
		return nil, e
	}
	if e = verifyEndpointRoute(command, s.endpoint, s.physical); e != nil {
		return nil, e
	}
	next("dns")
	closeDNS, e := openDNS(name, intf, p)
	if e != nil {
		return nil, e
	}
	s.undo.add(func() error { closeDNS(); return nil })
	emitStep(events, stage, stageStarted, nil)
	return s, nil
}
