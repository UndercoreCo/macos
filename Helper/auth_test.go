package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixPeerAuthentication(t *testing.T) {
	directory, e := os.MkdirTemp("/tmp", "undercore-auth-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(directory)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "rpc"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(3 * time.Second))
	client, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	if !authorized(server, os.Getuid(), os.Getpid()) {
		t.Fatal("own peer rejected")
	}
	if authorized(server, os.Getuid()+1, os.Getpid()) || authorized(server, os.Getuid(), os.Getpid()+1) {
		t.Fatal("foreign uid or process accepted")
	}
}
