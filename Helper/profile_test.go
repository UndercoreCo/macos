package main

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func fixture() string {
	k := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	return "[Interface]\nPrivateKey = " + k + "\nAddress = 10.9.0.2/32\nDNS = 1.1.1.1\nS1 = 32\nS2 = 32\nS3 = 32\nS4 = 32\nHeaderProtectionKey = " + k + "\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\nPublicKey = " + k + "\nEndpoint = vpn.example.com:51820\n"
}
func TestProfile(t *testing.T) {
	p, e := parseProfile([]byte(fixture()))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(p.peer[0], "public_key=") {
		t.Fatal("public key must precede peer fields")
	}
	if !strings.Contains(p.uapi("192.0.2.1:51820"), "header_protection_key=") {
		t.Fatal("AWG 3 key missing")
	}
}
func TestRejectPrivilegedInput(t *testing.T) {
	for _, v := range []string{
		"PostUp = touch /tmp/unsafe", "PreDown = rm -rf /", "SaveConfig = true", "I1 = <r 999999999>", "Jc = 999999999", "S4 = 999999999", "DNS = 1.1.1.1;echo bad", "PrivateKey = bad",
	} {
		s := strings.Replace(fixture(), "[Peer]", v+"\n[Peer]", 1)
		if _, e := parseProfile([]byte(s)); e == nil {
			t.Errorf("accepted %q", v)
		}
	}
}
func TestUnsupportedNetworks(t *testing.T) {
	for _, s := range []string{
		strings.ReplaceAll(fixture(), "0.0.0.0/0, ::/0", "192.168.0.0/16"), strings.ReplaceAll(fixture(), "vpn.example.com:51820", "[::1]:51820"), strings.ReplaceAll(fixture(), "DNS = 1.1.1.1\n", ""), fixture() + "\n[Peer]\n", strings.Repeat("x", 65537),
	} {
		if _, e := parseProfile([]byte(s)); e == nil {
			t.Fatal("unsupported profile accepted")
		}
	}
}
func TestRollbackOnPartialNetworkFailure(t *testing.T) {
	p, e := parseProfile([]byte(fixture()))
	if e != nil {
		t.Fatal(e)
	}
	var removed []string
	var undo undoStack
	run := func(path string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " get ") {
			return "interface: utun123\n", nil
		}
		if strings.Contains(joined, "add -inet6") {
			return "", errors.New("simulated route failure")
		}
		if strings.Contains(joined, "delete") {
			removed = append(removed, joined)
		}
		return "", nil
	}
	if configureNetwork(run, "utun123", p, &undo) == nil {
		t.Fatal("failure missing")
	}
	undo.close()
	undo.close()
	want := []string{"-n delete -inet -net 128.0.0.0/1 -interface utun123", "-n delete -inet -net 0.0.0.0/1 -interface utun123"}
	if !reflect.DeepEqual(removed, want) {
		t.Fatalf("cleanup must reverse only successful changes: %v", removed)
	}
}
func TestRollbackContinuesAfterFailure(t *testing.T) {
	var u undoStack
	var order []int
	u.add(func() error { order = append(order, 1); return nil })
	u.add(func() error { order = append(order, 2); return errors.New("failure") })
	if u.close() == nil || !reflect.DeepEqual(order, []int{2, 1}) {
		t.Fatal("cleanup stopped early")
	}
}

func TestWindowsLineEndings(t *testing.T) {
	if _, e := parseProfile([]byte(strings.ReplaceAll(fixture(), "\n", "\r\n"))); e != nil {
		t.Fatal(e)
	}
}

func TestDoesNotRemoveReplacedRoutes(t *testing.T) {
	p, e := parseProfile([]byte(fixture()))
	if e != nil {
		t.Fatal(e)
	}
	var undo undoStack
	run := func(path string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " get ") {
			return "interface: utun999\n", nil
		}
		if strings.Contains(joined, " delete ") {
			t.Fatal("removed a replacement route")
		}
		return "", nil
	}
	if configureNetwork(run, "utun123", p, &undo) != nil {
		t.Fatal("setup failed")
	}
	if undo.close() != nil {
		t.Fatal("cleanup failed")
	}
}

func TestExportedCamouflagePackets(t *testing.T) {
	fields := "I1 = <r 16><b 0x001122aabb>\nI2 =\nI3 =\nI4 =\nI5 =\n"
	source := strings.Replace(fixture(), "[Peer]", fields+"[Peer]", 1)
	p, err := parseProfile([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	uapi := p.uapi("192.0.2.1:51820")
	// Exercise the shipped engine parser too, with an in-memory TUN and no Up():
	// no host interface, routes, DNS changes or outgoing VPN connection.
	tunnel := tuntest.NewChannelTUN()
	engine := device.NewDevice(tunnel.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	if err := engine.IpcSet(uapi); err != nil {
		t.Fatal("engine rejected exported camouflage packet settings")
	}
	for _, field := range []string{"i1=<r 16><b 0x001122aabb>\n", "i2=\n", "i3=\n", "i4=\n", "i5=\n"} {
		if !strings.Contains(uapi, field) {
			t.Fatal("camouflage packet was lost")
		}
	}
}

func TestCamouflagePacketBounds(t *testing.T) {
	for _, spec := range []string{"", "<r 4096>", "<rc 12><rd 8><t><b abcd>"} {
		if !validPacketSpec(spec) {
			t.Errorf("rejected valid spec %q", spec)
		}
	}
	for _, spec := range []string{"<r -1>", "<r 999999999>", "<r 3000><r 3000>", "<r 4096><t>", "<r 1 2>", "<b 0xg0>", "<b 0x1>", "<b>", "<r 10", "garbage", "<r 10>garbage", "<d>", "<t 10>", "<>"} {
		source := strings.Replace(fixture(), "[Peer]", "I1 = "+spec+"\n[Peer]", 1)
		if _, err := parseProfile([]byte(source)); err == nil {
			t.Errorf("accepted invalid spec %q", spec)
		}
	}
	for _, line := range []string{"I6 =", "PrivateKey =", "I1 =\nI1 ="} {
		source := strings.Replace(fixture(), "[Peer]", line+"\n[Peer]", 1)
		if _, err := parseProfile([]byte(source)); err == nil {
			t.Fatal("accepted invalid/duplicate field")
		}
	}
	if _, err := parseProfile([]byte(fixture() + "I1 =\n")); err == nil {
		t.Fatal("accepted interface field in peer")
	}
}
