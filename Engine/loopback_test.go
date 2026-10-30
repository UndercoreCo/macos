package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// Real encrypted UDP exchange over loopback; fake TUNs never change the host network.
func TestAWG31Loopback(t *testing.T) {
	var keys [2]*ecdh.PrivateKey
	var tunnels [2]*tuntest.ChannelTUN
	var engines [2]*device.Device
	var ports [2]string
	for i := range keys {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("key generation failed")
		}
		keys[i] = key
	}
	for i := range engines {
		tunnels[i] = tuntest.NewChannelTUN()
		engines[i] = device.NewDevice(tunnels[i].TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		t.Cleanup(engines[i].Close)
		settings := fmt.Sprintf("private_key=%s\nlisten_port=0\njc=4\njmin=40\njmax=70\ns1=32\ns2=32\ns3=32\ns4=32\nh1=100001-100010\nh2=200001-200010\nh3=300001-300010\nh4=400001-400010\nheader_protection_key=%s\ncontent_padding_addition=8-16\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.99.0.%d/32\n",
			hex.EncodeToString(keys[i].Bytes()), strings.Repeat("07", 32), hex.EncodeToString(keys[i^1].PublicKey().Bytes()), (i^1)+1)
		if err := engines[i].IpcSet(settings); err != nil {
			t.Fatal("AWG 3.1 configuration rejected")
		}
		if err := engines[i].Up(); err != nil {
			t.Fatal("test engine failed to start")
		}
		state, err := engines[i].IpcGet()
		if err != nil {
			t.Fatal("test engine state unavailable")
		}
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				ports[i] = strings.TrimPrefix(line, "listen_port=")
			}
		}
		if ports[i] == "" || ports[i] == "0" {
			t.Fatal("loopback port unavailable")
		}
	}
	for i := range engines {
		settings := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%s\n", hex.EncodeToString(keys[i^1].PublicKey().Bytes()), ports[i^1])
		if err := engines[i].IpcSet(settings); err != nil {
			t.Fatal("loopback endpoint rejected")
		}
	}
	for round := 0; round < 3; round++ {
		for i := range engines {
			packet := tuntest.Ping(netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", (i^1)+1)), netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", i+1)))
			// UDP can lose packets, including while an engine applies its startup settings.
			// Require an intact round trip in both directions, with a bounded retry window.
			deadline := time.NewTimer(8 * time.Second)
			retry := time.NewTicker(200 * time.Millisecond)
			delivered := false
			attempts := 0
			for !delivered {
				select {
				case tunnels[i].Outbound <- packet:
					attempts++
					select {
					case received := <-tunnels[i^1].Inbound:
						if !bytes.Equal(received, packet) {
							t.Fatal("decrypted packet differs")
						}
						delivered = true
					case <-retry.C:
					case <-deadline.C:
						t.Fatal("encrypted exchange timed out")
					}
				case <-deadline.C:
					t.Fatal("test send timed out")
				}
			}
			deadline.Stop()
			retry.Stop()
			t.Logf("round %d direction %d delivered after %d packet(s)", round, i, attempts)
		}
	}
}
