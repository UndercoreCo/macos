package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var errProfile = errors.New("invalid profile")

type profile struct {
	addresses    []netip.Prefix
	dns          []netip.Addr
	mtu          int
	endpoint     string
	device, peer []string
}

var deviceFields = map[string]string{
	"jc": "jc", "jmin": "jmin", "jmax": "jmax", "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "headerprotectionkey": "header_protection_key",
	"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time",
	"rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout",
	"maxhandshakeattempts": "max_handshake_attempts", "randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
}

func keyHex(value string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(b) != 32 {
		return "", errProfile
	}
	return hex.EncodeToString(b), nil
}
func parseProfile(data []byte) (profile, error) {
	data = []byte(strings.ReplaceAll(string(data), "\r\n", "\n"))
	p := profile{mtu: 1280}
	if len(data) == 0 || len(data) > 65536 || strings.ContainsAny(string(data), "\x00\r") {
		return p, errProfile
	}
	section := ""
	seen := map[string]bool{}
	hasPrivate, hasPublic, hasDefault := false, false, false
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	for scan.Scan() {
		line := strings.TrimSpace(strings.SplitN(scan.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" || seen[line] {
				return p, errProfile
			}
			if line == "[Peer]" && !seen["[Interface]"] {
				return p, errProfile
			}
			seen[line] = true
			section = line
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || section == "" {
			return p, errProfile
		}
		key, value := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		id := section + key
		isPacket := section == "[Interface]" && isPacketField(key)
		if seen[id] || (value == "" && !isPacket) || len(value) > 1024 {
			return p, errProfile
		}
		seen[id] = true
		if section == "[Interface]" {
			switch key {
			case "i1", "i2", "i3", "i4", "i5":
				if !validPacketSpec(value) {
					return p, errProfile
				}
				p.device = append(p.device, key+"="+value)
			case "privatekey":
				h, e := keyHex(value)
				if e != nil {
					return p, e
				}
				p.device = append(p.device, "private_key="+h)
				hasPrivate = true
			case "address":
				for _, v := range strings.Split(value, ",") {
					a, e := netip.ParsePrefix(strings.TrimSpace(v))
					if e != nil || !a.Addr().IsGlobalUnicast() {
						return p, errProfile
					}
					p.addresses = append(p.addresses, a)
				}
			case "dns":
				for _, v := range strings.Split(value, ",") {
					a, e := netip.ParseAddr(strings.TrimSpace(v))
					if e != nil || !a.IsGlobalUnicast() {
						return p, errProfile
					}
					p.dns = append(p.dns, a)
				}
			case "mtu":
				n, e := strconv.Atoi(value)
				if e != nil || n < 1280 || n > 9000 {
					return p, errProfile
				}
				p.mtu = n
			case "listenport":
				n, e := strconv.Atoi(value)
				if e != nil || n < 0 || n > 65535 {
					return p, errProfile
				}
				p.device = append(p.device, "listen_port="+value)
			default:
				field, ok := deviceFields[key]
				if !ok {
					return p, errProfile
				}
				if key == "headerprotectionkey" {
					h, e := keyHex(value)
					if e != nil {
						return p, e
					}
					value = h
				} else if key == "randomtrailers" || key == "disablecookies" {
					v, e := strconv.ParseBool(value)
					if e != nil {
						return p, errProfile
					}
					value = strconv.FormatBool(v)
				} else {
					// Bound memory/amplification knobs before handing them to a privileged engine.
					limit := uint64(86400)
					if key == "jc" || key == "maxhandshakeattempts" {
						limit = 128
					}
					if key == "jmin" || key == "jmax" || strings.HasPrefix(key, "s") || key == "contentpaddingaddition" {
						limit = 4096
					}
					if strings.HasPrefix(key, "h") {
						limit = 4294967295
					}
					parts := strings.Split(value, "-")
					if len(parts) > 2 {
						return p, errProfile
					}
					var previous uint64
					for i, part := range parts {
						n, e := strconv.ParseUint(part, 10, 32)
						if e != nil || n > limit || i > 0 && n < previous {
							return p, errProfile
						}
						previous = n
					}
				}
				p.device = append(p.device, field+"="+value)
			}
		} else {
			switch key {
			case "publickey", "presharedkey":
				h, e := keyHex(value)
				if e != nil {
					return p, e
				}
				field := "preshared_key"
				if key == "publickey" {
					field = "public_key"
					hasPublic = true
				}
				p.peer = append(p.peer, field+"="+h)
			case "endpoint":
				host, port, e := net.SplitHostPort(value)
				n, pe := strconv.Atoi(port)
				if e != nil || pe != nil || n < 1 || n > 65535 || len(host) > 253 || host == "" {
					return p, errProfile
				}
				for _, c := range host {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
						return p, errProfile
					}
				}
				p.endpoint = value
			case "allowedips":
				for _, v := range strings.Split(value, ",") {
					a, e := netip.ParsePrefix(strings.TrimSpace(v))
					if e != nil || a.Bits() != 0 || a.Addr() != a.Masked().Addr() {
						return p, errProfile
					}
					if a.Addr().Is4() {
						hasDefault = true
					}
					p.peer = append(p.peer, "allowed_ip="+a.String())
				}
			case "persistentkeepalive":
				parts := strings.Split(value, "-")
				if len(parts) > 2 {
					return p, errProfile
				}
				var previous uint64
				for i, v := range parts {
					n, e := strconv.ParseUint(v, 10, 16)
					if e != nil || i > 0 && n < previous {
						return p, errProfile
					}
					previous = n
				}
				p.peer = append(p.peer, "persistent_keepalive_interval="+value)
			default:
				return p, errProfile
			}
		}
	}
	if scan.Err() != nil || !hasPrivate || !hasPublic || !hasDefault || p.endpoint == "" || len(p.addresses) == 0 || len(p.addresses) > 4 || len(p.dns) == 0 || len(p.dns) > 4 {
		return p, errProfile
	}
	hasV4 := false
	for _, a := range p.addresses {
		if a.Addr().Is4() {
			hasV4 = true
		}
	}
	if !hasV4 {
		return p, errProfile
	}
	// UAPI needs public_key before any peer attributes, regardless of .conf order.
	for i, v := range p.peer {
		if strings.HasPrefix(v, "public_key=") {
			p.peer[0], p.peer[i] = p.peer[i], p.peer[0]
			break
		}
	}
	return p, nil
}
func (p profile) uapi(endpoint string) string {
	return strings.Join(p.device, "\n") + "\nreplace_peers=true\n" + strings.Join(p.peer, "\n") + "\nendpoint=" + endpoint + "\n"
}
