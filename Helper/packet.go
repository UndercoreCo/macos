package main

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func isPacketField(key string) bool {
	return len(key) == 2 && key[0] == 'i' && key[1] >= '1' && key[1] <= '5'
}

// I1–I5 are optional handshake camouflage packets. Validate before the privileged
// engine parses or allocates them. Empty exported fields disable that packet.
// Support fixed bytes, random bytes/letters/digits and timestamps; bound the
// total generated packet, not just each individual tag.
func validPacketSpec(spec string) bool {
	const maximumPacketBytes = 4096
	total := 0
	remaining := strings.TrimSpace(spec)
	for remaining != "" {
		if !strings.HasPrefix(remaining, "<") {
			return false
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return false
		}
		parts := strings.Fields(remaining[1:end])
		if len(parts) == 0 || len(parts) > 2 {
			return false
		}
		size := 0
		switch parts[0] {
		case "t":
			if len(parts) != 1 {
				return false
			}
			size = 4
		case "r", "rc", "rd":
			if len(parts) != 2 {
				return false
			}
			n, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil || n > maximumPacketBytes {
				return false
			}
			size = int(n)
		case "b":
			if len(parts) != 2 {
				return false
			}
			value := strings.TrimPrefix(parts[1], "0x")
			if value == "" || len(value) > maximumPacketBytes*2 {
				return false
			}
			decoded, err := hex.DecodeString(value)
			if err != nil {
				return false
			}
			size = len(decoded)
		default:
			return false
		}
		total += size
		if total > maximumPacketBytes {
			return false
		}
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	return true
}
