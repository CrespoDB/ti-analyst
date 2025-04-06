package core

import "net"

// IsPrivateIP checks whether the given IP is in a private range.
func IsPrivateIP(ip net.IP) bool {
	// IPv4 private ranges.
	if ipv4 := ip.To4(); ipv4 != nil {
		switch {
		case ipv4[0] == 10:
			return true
		case ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31:
			return true
		case ipv4[0] == 192 && ipv4[1] == 168:
			return true
		}
	}
	// IPv6: fc00::/7.
	if ip.To16() != nil && ip.To4() == nil {
		if ip[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}
