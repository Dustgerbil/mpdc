package main

import (
	"net"
	"net/netip"
)

func addressFamily(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func classifyIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "invalid"
	}
	if address.IsLoopback() {
		return "loopback"
	}
	if address.IsPrivate() {
		return "private"
	}
	if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return "link-local"
	}
	if address.IsUnspecified() {
		return "unspecified"
	}
	if address.IsMulticast() {
		return "multicast"
	}
	prefixes := []struct {
		prefix netip.Prefix
		name   string
	}{
		{netip.MustParsePrefix("100.64.0.0/10"), "shared"},
		{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
		{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
		{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
		{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	}
	for _, item := range prefixes {
		if item.prefix.Contains(address) {
			return item.name
		}
	}
	if !address.IsGlobalUnicast() {
		return "reserved"
	}
	return "public"
}
