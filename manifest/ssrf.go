package manifest

import (
	"fmt"
	"net"
)

// privateRanges are the RFC 1918 / RFC 4193 private address ranges.
var privateRanges = []net.IPNet{
	// IPv4 private
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	// IPv4 link-local
	{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)},
}

// IsPrivateIP returns true for loopback, link-local, and RFC 1918 addresses.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupHost is the DNS resolver function used by CheckSSRF.
// It can be replaced in tests to avoid real DNS lookups.
var LookupHost = net.LookupHost

// CheckSSRF resolves the host via DNS and rejects private IPs.
// If allowedCIDRs is non-empty, resolved IPs must fall within those ranges.
// Loopback and link-local are always blocked unless explicitly allowed.
func CheckSSRF(host string, allowedCIDRs []string) error {
	// Short-circuit: if host is already an IP literal, skip DNS.
	var addrs []string
	if ip := net.ParseIP(host); ip != nil {
		addrs = []string{host}
	} else {
		var err error
		addrs, err = LookupHost(host)
		if err != nil {
			return fmt.Errorf("ssrf: DNS resolution failed for %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("ssrf: no addresses resolved for %q", host)
		}
	}

	// Parse allowed CIDRs once.
	var allowed []net.IPNet
	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("ssrf: invalid allowed CIDR %q: %w", cidr, err)
		}
		allowed = append(allowed, *network)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("ssrf: invalid IP %q resolved for %q", addr, host)
		}

		if len(allowed) > 0 {
			// When an allowlist is specified, IPs must fall within it.
			if !ipInNets(ip, allowed) {
				return fmt.Errorf("ssrf: resolved IP %s for %q is not in allowed CIDRs", ip, host)
			}
		} else {
			// Default: block private/loopback/link-local.
			if IsPrivateIP(ip) {
				return fmt.Errorf("ssrf: resolved IP %s for %q is a private address", ip, host)
			}
		}
	}

	return nil
}

func ipInNets(ip net.IP, nets []net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
