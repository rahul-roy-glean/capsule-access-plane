package manifest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// privateRanges are the private or otherwise non-routable ranges the access
// plane should never reach by default.
var privateRanges = []net.IPNet{
	// IPv4 private
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	// IPv4 link-local
	{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)},
	// Carrier-grade NAT / shared address space
	{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
	// IPv6 unique local addresses
	{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
}

// IsPrivateIP returns true for loopback, link-local, RFC1918, ULA, and other
// non-publicly-routable ranges that should be blocked by default.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupHost is the DNS resolver function used by SSRF checks.
// It can be replaced in tests to avoid real DNS lookups.
var LookupHost = net.LookupHost

// ResolveValidatedIPs resolves a host and returns the validated IPs that are
// allowed for subsequent dialing.
func ResolveValidatedIPs(host string, allowedCIDRs []string) ([]net.IP, error) {
	// Short-circuit: if host is already an IP literal, skip DNS.
	var addrs []string
	if ip := net.ParseIP(host); ip != nil {
		addrs = []string{host}
	} else {
		var err error
		addrs, err = LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("ssrf: DNS resolution failed for %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("ssrf: no addresses resolved for %q", host)
		}
	}

	// Parse allowed CIDRs once.
	var allowed []net.IPNet
	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: invalid allowed CIDR %q: %w", cidr, err)
		}
		allowed = append(allowed, *network)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("ssrf: invalid IP %q resolved for %q", addr, host)
		}

		if len(allowed) > 0 {
			if !ipInNets(ip, allowed) {
				return nil, fmt.Errorf("ssrf: resolved IP %s for %q is not in allowed CIDRs", ip, host)
			}
		} else if IsPrivateIP(ip) {
			return nil, fmt.Errorf("ssrf: resolved IP %s for %q is a private address", ip, host)
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

// CheckSSRF resolves the host via DNS and rejects private IPs.
// If allowedCIDRs is non-empty, resolved IPs must fall within those ranges.
// Loopback and link-local are always blocked unless explicitly allowed.
func CheckSSRF(host string, allowedCIDRs []string) error {
	_, err := ResolveValidatedIPs(host, allowedCIDRs)
	return err
}

// NewPinnedDialContext returns a DialContext that only dials one of the
// previously validated IPs for a specific hostname, preventing post-check DNS
// rebinding from changing the connection target.
func NewPinnedDialContext(host string, ips []net.IP, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialHost, dialPort, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if dialHost != host {
			return nil, fmt.Errorf("ssrf: dial target host %q does not match pinned host %q", dialHost, host)
		}
		dialer := &net.Dialer{Timeout: timeout}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), dialPort))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("ssrf: no validated IPs available for %q", host)
		}
		return nil, lastErr
	}
}

// DestinationPort returns the destination port, defaulting from protocol.
func DestinationPort(dest *Destination) int {
	if dest == nil {
		return 0
	}
	if dest.Port != 0 {
		return dest.Port
	}
	switch dest.Protocol {
	case "http":
		return 80
	case "https", "":
		return 443
	default:
		return 0
	}
}

// DestinationPortString returns the destination port as a string when known.
func DestinationPortString(dest *Destination) string {
	port := DestinationPort(dest)
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}

func ipInNets(ip net.IP, nets []net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
