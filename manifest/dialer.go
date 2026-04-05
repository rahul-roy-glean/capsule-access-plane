package manifest

import (
	"context"
	"fmt"
	"net"
	"time"
)

// PinnedDialer returns a DialContext function that connects to one of the
// pre-resolved IPs instead of performing DNS resolution again.
// This prevents DNS rebinding (TOCTOU) attacks where the DNS response changes
// between the SSRF check and the actual connection.
func PinnedDialer(resolvedIPs []net.IP, port string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var lastErr error
		for _, ip := range resolvedIPs {
			pinnedAddr := net.JoinHostPort(ip.String(), port)
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctx, network, pinnedAddr)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}
		if lastErr != nil {
			return nil, fmt.Errorf("pinned dial: all resolved IPs failed: %w", lastErr)
		}
		return nil, fmt.Errorf("pinned dial: no resolved IPs provided")
	}
}
