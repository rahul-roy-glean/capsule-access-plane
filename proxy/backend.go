package proxy

import "context"

// ProxyBackend abstracts the proxy transport layer.
// The Go CONNECT proxy and ICAP server are both implementations.
type ProxyBackend interface {
	// Start begins accepting connections on the given address.
	Start(ctx context.Context, addr string) error
	// Stop gracefully shuts down.
	Stop(ctx context.Context) error
	// Addr returns the listen address, or "" if not started.
	Addr() string
	// Mode returns the backend identifier (e.g., "connect", "icap").
	Mode() string
}
