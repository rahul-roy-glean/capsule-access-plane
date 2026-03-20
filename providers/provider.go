package providers

import (
	"context"
	"net/http"
)

// CredentialProvider supplies credentials for outbound requests to a set of hosts.
type CredentialProvider interface {
	// Name returns the unique name of this provider (e.g. "github-prod").
	Name() string

	// Type returns the provider type (e.g. "static", "github-app", "bearer-token").
	Type() string

	// Matches reports whether this provider handles the given host.
	Matches(host string) bool

	// InjectCredentials modifies the request to include the provider's credential
	// (e.g. setting an Authorization header). Used by the SSL bump proxy path.
	InjectCredentials(req *http.Request) error

	// ResolveToken returns the raw token value. Used by the remote execution
	// endpoint and the DirectHTTPAdapter proxy.
	ResolveToken(ctx context.Context) (string, error)

	// Start initializes the provider (e.g. starts background token rotation).
	Start(ctx context.Context) error

	// Stop tears down the provider.
	Stop()
}
