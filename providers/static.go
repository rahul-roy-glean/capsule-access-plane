package providers

import (
	"context"
	"net/http"

	"github.com/rahul-roy-glean/capsule-access-plane/grants"
)

// StaticProvider wraps the existing CredentialResolver (env:/literal:/stored:)
// as a CredentialProvider. This preserves backward compatibility when no
// provider config file is supplied.
type StaticProvider struct {
	name          string
	credResolver  *grants.CredentialResolver
	credentialRef string
	hosts         map[string]bool
}

// NewStaticProvider creates a provider that resolves credentials via the given
// CredentialResolver and credential reference string.
func NewStaticProvider(name string, credResolver *grants.CredentialResolver, credentialRef string, hosts []string) *StaticProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &StaticProvider{
		name:          name,
		credResolver:  credResolver,
		credentialRef: credentialRef,
		hosts:         hostSet,
	}
}

func (p *StaticProvider) Name() string { return p.name }
func (p *StaticProvider) Type() string { return "static" }

func (p *StaticProvider) Matches(host string) bool {
	if len(p.hosts) == 0 {
		return true // default provider matches all hosts
	}
	return p.hosts[host]
}

func (p *StaticProvider) InjectCredentials(req *http.Request) error {
	token, err := p.ResolveToken(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (p *StaticProvider) ResolveToken(ctx context.Context) (string, error) {
	return p.credResolver.Resolve(ctx, p.credentialRef)
}

func (p *StaticProvider) Start(_ context.Context) error { return nil }
func (p *StaticProvider) Stop()                         {}
