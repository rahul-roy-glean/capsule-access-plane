package providers

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	gcpClientMu  sync.Mutex
	gcpClientVal *http.Client
)

// gcpAuthenticatedClient returns an HTTP client authenticated with Google
// Application Default Credentials. On GKE with workload identity, this
// picks up the pod's service account credentials automatically.
// The client is created once and reused across all providers.
func gcpAuthenticatedClient(ctx context.Context) (*http.Client, error) {
	gcpClientMu.Lock()
	defer gcpClientMu.Unlock()

	if gcpClientVal != nil {
		return gcpClientVal, nil
	}

	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("gcp auth: find default credentials: %w", err)
	}

	gcpClientVal = oauth2.NewClient(ctx, creds.TokenSource)
	return gcpClientVal, nil
}
