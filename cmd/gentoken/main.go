package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
)

func main() {
	secret := flag.String("secret", "", "HMAC secret (required)")
	runnerID := flag.String("runner-id", "runner-1", "Runner ID")
	sessionID := flag.String("session-id", "session-1", "Session ID")
	ttl := flag.Duration("ttl", time.Hour, "Token TTL")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "error: -secret is required")
		os.Exit(1)
	}

	claims := &identity.Claims{
		RunnerID:    *runnerID,
		SessionID:   *sessionID,
		WorkloadKey: "wk-local",
		HostID:      "host-local",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(*ttl),
	}

	token, err := identity.SignClaims(claims, []byte(*secret))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(token)
}
