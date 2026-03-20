package manifest

import (
	"net"
	"testing"
)

func TestIsPrivateIP_Loopback(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 should be private")
	}
	if !IsPrivateIP(net.ParseIP("127.0.0.2")) {
		t.Error("127.0.0.2 should be private")
	}
	if !IsPrivateIP(net.ParseIP("::1")) {
		t.Error("::1 should be private")
	}
}

func TestIsPrivateIP_RFC1918(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"140.82.121.3", false}, // github.com
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := IsPrivateIP(ip)
		if got != tt.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateIP_LinkLocal(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("169.254.0.1")) {
		t.Error("169.254.0.1 should be private (link-local)")
	}
	if !IsPrivateIP(net.ParseIP("169.254.169.254")) {
		t.Error("169.254.169.254 should be private (GCP metadata IP)")
	}
}

func TestCheckSSRF_BlocksPrivateIP(t *testing.T) {
	// Mock DNS to return a private IP.
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}

	err := CheckSSRF("evil-redirect.example.com", nil)
	if err == nil {
		t.Fatal("expected error for private IP")
	}
}

func TestCheckSSRF_AllowsPublicIP(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"140.82.121.3"}, nil
	}

	err := CheckSSRF("api.github.com", nil)
	if err != nil {
		t.Fatalf("unexpected error for public IP: %v", err)
	}
}

func TestCheckSSRF_BlocksLoopback(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}

	err := CheckSSRF("localhost", nil)
	if err == nil {
		t.Fatal("expected error for loopback")
	}
}

func TestCheckSSRF_AllowedCIDRs_Permits(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}

	// Loopback is normally blocked, but AllowedIPs explicitly permits it.
	err := CheckSSRF("localhost", []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("unexpected error with allowlist: %v", err)
	}
}

func TestCheckSSRF_AllowedCIDRs_Rejects(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"8.8.8.8"}, nil
	}

	// Only 10.0.0.0/8 is allowed, so 8.8.8.8 should be rejected.
	err := CheckSSRF("dns.google", []string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("expected error for IP outside allowed CIDRs")
	}
}

func TestCheckSSRF_MultipleAddresses_OnePrivate(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return []string{"140.82.121.3", "10.0.0.1"}, nil
	}

	// One resolved IP is private → should block.
	err := CheckSSRF("dual-homed.example.com", nil)
	if err == nil {
		t.Fatal("expected error when any resolved IP is private")
	}
}

func TestCheckSSRF_DNSFailure(t *testing.T) {
	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	LookupHost = func(host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}

	err := CheckSSRF("nonexistent.invalid", nil)
	if err == nil {
		t.Fatal("expected error for DNS failure")
	}
}
