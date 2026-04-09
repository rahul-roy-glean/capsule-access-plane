package manifest

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPinnedDialer_ConnectsToResolvedIP(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolvedIPs := []net.IP{net.ParseIP("127.0.0.1")}
	dialFn := PinnedDialer(resolvedIPs, port)

	// Accept in background.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	// Dial using PinnedDialer. The addr argument should be ignored.
	conn, err := dialFn(context.Background(), "tcp", "ignored.example.com:443")
	if err != nil {
		t.Fatalf("PinnedDialer dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Verify the connection was established.
	serverConn := <-accepted
	defer func() { _ = serverConn.Close() }()

	// Verify we connected to the expected address.
	remoteAddr := conn.RemoteAddr().String()
	expectedAddr := net.JoinHostPort("127.0.0.1", port)
	if remoteAddr != expectedAddr {
		t.Errorf("connected to %s, want %s", remoteAddr, expectedAddr)
	}
}

func TestPinnedDialer_TriesMultipleIPs(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// First IP is unreachable (198.51.100.1 is TEST-NET-2, should fail fast),
	// second IP is the local listener.
	resolvedIPs := []net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("127.0.0.1")}
	dialFn := PinnedDialer(resolvedIPs, port)

	// Accept in background.
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	conn, err := dialFn(context.Background(), "tcp", "ignored.example.com:443")
	if err != nil {
		t.Fatalf("PinnedDialer should have connected via fallback IP: %v", err)
	}
	_ = conn.Close()
}

func TestPinnedDialer_NoIPsReturnsError(t *testing.T) {
	dialFn := PinnedDialer(nil, "443")

	_, err := dialFn(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error with no resolved IPs")
	}
}

func TestPinnedDialer_AllFailReturnsError(t *testing.T) {
	// Use TEST-NET addresses that should be unreachable and timeout quickly.
	resolvedIPs := []net.IP{net.ParseIP("198.51.100.1")}
	dialFn := PinnedDialer(resolvedIPs, "1") // port 1 is unlikely to be listening

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := dialFn(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error when all IPs fail to connect")
	}
}
