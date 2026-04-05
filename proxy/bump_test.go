package proxy

import (
	"fmt"
	"testing"
)

func TestCertCache_Hit(t *testing.T) {
	ca, err := NewCertAuthorityWithMaxCache(10)
	if err != nil {
		t.Fatalf("NewCertAuthorityWithMaxCache: %v", err)
	}

	cert1, err := ca.GetCertificate("api.github.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	cert2, err := ca.GetCertificate("api.github.com")
	if err != nil {
		t.Fatalf("GetCertificate (cached): %v", err)
	}

	if cert1 != cert2 {
		t.Error("expected same pointer for cached cert")
	}

	if ca.CacheLen() != 1 {
		t.Errorf("cache len = %d, want 1", ca.CacheLen())
	}
}

func TestCertCache_EvictionAtMaxSize(t *testing.T) {
	const maxCache = 8
	ca, err := NewCertAuthorityWithMaxCache(maxCache)
	if err != nil {
		t.Fatalf("NewCertAuthorityWithMaxCache: %v", err)
	}

	// Fill the cache to capacity.
	for i := 0; i < maxCache; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		if _, err := ca.GetCertificate(host); err != nil {
			t.Fatalf("GetCertificate(%s): %v", host, err)
		}
	}
	if ca.CacheLen() != maxCache {
		t.Fatalf("cache len = %d, want %d", ca.CacheLen(), maxCache)
	}

	// Adding one more should trigger eviction of the oldest 25% (2 entries).
	if _, err := ca.GetCertificate("trigger.example.com"); err != nil {
		t.Fatalf("GetCertificate(trigger): %v", err)
	}

	// After eviction: removed 2 oldest, then added 1 new → 8 - 2 + 1 = 7.
	wantLen := maxCache - maxCache/4 + 1
	if ca.CacheLen() != wantLen {
		t.Errorf("cache len after eviction = %d, want %d", ca.CacheLen(), wantLen)
	}
}

func TestCertCache_EvictsOldestEntries(t *testing.T) {
	const maxCache = 4
	ca, err := NewCertAuthorityWithMaxCache(maxCache)
	if err != nil {
		t.Fatalf("NewCertAuthorityWithMaxCache: %v", err)
	}

	// Fill with host-0 through host-3.
	for i := 0; i < maxCache; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		if _, err := ca.GetCertificate(host); err != nil {
			t.Fatalf("GetCertificate(%s): %v", host, err)
		}
	}

	// Trigger eviction by adding one more. With maxCache=4, eviction removes
	// the oldest 25% = 1 entry (host-0).
	if _, err := ca.GetCertificate("new.example.com"); err != nil {
		t.Fatalf("GetCertificate(new): %v", err)
	}

	// host-0 should have been evicted.
	ca.mu.RLock()
	_, hasOldest := ca.cache["host-0.example.com"]
	ca.mu.RUnlock()
	if hasOldest {
		t.Error("expected host-0.example.com to be evicted, but it is still in cache")
	}

	// host-1 through host-3 and new should still be present.
	for _, host := range []string{"host-1.example.com", "host-2.example.com", "host-3.example.com", "new.example.com"} {
		ca.mu.RLock()
		_, ok := ca.cache[host]
		ca.mu.RUnlock()
		if !ok {
			t.Errorf("expected %s to still be in cache", host)
		}
	}
}
