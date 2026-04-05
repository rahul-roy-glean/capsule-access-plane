package server

import (
	"fmt"
	"sync"
	"time"
)

// SessionRegistration represents a session registered by the orchestrator.
type SessionRegistration struct {
	SessionID   string       `json:"session_id"`
	UserEmail   string       `json:"user_email"`
	RunnerID    string       `json:"runner_id,omitempty"`
	DomainRules []DomainRule `json:"domain_rules"`
	ExpiresAt   time.Time    `json:"expires_at,omitempty"`
}

// DomainRule maps a host pattern to a credential provider and optional
// identity headers to inject into proxied requests.
type DomainRule struct {
	// HostPattern is a host glob (e.g., "*.googleapis.com").
	HostPattern string `json:"host_pattern"`
	// ProviderName is the credential provider to use for this domain.
	ProviderName string `json:"provider_name"`
	// IdentityHeaders are extra headers injected into proxied requests.
	IdentityHeaders map[string]string `json:"identity_headers,omitempty"`
}

// SessionStore is a concurrency-safe in-memory store for session registrations.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionRegistration
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*SessionRegistration),
	}
}

// Register adds a session to the store. Returns an error if a session with
// the same ID already exists.
func (s *SessionStore) Register(reg *SessionRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[reg.SessionID]; exists {
		return fmt.Errorf("session %q already registered", reg.SessionID)
	}
	s.sessions[reg.SessionID] = reg
	return nil
}

// Get returns the registration for a session, or false if not found.
func (s *SessionStore) Get(sessionID string) (*SessionRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reg, ok := s.sessions[sessionID]
	return reg, ok
}

// Deregister removes a session from the store. Returns true if the session
// existed and was removed.
func (s *SessionStore) Deregister(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[sessionID]; !exists {
		return false
	}
	delete(s.sessions, sessionID)
	return true
}

// List returns a snapshot of all registered sessions.
func (s *SessionStore) List() []*SessionRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*SessionRegistration, 0, len(s.sessions))
	for _, reg := range s.sessions {
		out = append(out, reg)
	}
	return out
}
