package session

import (
	"sync"
	"time"
)

// FamilyCredential holds optional per-family credential data pushed with a session policy.
type FamilyCredential struct {
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Policy defines which tool families a session is allowed to use,
// along with optional per-family credentials.
type Policy struct {
	SessionID string                       `json:"session_id"`
	Families  map[string]*FamilyCredential `json:"families"`
	CreatedAt time.Time                    `json:"created_at"`
}

// PolicyStore is a thread-safe in-memory store mapping session IDs to policies.
type PolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*Policy // session_id -> policy
}

// NewPolicyStore creates an empty PolicyStore.
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		policies: make(map[string]*Policy),
	}
}

// Set stores (or replaces) the policy for the given session ID.
func (s *PolicyStore) Set(sessionID string, p *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.SessionID = sessionID
	s.policies[sessionID] = p
}

// Get retrieves the policy for a session. Returns nil, false if not found.
func (s *PolicyStore) Get(sessionID string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[sessionID]
	return p, ok
}

// Delete removes the policy for a session.
func (s *PolicyStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, sessionID)
}

// HasPolicy reports whether a session has an active policy.
func (s *PolicyStore) HasPolicy(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.policies[sessionID]
	return ok
}
