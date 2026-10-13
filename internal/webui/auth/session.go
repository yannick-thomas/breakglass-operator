package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrSessionExpired = errors.New("session has expired")
	ErrStoreFull      = errors.New("session store is full")
)

const (
	// maxSessions bounds memory use; a login beyond it fails instead of
	// silently evicting a person who may be in the middle of an incident.
	maxSessions = 10000
	// maxPendingLogins bounds unauthenticated login attempts in flight.
	maxPendingLogins = 1000
	pendingLoginTTL  = 10 * time.Minute
)

// Identity is the person as the Kubernetes API server sees them. It is
// resolved with a SelfSubjectReview using the person's own credential and is
// therefore exactly the identity that admission records as requester or
// approver. OIDC claims are never used for authorization decisions.
type Identity struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

// TokenSet is the verified OIDC credential of one session.
type TokenSet struct {
	// Subject is the OIDC "sub" claim. A refresh must not change it.
	Subject      string
	IDToken      string
	Expiry       time.Time
	RefreshToken string
	DisplayName  string
}

// Session is one signed-in browser. It lives only in server memory; the
// browser holds an opaque random identifier and never sees a token.
type Session struct {
	ID          string
	Identity    Identity
	DisplayName string
	ExpiresAt   time.Time

	mu     sync.Mutex
	tokens *TokenSet // nil in dev mode
}

// NewSession creates a session for a verified identity. tokens is nil only in
// dev mode, where the developer's kubeconfig is the credential.
func NewSession(identity Identity, displayName string, tokens *TokenSet, ttl time.Duration) *Session {
	return &Session{
		Identity:    identity,
		DisplayName: displayName,
		ExpiresAt:   time.Now().Add(ttl),
		tokens:      tokens,
	}
}

// PendingLogin binds an OIDC authorization round trip to one browser.
type PendingLogin struct {
	Nonce        string
	PKCEVerifier string
	expiresAt    time.Time
}

// Store keeps sessions and pending logins in memory. Sessions do not survive
// a restart, which is acceptable for a short-lived BFF: people sign in again.
// Because of this the WebUI runs as a single replica.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	pending  map[string]PendingLogin
	now      func() time.Time
}

// NewStore creates an empty in-memory session store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*Session),
		pending:  make(map[string]PendingLogin),
		now:      time.Now,
	}
}

// Add stores a session and assigns its random identifier.
func (s *Store) Add(sess *Session) error {
	id, err := RandomString(32)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.sessions) >= maxSessions {
		return ErrStoreFull
	}
	sess.ID = id
	s.sessions[id] = sess
	return nil
}

// Get returns a live session.
func (s *Store) Get(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionExpired
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil, ErrSessionExpired
	}
	return sess, nil
}

// Delete removes a session, for example on logout or when Kubernetes no
// longer accepts its credential.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// AddPending records a login round trip under its state value.
func (s *Store) AddPending(state string, p PendingLogin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.pending) >= maxPendingLogins {
		return ErrStoreFull
	}
	p.expiresAt = s.now().Add(pendingLoginTTL)
	s.pending[state] = p
	return nil
}

// TakePending returns and removes a pending login, so that each state value
// can be redeemed at most once.
func (s *Store) TakePending(state string) (PendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	delete(s.pending, state)
	if !ok || s.now().After(p.expiresAt) {
		return PendingLogin{}, false
	}
	return p, true
}

func (s *Store) sweepLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for state, p := range s.pending {
		if now.After(p.expiresAt) {
			delete(s.pending, state)
		}
	}
}

// RandomString returns n cryptographically random bytes, base64url encoded.
func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
