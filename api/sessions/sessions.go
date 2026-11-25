// Package sessions implements the in-process session store for the
// turnpass-x API server. Each session owns a cookie jar. The store is
// thread-safe and not coupled to the solving engine.
package sessions

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cestrenium/turnpass/api/types"
	"github.com/cestrenium/turnpass/internal/cookies"
)

// DefaultTTL is the default session lifetime in minutes.
const DefaultTTL = 15

// Session is a single named session with its own cookie jar.
type Session struct {
	ID      string
	Cookies *cookies.Jar
	Expires time.Time
	Created time.Time
}

// Store manages sessions in memory.
type Store struct {
	mu         sync.RWMutex
	sessions   map[string]*Session
	defaultTTL time.Duration
}

// New returns an empty session store with the given default TTL.
func New(defaultTTL time.Duration) *Store {
	if defaultTTL <= 0 {
		defaultTTL = DefaultTTL * time.Minute
	}
	return &Store{
		sessions:   make(map[string]*Session),
		defaultTTL: defaultTTL,
	}
}

// Create creates a new session with the given ID and TTL. If id is empty, a
// new random ID is generated. Returns the session.
func (s *Store) Create(id string, ttlMinutes int) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		id = generateID()
	} else if _, exists := s.sessions[id]; exists {
		return nil, fmt.Errorf("session %q already exists", id)
	}
	ttl := s.defaultTTL
	if ttlMinutes > 0 {
		ttl = time.Duration(ttlMinutes) * time.Minute
	}
	sess := &Session{
		ID:      id,
		Cookies: cookies.New(),
		Expires: time.Now().Add(ttl),
		Created: time.Now(),
	}
	s.sessions[id] = sess
	return sess, nil
}

// Get returns the session with the given ID, creating it if createMissing is
// true. Returns an error if the session does not exist and createMissing is
// false, or if it has expired.
func (s *Store) Get(id string, createMissing bool) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		if !createMissing {
			return nil, fmt.Errorf("session %q not found", id)
		}
		sess = &Session{
			ID:      id,
			Cookies: cookies.New(),
			Expires: time.Now().Add(s.defaultTTL),
			Created: time.Now(),
		}
		s.sessions[id] = sess
		return sess, nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, id)
		if !createMissing {
			return nil, fmt.Errorf("session %q expired", id)
		}
		sess = &Session{
			ID:      id,
			Cookies: cookies.New(),
			Expires: time.Now().Add(s.defaultTTL),
			Created: time.Now(),
		}
		s.sessions[id] = sess
	}
	return sess, nil
}

// List returns all live sessions, pruning expired ones as a side effect.
func (s *Store) List() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []*Session
	for id, sess := range s.sessions {
		if now.After(sess.Expires) {
			delete(s.sessions, id)
			continue
		}
		out = append(out, sess)
	}
	return out
}

// Destroy removes a session. Returns ErrNotFound if it does not exist.
func (s *Store) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return ErrNotFound
	}
	delete(s.sessions, id)
	return nil
}

// CookiesForSession returns the cookies of a session as FlareSolverr cookies.
func (s *Store) CookiesForSession(id string) ([]types.Cookie, error) {
	sess, err := s.Get(id, false)
	if err != nil {
		return nil, err
	}
	all := sess.Cookies.All()
	out := make([]types.Cookie, 0, len(all))
	for _, c := range all {
		out = append(out, types.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HttpOnly: c.HttpOnly,
		})
	}
	return out, nil
}

// ErrNotFound is returned when a session does not exist.
var ErrNotFound = errors.New("session not found")

// generateID returns a short unique session ID.
func generateID() string {
	return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}
