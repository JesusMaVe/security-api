package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionCookie = "session"

// sessionStore keeps opaque random session IDs in memory. No signing key is
// involved, so rotating secrets never invalidates a logged-in user.
type sessionStore struct {
	ttl time.Duration

	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	user    ldapUser
	expires time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{ttl: ttl, sessions: map[string]session{}}
}

func (s *sessionStore) Create(user ldapUser) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{user: user, expires: now.Add(s.ttl)}
	return id, nil
}

func (s *sessionStore) Get(id string) (ldapUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, id)
		return ldapUser{}, false
	}
	return sess.user, true
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}
