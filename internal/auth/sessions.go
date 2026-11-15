package auth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// maxSessions bounds memory; the oldest session is dropped past it.
const maxSessions = 10000

type session struct {
	name    string
	role    Role
	csrf    string
	expires time.Time
}

// sessionStore keeps sessions in memory, keyed by a hash of the session id
// so a memory dump does not hand out usable cookies. Sessions end on
// restart; users sign in again.
type sessionStore struct {
	mu   sync.Mutex
	byID map[[32]byte]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{byID: map[[32]byte]*session{}}
}

// create returns a new session id.
func (s *sessionStore) create(name string, role Role, ttl time.Duration, now time.Time) (id string, sess *session) {
	id = randomToken(32)
	sess = &session{name: name, role: role, csrf: randomToken(32), expires: now.Add(ttl)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byID) >= maxSessions {
		s.sweepLocked(now)
		if len(s.byID) >= maxSessions {
			var oldestKey [32]byte
			var oldest time.Time
			for k, v := range s.byID {
				if oldest.IsZero() || v.expires.Before(oldest) {
					oldestKey, oldest = k, v.expires
				}
			}
			delete(s.byID, oldestKey)
		}
	}
	s.byID[sha256.Sum256([]byte(id))] = sess
	return id, sess
}

func (s *sessionStore) get(id string, now time.Time) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(id))
	sess, ok := s.byID[k]
	if !ok {
		return session{}, false
	}
	if now.After(sess.expires) {
		delete(s.byID, k)
		return session{}, false
	}
	return *sess, true
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, sha256.Sum256([]byte(id)))
}

func (s *sessionStore) sweepLocked(now time.Time) {
	for k, v := range s.byID {
		if now.After(v.expires) {
			delete(s.byID, k)
		}
	}
}
