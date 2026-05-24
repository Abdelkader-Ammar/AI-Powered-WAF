package trustscore

import (
	"sync"
)

// UserStore defines the interface for loading and saving UserTrustProfiles.
// The in-memory implementation below is used for development and testing.
// In production, replace with a Redis or SQL-backed implementation that
// satisfies the same interface — no other files need to change.
type UserStore interface {
	Load(userID string, now float64) *UserTrustProfile
	Save(profile *UserTrustProfile)
	Delete(userID string)
}

// MemoryUserStore is a goroutine-safe in-memory UserStore.
// Profiles persist for the lifetime of the process (equivalent to a single
// server instance). In production, swap this for a RedisUserStore or
// PostgresUserStore that implements the UserStore interface.
type MemoryUserStore struct {
	mu       sync.Mutex
	profiles map[string]*UserTrustProfile
}

// NewMemoryUserStore returns an initialised MemoryUserStore.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		profiles: make(map[string]*UserTrustProfile),
	}
}

// Load returns the UserTrustProfile for userID. If no profile exists yet,
// a fresh one is created with NewUserProfile() and stored before returning.
func (s *MemoryUserStore) Load(userID string, now float64) *UserTrustProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	p, ok := s.profiles[userID]
	if !ok {
		p = NewUserProfile(userID, now)
		s.profiles[userID] = p
	}
	
	// C4 fix: returning the pointer directly, avoiding serialization copies.
	// Thread-safety is now handled internally via sync.RWMutex inside UserTrustProfile.
	return p
}

// Save is a no-op for MemoryUserStore since Load returns a mutable pointer
// that updates safely via internal mutexes.
func (s *MemoryUserStore) Save(profile *UserTrustProfile) {
	// No-op for in-memory store now that we rely on pointer mutations
}

// Delete removes a profile from the store (e.g. on account deletion or
// explicit trust-score reset by an admin).
func (s *MemoryUserStore) Delete(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, userID)
}

// DefaultUserStore is the package-level store used by ProcessEventForUser.
// Replace with a DB-backed implementation at startup, e.g.:
//
//	DefaultUserStore = NewRedisUserStore(redisClient)
var DefaultUserStore UserStore = NewMemoryUserStore()
