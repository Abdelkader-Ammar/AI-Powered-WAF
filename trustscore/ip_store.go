package trustscore

import (
	"sync"
	"time"
)

// IPStore defines the interface for loading and saving IPProfiles, mirroring the
// UserStore seam (user_store.go). The in-memory implementation below is used for
// development and single-instance deployments. In production, replace with a
// Redis- or SQL-backed implementation that satisfies the same interface — no
// scoring code needs to change.
type IPStore interface {
	// Load returns the IPProfile for ip, creating a fresh one if absent.
	Load(ip string) *IPProfile
	// Save persists a profile. For the in-memory pointer store this is a no-op,
	// since Load returns a live pointer mutated under the profile's own mutex.
	Save(profile *IPProfile)
	// Delete removes a profile (e.g. on eviction or an admin reset).
	Delete(ip string)
}

// MemoryIPStore is a goroutine-safe in-memory IPStore. It owns the profile map
// that previously lived directly in api.go, plus the eviction goroutine that
// drops profiles unseen for longer than the TTL.
type MemoryIPStore struct {
	mu       sync.Mutex
	profiles map[string]*IPProfile
}

// NewMemoryIPStore returns an initialised store and starts its eviction loop.
func NewMemoryIPStore() *MemoryIPStore {
	s := &MemoryIPStore{profiles: make(map[string]*IPProfile)}
	go s.evictLoop()
	return s
}

// evictLoop drops profiles that have not been seen within the last hour. It runs
// every 15 minutes, matching the prior behaviour of the api.go init goroutine.
func (s *MemoryIPStore) evictLoop() {
	for {
		time.Sleep(15 * time.Minute)
		now := float64(time.Now().Unix())
		s.mu.Lock()
		for ip, p := range s.profiles {
			if now-p.LastSeen > 3600 {
				delete(s.profiles, ip)
			}
		}
		s.mu.Unlock()
	}
}

// Load returns the profile for ip, creating and storing one if it does not exist.
func (s *MemoryIPStore) Load(ip string) *IPProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.profiles[ip]; ok {
		return p
	}
	p := NewIPProfile(ip)
	s.profiles[ip] = p
	return p
}

// Save is a no-op for the in-memory store: Load returns a live pointer whose
// fields are mutated under the profile's own RWMutex.
func (s *MemoryIPStore) Save(profile *IPProfile) {}

// Delete removes a profile from the store.
func (s *MemoryIPStore) Delete(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, ip)
}

// DefaultIPStore is the package-level store used by GetOrCreateProfile. Replace
// with a Redis- or SQL-backed implementation at startup, e.g.:
//
//	DefaultIPStore = NewRedisIPStore(redisClient)
var DefaultIPStore IPStore = NewMemoryIPStore()
