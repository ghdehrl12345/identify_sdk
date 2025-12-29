package auth

import (
	"sync"
	"time"
)

// RateLimiter defines the interface for login rate limiting.
type RateLimiter interface {
	// AllowLogin checks if a login attempt is allowed for the given user/IP.
	AllowLogin(userID, ip string) bool
	// RecordFailure records a failed login attempt.
	RecordFailure(userID, ip string)
	// Reset clears the failure count for a user/IP (e.g., after successful login).
	Reset(userID, ip string)
}

// RateLimitConfig holds configuration for rate limiting.
type RateLimitConfig struct {
	MaxAttempts int           // Maximum attempts before blocking
	Window      time.Duration // Time window for counting attempts
	BlockTime   time.Duration // How long to block after max attempts
}

// DefaultRateLimitConfig returns sensible defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxAttempts: 5,
		Window:      15 * time.Minute,
		BlockTime:   30 * time.Minute,
	}
}

type rateLimitEntry struct {
	attempts  int
	firstFail time.Time
	blockedAt time.Time
}

// MemoryRateLimiter is an in-memory implementation of RateLimiter.
type MemoryRateLimiter struct {
	config  RateLimitConfig
	entries map[string]*rateLimitEntry
	mu      sync.RWMutex
}

// NewMemoryRateLimiter creates a new in-memory rate limiter.
func NewMemoryRateLimiter(config RateLimitConfig) *MemoryRateLimiter {
	rl := &MemoryRateLimiter{
		config:  config,
		entries: make(map[string]*rateLimitEntry),
	}
	go rl.startCleanupLoop()
	return rl
}

func (r *MemoryRateLimiter) getKey(userID, ip string) string {
	return userID + ":" + ip
}

// AllowLogin checks if a login attempt is allowed.
func (r *MemoryRateLimiter) AllowLogin(userID, ip string) bool {
	key := r.getKey(userID, ip)

	r.mu.RLock()
	entry, exists := r.entries[key]
	r.mu.RUnlock()

	if !exists {
		return true
	}

	now := time.Now()

	// Check if blocked
	if !entry.blockedAt.IsZero() {
		if now.Before(entry.blockedAt.Add(r.config.BlockTime)) {
			return false // Still blocked
		}
		// Block time expired, allow retry
		r.Reset(userID, ip)
		return true
	}

	// Check if window expired
	if now.After(entry.firstFail.Add(r.config.Window)) {
		r.Reset(userID, ip)
		return true
	}

	// Check attempt count
	return entry.attempts < r.config.MaxAttempts
}

// RecordFailure records a failed login attempt.
func (r *MemoryRateLimiter) RecordFailure(userID, ip string) {
	key := r.getKey(userID, ip)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.entries[key]
	if !exists {
		r.entries[key] = &rateLimitEntry{
			attempts:  1,
			firstFail: now,
		}
		return
	}

	// Check if window expired
	if now.After(entry.firstFail.Add(r.config.Window)) {
		entry.attempts = 1
		entry.firstFail = now
		entry.blockedAt = time.Time{}
		return
	}

	entry.attempts++
	if entry.attempts >= r.config.MaxAttempts {
		entry.blockedAt = now
	}
}

// Reset clears the failure count for a user/IP.
func (r *MemoryRateLimiter) Reset(userID, ip string) {
	key := r.getKey(userID, ip)

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
}

func (r *MemoryRateLimiter) startCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		r.cleanup()
	}
}

func (r *MemoryRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, entry := range r.entries {
		// Remove entries where both window and block time have expired
		windowExpired := now.After(entry.firstFail.Add(r.config.Window))
		blockExpired := entry.blockedAt.IsZero() || now.After(entry.blockedAt.Add(r.config.BlockTime))
		if windowExpired && blockExpired {
			delete(r.entries, key)
		}
	}
}

// NoOpRateLimiter is a rate limiter that allows everything (for testing).
type NoOpRateLimiter struct{}

// NewNoOpRateLimiter creates a no-op rate limiter.
func NewNoOpRateLimiter() *NoOpRateLimiter {
	return &NoOpRateLimiter{}
}

// AllowLogin always returns true.
func (n *NoOpRateLimiter) AllowLogin(userID, ip string) bool {
	return true
}

// RecordFailure does nothing.
func (n *NoOpRateLimiter) RecordFailure(userID, ip string) {}

// Reset does nothing.
func (n *NoOpRateLimiter) Reset(userID, ip string) {}
