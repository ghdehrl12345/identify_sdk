package auth

import (
	"sync"
	"time"
)

// TokenStore defines the interface for JTI storage to prevent token replay attacks.
type TokenStore interface {
	// Store saves a JTI with its expiration time. Returns error if JTI already exists.
	Store(jti string, expiresAt time.Time) error
	// Exists checks if a JTI has been used.
	Exists(jti string) bool
	// Cleanup removes expired JTIs.
	Cleanup()
}

// MemoryTokenStore is an in-memory implementation of TokenStore.
type MemoryTokenStore struct {
	tokens map[string]time.Time
	mu     sync.RWMutex
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	store := &MemoryTokenStore{
		tokens: make(map[string]time.Time),
	}
	// Start background cleanup goroutine
	go store.startCleanupLoop()
	return store
}

// Store saves a JTI. Returns error if already exists.
func (m *MemoryTokenStore) Store(jti string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tokens[jti]; exists {
		return ErrJTIAlreadyUsed
	}
	m.tokens[jti] = expiresAt
	return nil
}

// Exists checks if a JTI has been used.
func (m *MemoryTokenStore) Exists(jti string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.tokens[jti]
	return exists
}

// Cleanup removes expired JTIs.
func (m *MemoryTokenStore) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for jti, expiresAt := range m.tokens {
		if now.After(expiresAt) {
			delete(m.tokens, jti)
		}
	}
}

func (m *MemoryTokenStore) startCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.Cleanup()
	}
}

// NoOpTokenStore is a no-op implementation for environments without replay protection.
type NoOpTokenStore struct{}

// NewNoOpTokenStore creates a no-op token store.
func NewNoOpTokenStore() *NoOpTokenStore {
	return &NoOpTokenStore{}
}

// Store always succeeds.
func (n *NoOpTokenStore) Store(jti string, expiresAt time.Time) error {
	return nil
}

// Exists always returns false.
func (n *NoOpTokenStore) Exists(jti string) bool {
	return false
}

// Cleanup does nothing.
func (n *NoOpTokenStore) Cleanup() {}

// ErrJTIAlreadyUsed is returned when a JTI has already been used.
var ErrJTIAlreadyUsed = New("E1013", "token already used (replay detected)")

// New creates a new error (imported pattern from errors package).
func New(code, message string) *TokenError {
	return &TokenError{Code: code, Message: message}
}

// TokenError represents a token-related error.
type TokenError struct {
	Code    string
	Message string
}

func (e *TokenError) Error() string {
	return e.Code + ": " + e.Message
}
