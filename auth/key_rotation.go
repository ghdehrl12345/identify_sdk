package auth

import (
	"fmt"
	"sync"
	"time"
)

// KeyVersion represents a versioned key pair.
type KeyVersion struct {
	Version   string    // Semantic version (e.g., "v1.0.0")
	VKID      string    // Verifying key fingerprint
	PKID      string    // Proving key fingerprint
	CreatedAt time.Time // When this version was created
	ExpiresAt time.Time // When this version expires (0 = never)
	IsActive  bool      // Whether this is the current active version
}

// KeyManager defines the interface for key version management.
type KeyManager interface {
	// GetActiveVersion returns the currently active key version.
	GetActiveVersion() (*KeyVersion, error)
	// GetVersion returns a specific key version by ID.
	GetVersion(vkID string) (*KeyVersion, error)
	// ListVersions returns all available key versions.
	ListVersions() ([]KeyVersion, error)
	// IsVersionValid checks if a version is still valid for verification.
	IsVersionValid(vkID string) bool
	// RegisterVersion registers a new key version.
	RegisterVersion(version KeyVersion) error
	// SetActiveVersion sets the active key version.
	SetActiveVersion(vkID string) error
	// DeprecateVersion marks a version as deprecated.
	DeprecateVersion(vkID string) error
}

// MemoryKeyManager is an in-memory implementation of KeyManager.
type MemoryKeyManager struct {
	versions      map[string]*KeyVersion
	activeVersion string
	mu            sync.RWMutex
}

// NewMemoryKeyManager creates a new in-memory key manager.
func NewMemoryKeyManager() *MemoryKeyManager {
	return &MemoryKeyManager{
		versions: make(map[string]*KeyVersion),
	}
}

// GetActiveVersion returns the currently active key version.
func (m *MemoryKeyManager) GetActiveVersion() (*KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeVersion == "" {
		return nil, fmt.Errorf("no active key version")
	}
	v, ok := m.versions[m.activeVersion]
	if !ok {
		return nil, fmt.Errorf("active version not found: %s", m.activeVersion)
	}
	return v, nil
}

// GetVersion returns a specific key version by VKID.
func (m *MemoryKeyManager) GetVersion(vkID string) (*KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.versions[vkID]
	if !ok {
		return nil, fmt.Errorf("version not found: %s", vkID)
	}
	return v, nil
}

// ListVersions returns all available key versions.
func (m *MemoryKeyManager) ListVersions() ([]KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := make([]KeyVersion, 0, len(m.versions))
	for _, v := range m.versions {
		versions = append(versions, *v)
	}
	return versions, nil
}

// IsVersionValid checks if a version is still valid for verification.
func (m *MemoryKeyManager) IsVersionValid(vkID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.versions[vkID]
	if !ok {
		return false
	}
	// Check expiration
	if !v.ExpiresAt.IsZero() && time.Now().After(v.ExpiresAt) {
		return false
	}
	return true
}

// RegisterVersion registers a new key version.
func (m *MemoryKeyManager) RegisterVersion(version KeyVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.versions[version.VKID]; exists {
		return fmt.Errorf("version already exists: %s", version.VKID)
	}
	m.versions[version.VKID] = &version

	// Auto-activate if first version
	if m.activeVersion == "" {
		m.activeVersion = version.VKID
		m.versions[version.VKID].IsActive = true
	}
	return nil
}

// SetActiveVersion sets the active key version.
func (m *MemoryKeyManager) SetActiveVersion(vkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.versions[vkID]; !ok {
		return fmt.Errorf("version not found: %s", vkID)
	}

	// Deactivate current
	if m.activeVersion != "" {
		if v, ok := m.versions[m.activeVersion]; ok {
			v.IsActive = false
		}
	}

	// Activate new
	m.activeVersion = vkID
	m.versions[vkID].IsActive = true
	return nil
}

// DeprecateVersion marks a version as deprecated by setting an expiration.
func (m *MemoryKeyManager) DeprecateVersion(vkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, ok := m.versions[vkID]
	if !ok {
		return fmt.Errorf("version not found: %s", vkID)
	}

	// Set expiration to 30 days from now for graceful deprecation
	v.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	return nil
}

// KeyRotationConfig holds configuration for key rotation.
type KeyRotationConfig struct {
	// GracePeriod is how long old keys remain valid after rotation.
	GracePeriod time.Duration
	// NotifyBeforeExpiry notifies N days before key expiry.
	NotifyBeforeExpiry time.Duration
}

// DefaultKeyRotationConfig returns sensible defaults.
func DefaultKeyRotationConfig() KeyRotationConfig {
	return KeyRotationConfig{
		GracePeriod:        30 * 24 * time.Hour, // 30 days
		NotifyBeforeExpiry: 7 * 24 * time.Hour,  // 7 days
	}
}

// KeyRotationNotifier is called when key rotation events occur.
type KeyRotationNotifier func(event KeyRotationEvent)

// KeyRotationEvent represents a key rotation event.
type KeyRotationEvent struct {
	Type      string    // "rotation", "expiry_warning", "expired"
	OldVKID   string    // Previous key ID (for rotation)
	NewVKID   string    // New key ID (for rotation)
	ExpiresAt time.Time // When the key expires
	Message   string    // Human-readable message
}

// AutoKeyRotator monitors key expiration and triggers notifications.
type AutoKeyRotator struct {
	manager  KeyManager
	config   KeyRotationConfig
	notifier KeyRotationNotifier
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewAutoKeyRotator creates an automatic key rotation monitor.
func NewAutoKeyRotator(manager KeyManager, config KeyRotationConfig, notifier KeyRotationNotifier) *AutoKeyRotator {
	return &AutoKeyRotator{
		manager:  manager,
		config:   config,
		notifier: notifier,
		done:     make(chan struct{}),
	}
}

// Start begins monitoring for key expiration.
func (r *AutoKeyRotator) Start() {
	r.wg.Add(1)
	go r.monitorLoop()
}

// Stop stops the rotation monitor.
func (r *AutoKeyRotator) Stop() {
	close(r.done)
	r.wg.Wait()
}

func (r *AutoKeyRotator) monitorLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.checkExpiration()
		case <-r.done:
			return
		}
	}
}

func (r *AutoKeyRotator) checkExpiration() {
	versions, err := r.manager.ListVersions()
	if err != nil {
		return
	}

	now := time.Now()
	for _, v := range versions {
		if v.ExpiresAt.IsZero() {
			continue
		}

		// Check if expiring soon
		if v.ExpiresAt.Sub(now) <= r.config.NotifyBeforeExpiry && v.ExpiresAt.After(now) {
			if r.notifier != nil {
				r.notifier(KeyRotationEvent{
					Type:      "expiry_warning",
					OldVKID:   v.VKID,
					ExpiresAt: v.ExpiresAt,
					Message:   fmt.Sprintf("Key %s expires in %v", v.VKID[:8], v.ExpiresAt.Sub(now).Round(time.Hour)),
				})
			}
		}

		// Check if expired
		if now.After(v.ExpiresAt) {
			if r.notifier != nil {
				r.notifier(KeyRotationEvent{
					Type:      "expired",
					OldVKID:   v.VKID,
					ExpiresAt: v.ExpiresAt,
					Message:   fmt.Sprintf("Key %s has expired", v.VKID[:8]),
				})
			}
		}
	}
}
