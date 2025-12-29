package commitment

import (
	"testing"
)

func TestMigrateCommitment(t *testing.T) {
	secret := "test-secret-123"
	salt := "0123456789abcdef0123456789abcdef" // 32-byte hex

	cfg := DefaultMigrationConfig()
	result := MigrateCommitment(secret, salt, cfg)

	if !result.Success {
		t.Fatalf("migration failed: %v", result.Error)
	}

	if result.OldCommitment == "" {
		t.Error("old commitment is empty")
	}
	if result.NewCommitment == "" {
		t.Error("new commitment is empty")
	}
	if result.OldCommitment == result.NewCommitment {
		t.Error("old and new commitments should be different (different Argon2 params)")
	}

	t.Logf("Old (v1): %s", result.OldCommitment[:20]+"...")
	t.Logf("New (v2): %s", result.NewCommitment[:20]+"...")
}

func TestVerifyAndMigrate(t *testing.T) {
	secret := "test-secret-123"
	salt := "0123456789abcdef0123456789abcdef"

	cfg := DefaultMigrationConfig()

	// First, get the correct old commitment
	firstResult := MigrateCommitment(secret, salt, cfg)
	if !firstResult.Success {
		t.Fatalf("initial migration failed: %v", firstResult.Error)
	}

	// Now verify and migrate with correct old commitment
	result := VerifyAndMigrate(secret, salt, firstResult.OldCommitment, cfg)
	if !result.Success {
		t.Fatalf("verify and migrate failed: %v", result.Error)
	}

	if result.NewCommitment != firstResult.NewCommitment {
		t.Error("new commitments should match")
	}
}

func TestVerifyAndMigrate_WrongSecret(t *testing.T) {
	secret := "test-secret-123"
	wrongSecret := "wrong-secret"
	salt := "0123456789abcdef0123456789abcdef"

	cfg := DefaultMigrationConfig()

	// Get correct old commitment
	correctResult := MigrateCommitment(secret, salt, cfg)
	if !correctResult.Success {
		t.Fatalf("initial migration failed: %v", correctResult.Error)
	}

	// Try with wrong secret
	result := VerifyAndMigrate(wrongSecret, salt, correctResult.OldCommitment, cfg)
	if result.Success {
		t.Error("should fail with wrong secret")
	}
	if result.Error == nil {
		t.Error("should have error")
	}
}

func TestBatchMigration(t *testing.T) {
	cfg := DefaultMigrationConfig()
	batch := NewBatchMigration(cfg)

	entries := []MigrationEntry{
		{
			UserID: "user1",
			Secret: "password1",
			Salt:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
		},
		{
			UserID: "user2",
			Secret: "password2",
			Salt:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2",
		},
	}

	result := batch.Migrate(entries)

	if len(result.Successful) != 2 {
		t.Errorf("expected 2 successful, got %d", len(result.Successful))
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected 0 failed, got %d", len(result.Failed))
	}

	for _, s := range result.Successful {
		t.Logf("User %s: old=%s... new=%s...", s.UserID, s.OldCommitment[:10], s.NewCommitment[:10])
	}
}
