package commitment

import (
	"fmt"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
)

// MigrationConfig holds parameters for commitment migration.
type MigrationConfig struct {
	// V1 parameters (for verification)
	V1Iterations uint32
	V1Memory     uint32

	// V2 parameters (target)
	V2Iterations uint32
	V2Memory     uint32
}

// DefaultMigrationConfig returns the config for v1.x to v2.x migration.
func DefaultMigrationConfig() MigrationConfig {
	return MigrationConfig{
		V1Iterations: 1,
		V1Memory:     64 * 1024,
		V2Iterations: 3,
		V2Memory:     64 * 1024,
	}
}

// MigrationResult contains the result of a commitment migration.
type MigrationResult struct {
	OldCommitment string // v1 commitment (for reference)
	NewCommitment string // v2 commitment
	Salt          string // Salt (unchanged)
	Success       bool
	Error         error
}

// MigrateCommitment regenerates a commitment with v2 Argon2 parameters.
// The user must provide their secret again since commitments are derived from secrets.
// Returns both old (for verification) and new commitments.
func MigrateCommitment(secret string, saltHex string, migCfg MigrationConfig) MigrationResult {
	// Generate old commitment with v1 params (for verification)
	v1Config := common.SharedConfig{
		TargetYear:      2025, // doesn't affect commitment
		LimitAge:        20,
		ArgonIterations: migCfg.V1Iterations,
		ArgonMemory:     migCfg.V1Memory,
	}
	oldCommitment, _, _, err := ComputeCommitment(secret, saltHex, v1Config)
	if err != nil {
		return MigrationResult{
			Success: false,
			Error:   fmt.Errorf("failed to compute v1 commitment: %w", err),
		}
	}

	// Generate new commitment with v2 params
	v2Config := common.SharedConfig{
		TargetYear:      2025,
		LimitAge:        20,
		ArgonIterations: migCfg.V2Iterations,
		ArgonMemory:     migCfg.V2Memory,
	}
	newCommitment, _, _, err := ComputeCommitment(secret, saltHex, v2Config)
	if err != nil {
		return MigrationResult{
			OldCommitment: oldCommitment,
			Success:       false,
			Error:         fmt.Errorf("failed to compute v2 commitment: %w", err),
		}
	}

	return MigrationResult{
		OldCommitment: oldCommitment,
		NewCommitment: newCommitment,
		Salt:          saltHex,
		Success:       true,
	}
}

// VerifyAndMigrate verifies the old commitment matches and returns the new one.
// This ensures the user provided the correct secret before migration.
func VerifyAndMigrate(secret string, saltHex string, expectedOldCommitment string, migCfg MigrationConfig) MigrationResult {
	result := MigrateCommitment(secret, saltHex, migCfg)
	if !result.Success {
		return result
	}

	// Verify old commitment matches
	if result.OldCommitment != expectedOldCommitment {
		return MigrationResult{
			OldCommitment: result.OldCommitment,
			Success:       false,
			Error:         fmt.Errorf("old commitment mismatch: secret or salt may be incorrect"),
		}
	}

	return result
}

// BatchMigration migrates multiple commitments at once.
type BatchMigration struct {
	config MigrationConfig
}

// NewBatchMigration creates a batch migration helper.
func NewBatchMigration(cfg MigrationConfig) *BatchMigration {
	return &BatchMigration{config: cfg}
}

// MigrationEntry represents a single user's commitment to migrate.
type MigrationEntry struct {
	UserID        string
	Secret        string
	Salt          string
	OldCommitment string // For verification
}

// BatchMigrationResult contains results for all entries.
type BatchMigrationResult struct {
	Successful []BatchMigrationSuccess
	Failed     []BatchMigrationFailure
}

// BatchMigrationSuccess represents a successful migration.
type BatchMigrationSuccess struct {
	UserID        string
	OldCommitment string
	NewCommitment string
	Salt          string
}

// BatchMigrationFailure represents a failed migration.
type BatchMigrationFailure struct {
	UserID string
	Error  string
}

// Migrate processes all entries and returns results.
func (b *BatchMigration) Migrate(entries []MigrationEntry) BatchMigrationResult {
	result := BatchMigrationResult{
		Successful: make([]BatchMigrationSuccess, 0),
		Failed:     make([]BatchMigrationFailure, 0),
	}

	for _, entry := range entries {
		var migResult MigrationResult
		if entry.OldCommitment != "" {
			// Verify and migrate
			migResult = VerifyAndMigrate(entry.Secret, entry.Salt, entry.OldCommitment, b.config)
		} else {
			// Just migrate without verification
			migResult = MigrateCommitment(entry.Secret, entry.Salt, b.config)
		}

		if migResult.Success {
			result.Successful = append(result.Successful, BatchMigrationSuccess{
				UserID:        entry.UserID,
				OldCommitment: migResult.OldCommitment,
				NewCommitment: migResult.NewCommitment,
				Salt:          migResult.Salt,
			})
		} else {
			result.Failed = append(result.Failed, BatchMigrationFailure{
				UserID: entry.UserID,
				Error:  migResult.Error.Error(),
			})
		}
	}

	return result
}
