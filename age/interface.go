package age

import "github.com/ghdehrl12345/identify_sdk/v2/common"

// AgeVerifier defines the interface for age verification.
type AgeVerifier interface {
	// VerifyAge validates a proof asserting adulthood.
	VerifyAge(proof []byte) (bool, error)
	// GetConfig returns the shared configuration.
	GetConfig() common.SharedConfig
}

// AgeProver defines the interface for generating age proofs.
type AgeProver interface {
	// GenerateAgeProof creates a proof for age verification without revealing birth year.
	GenerateAgeProof(birthYear int, currentYear int, limitAge int) ([]byte, error)
}

// MetaAgeVerifier enforces metadata matching for vk_id and params_version.
type MetaAgeVerifier interface {
	VerifyAgeWithMeta(proof []byte, vkID string, paramsVersion string) (bool, error)
}

// PolicyProvider exposes policy metadata for client sync.
type PolicyProvider interface {
	PolicyBundle() PolicyBundle
}
