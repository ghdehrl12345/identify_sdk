package age

import "github.com/ghdehrl12345/identify_sdk/common"

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
