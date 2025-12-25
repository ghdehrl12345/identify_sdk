package auth

import "github.com/ghdehrl12345/identify_sdk/v2/common"

// Authenticator defines the interface for ZKP-based authentication.
type Authenticator interface {
	// CreateCommitment derives a salted commitment from a user-secret for storage.
	CreateCommitment(secret string) (commitment string, salt string, err error)
	// VerifyLogin checks whether a Groth16 proof matches the stored commitment/salt and the server-issued challenge.
	VerifyLogin(proof []byte, publicCommitment string, salt string, challenge int) (bool, error)
	// GetConfig returns the shared configuration (policy/KDF parameters).
	GetConfig() common.SharedConfig
}

// StatelessAuthenticator defines an interface for stateless challenge verification.
type StatelessAuthenticator interface {
	// VerifyLoginWithToken validates a stateless challenge token and verifies the proof.
	VerifyLoginWithToken(proof []byte, publicCommitment string, salt string, challengeToken string) (bool, error)
}

// MetaAuthenticator enforces metadata matching for vk_id and params_version.
type MetaAuthenticator interface {
	VerifyLoginWithMeta(proof []byte, publicCommitment string, salt string, challenge int, vkID string, paramsVersion string) (bool, error)
}

// PolicyProvider exposes policy metadata for client sync.
type PolicyProvider interface {
	PolicyBundle() PolicyBundle
}

// Prover defines the interface for generating ZKP proofs on the client side.
type Prover interface {
	// CalculateCommitment derives a commitment with a random salt.
	CalculateCommitment(secret string) (commitment string, salt string, err error)
	// GenerateProof creates a Groth16 proof for authentication.
	GenerateProof(secret string, birthYear int, currentYear int, limitAge int, challenge int, saltHex string) (proof []byte, commitment string, binding string, err error)
}
