package age

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/ghdehrl12345/identify_sdk/common"
	"golang.org/x/crypto/blake2b"
)

//go:embed age.vk
var ageVerifyingKeyData []byte

// EmbeddedAgeVerifyingKeyID is the blake2b-256 fingerprint of the embedded age verifying key.
var EmbeddedAgeVerifyingKeyID = blake2bAgeVerifierSumHex(ageVerifyingKeyData)

// Verifier implements the AgeVerifier interface.
type Verifier struct {
	verifyingKey groth16.VerifyingKey
	config       common.SharedConfig
}

// VerifierConfig holds configuration for the age verifier.
type VerifierConfig struct {
	Config     common.SharedConfig
	ExpectedVK string // optional: expected verifying key fingerprint
}

// NewVerifier creates an age verifier with default config.
func NewVerifier() (*Verifier, error) {
	return NewVerifierWithConfig(VerifierConfig{Config: common.DefaultSharedConfig()})
}

// NewVerifierWithConfig creates an age verifier with custom config.
func NewVerifierWithConfig(cfg VerifierConfig) (*Verifier, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if len(ageVerifyingKeyData) == 0 {
		return nil, fmt.Errorf("embedded age verifying key is empty (run setup)")
	}
	if _, err := vk.ReadFrom(bytes.NewReader(ageVerifyingKeyData)); err != nil {
		return nil, fmt.Errorf("age verifying key parse failed: %w", err)
	}
	if cfg.ExpectedVK != "" && cfg.ExpectedVK != EmbeddedAgeVerifyingKeyID {
		return nil, fmt.Errorf("age verifying key fingerprint mismatch: expected %s got %s", cfg.ExpectedVK, EmbeddedAgeVerifyingKeyID)
	}

	return &Verifier{
		verifyingKey: vk,
		config:       pickAgeSharedConfig(cfg.Config),
	}, nil
}

// VerifyAge validates a proof asserting adulthood.
func (v *Verifier) VerifyAge(proofBytes []byte) (bool, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, fmt.Errorf("proof format error: %w", err)
	}

	var publicCurr big.Int
	publicCurr.SetInt64(int64(v.config.TargetYear))
	var publicLimit big.Int
	publicLimit.SetInt64(int64(v.config.LimitAge))

	assignment := AgeCircuit{
		CurrentYear: publicCurr,
		LimitAge:    publicLimit,
	}

	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("public witness creation failed: %w", err)
	}

	if err := groth16.Verify(proof, v.verifyingKey, publicWitness); err != nil {
		return false, fmt.Errorf("age verification failed: %w", err)
	}

	return true, nil
}

// GetConfig returns the shared configuration.
func (v *Verifier) GetConfig() common.SharedConfig {
	return v.config
}

// AgeVerifyingKeyID returns the fingerprint of the embedded age verifying key.
func AgeVerifyingKeyID() string {
	return EmbeddedAgeVerifyingKeyID
}

func pickAgeSharedConfig(cfg common.SharedConfig) common.SharedConfig {
	def := common.DefaultSharedConfig()
	if cfg.TargetYear == 0 {
		cfg.TargetYear = def.TargetYear
	}
	if cfg.LimitAge == 0 {
		cfg.LimitAge = def.LimitAge
	}
	return cfg
}

func blake2bAgeVerifierSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}
