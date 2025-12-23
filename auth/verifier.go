package auth

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/ghdehrl12345/identify_sdk/commitment"
	"github.com/ghdehrl12345/identify_sdk/common"
	"golang.org/x/crypto/blake2b"
)

//go:embed user.vk
var verifyingKeyData []byte

// EmbeddedVerifyingKeyID is the blake2b-256 fingerprint of the embedded verifying key.
var EmbeddedVerifyingKeyID = blake2bVerifierSumHex(verifyingKeyData)

// Verifier implements the Authenticator interface for verifying authentication proofs.
type Verifier struct {
	verifyingKey groth16.VerifyingKey
	config       common.SharedConfig
}

// VerifierConfig holds configuration for the verifier.
type VerifierConfig struct {
	Config     common.SharedConfig
	ExpectedVK string // optional: expected verifying key fingerprint
}

// NewVerifier creates a verifier with default config.
func NewVerifier() (*Verifier, error) {
	return NewVerifierWithConfig(VerifierConfig{Config: common.DefaultSharedConfig()})
}

// NewVerifierWithConfig creates a verifier with custom config.
func NewVerifierWithConfig(cfg VerifierConfig) (*Verifier, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if len(verifyingKeyData) == 0 {
		return nil, fmt.Errorf("embedded verifying key is empty (run setup)")
	}
	if _, err := vk.ReadFrom(bytes.NewReader(verifyingKeyData)); err != nil {
		return nil, fmt.Errorf("verifying key parse failed: %w", err)
	}
	if cfg.ExpectedVK != "" && cfg.ExpectedVK != EmbeddedVerifyingKeyID {
		return nil, fmt.Errorf("verifying key fingerprint mismatch: expected %s got %s", cfg.ExpectedVK, EmbeddedVerifyingKeyID)
	}

	return &Verifier{
		verifyingKey: vk,
		config:       pickSharedConfig(cfg.Config),
	}, nil
}

// CreateCommitment derives a salted commitment from a user-secret for storage.
func (v *Verifier) CreateCommitment(secret string) (string, string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", "", err
	}
	commit, _, _, err := commitment.ComputeCommitment(secret, salt, v.config)
	return commit, salt, err
}

// VerifyLogin checks whether a Groth16 proof matches the stored commitment/salt and challenge.
func (v *Verifier) VerifyLogin(proofBytes []byte, publicCommitment string, salt string, challenge int) (bool, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, fmt.Errorf("proof format error: %w", err)
	}

	var publicHashInt big.Int
	if _, ok := publicHashInt.SetString(publicCommitment, 10); !ok {
		return false, fmt.Errorf("public commitment parse failed: %s", publicCommitment)
	}

	saltInt, err := saltStringToInt(salt)
	if err != nil {
		return false, fmt.Errorf("salt parse failed: %w", err)
	}

	bindingStr, err := commitment.ComputeBinding(publicCommitment, challenge)
	if err != nil {
		return false, fmt.Errorf("binding compute failed: %w", err)
	}
	var bindingInt big.Int
	if _, ok := bindingInt.SetString(bindingStr, 10); !ok {
		return false, fmt.Errorf("binding parse failed: %s", bindingStr)
	}

	assignment := UserCircuit{
		PublicHash:  publicHashInt,
		Binding:     bindingInt,
		Salt:        saltInt,
		CurrentYear: v.config.TargetYear,
		LimitAge:    v.config.LimitAge,
		Challenge:   challenge,
	}

	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("public witness creation failed: %w", err)
	}

	if err := groth16.Verify(proof, v.verifyingKey, publicWitness); err != nil {
		return false, fmt.Errorf("proof verification failed: %w", err)
	}

	return true, nil
}

// GetConfig returns the shared configuration.
func (v *Verifier) GetConfig() common.SharedConfig {
	return v.config
}

// VerifyingKeyID returns the fingerprint of the embedded verifying key.
func VerifyingKeyID() string {
	return EmbeddedVerifyingKeyID
}

func saltStringToInt(salt string) (big.Int, error) {
	var out big.Int
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return out, err
	}
	out.SetBytes(saltBytes)
	return out, nil
}

func pickSharedConfig(cfg common.SharedConfig) common.SharedConfig {
	def := common.DefaultSharedConfig()
	if cfg.TargetYear == 0 {
		cfg.TargetYear = def.TargetYear
	}
	if cfg.LimitAge == 0 {
		cfg.LimitAge = def.LimitAge
	}
	if cfg.ArgonMemory == 0 {
		cfg.ArgonMemory = def.ArgonMemory
	}
	if cfg.ArgonIterations == 0 {
		cfg.ArgonIterations = def.ArgonIterations
	}
	return cfg
}

func blake2bVerifierSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}
