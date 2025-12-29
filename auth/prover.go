package auth

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ghdehrl12345/identify_sdk/v2/commitment"
	"github.com/ghdehrl12345/identify_sdk/v2/common"
	"golang.org/x/crypto/blake2b"
)

//go:embed user.pk
var provingKeyData []byte

// EmbeddedProvingKeyID is the blake2b-256 fingerprint of the embedded proving key.
var EmbeddedProvingKeyID = blake2bSumHex(provingKeyData)

// Policy defines client-side policy parameters.
type Policy struct {
	MinimumAge      int
	ChallengeWindow int
	Timezone        string
}

// DefaultPolicy returns the default policy.
func DefaultPolicy() Policy {
	return Policy{MinimumAge: 20, ChallengeWindow: 0, Timezone: "UTC"}
}

// UserProver implements the Prover interface for generating authentication proofs.
type UserProver struct {
	provingKey groth16.ProvingKey
	ccs        constraint.ConstraintSystem
	policy     Policy
	config     common.SharedConfig
}

// NewUserProver creates a prover with default policy and config.
func NewUserProver() (*UserProver, error) {
	return NewUserProverWithPolicy(DefaultPolicy(), common.DefaultSharedConfig())
}

// NewUserProverWithPolicy creates a prover with custom policy and config.
func NewUserProverWithPolicy(policy Policy, cfg common.SharedConfig) (*UserProver, error) {
	var circuit UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compile failed: %w", err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(provingKeyData)); err != nil {
		return nil, fmt.Errorf("proving key parse failed: %w", err)
	}

	return &UserProver{
		provingKey: pk,
		ccs:        ccs,
		policy:     policy,
		config:     cfg,
	}, nil
}

// NewUserProverFromPK creates a prover from external proving key bytes.
func NewUserProverFromPK(pkBytes []byte) (*UserProver, error) {
	return NewUserProverFromPKWithPolicy(pkBytes, DefaultPolicy(), common.DefaultSharedConfig())
}

// NewUserProverFromPKWithPolicy creates a prover from external proving key with custom policy.
func NewUserProverFromPKWithPolicy(pkBytes []byte, policy Policy, cfg common.SharedConfig) (*UserProver, error) {
	var circuit UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compile failed: %w", err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return nil, fmt.Errorf("proving key parse failed: %w", err)
	}

	return &UserProver{
		provingKey: pk,
		ccs:        ccs,
		policy:     policy,
		config:     cfg,
	}, nil
}

// CalculateCommitment derives a commitment with a random salt.
func (u *UserProver) CalculateCommitment(secret string) (string, string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", "", err
	}
	commit, _, _, err := commitment.ComputeCommitment(secret, salt, u.config)
	return commit, salt, err
}

// GenerateProof creates a Groth16 proof for authentication.
func (u *UserProver) GenerateProof(secret string, birthYear int, currentYear int, limitAge int, challenge int, saltHex string) ([]byte, string, string, error) {
	if limitAge == 0 {
		limitAge = u.policy.MinimumAge
	}
	if currentYear == 0 {
		currentYear = u.config.TargetYear
	}

	commitmentStr, binding, derived, saltInt, err := commitment.ComputeCommitmentAndBinding(secret, saltHex, challenge, u.config)
	if err != nil {
		return nil, "", "", err
	}

	var publicHashInt big.Int
	publicHashInt.SetString(commitmentStr, 10)
	var bindingInt big.Int
	bindingInt.SetString(binding, 10)

	assignment := UserCircuit{
		PublicHash:  publicHashInt,
		Binding:     bindingInt,
		Salt:        saltInt,
		CurrentYear: currentYear,
		LimitAge:    limitAge,
		Challenge:   challenge,
		SecretKey:   frToBigInt(derived),
		BirthYear:   birthYear,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, "", "", fmt.Errorf("witness creation failed: %w", err)
	}

	proof, err := groth16.Prove(u.ccs, u.provingKey, witness)
	if err != nil {
		return nil, "", "", fmt.Errorf("proof generation failed: %w", err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	return buf.Bytes(), commitmentStr, binding, nil
}

// SaltBytes is the number of bytes for salt generation.
// NIST recommends 128-bit minimum; we use 256-bit (32 bytes) for enhanced security.
const SaltBytes = 32

// GenerateSalt generates a random 32-byte salt as hex string.
func GenerateSalt() (string, error) {
	buf := make([]byte, SaltBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ProvingKeyID returns the fingerprint of the embedded proving key.
func ProvingKeyID() string {
	return EmbeddedProvingKeyID
}

func blake2bSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func frToBigInt(e fr.Element) big.Int {
	var i big.Int
	e.BigInt(&i)
	return i
}
