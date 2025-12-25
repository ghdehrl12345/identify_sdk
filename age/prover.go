package age

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ghdehrl12345/identify_sdk/v2/common"
	"golang.org/x/crypto/blake2b"
)

//go:embed age.pk
var ageProvingKeyData []byte

// EmbeddedAgeProvingKeyID is the blake2b-256 fingerprint of the embedded age proving key.
var EmbeddedAgeProvingKeyID = blake2bAgeSumHex(ageProvingKeyData)

// Prover implements the AgeProver interface for generating age proofs.
type Prover struct {
	provingKey groth16.ProvingKey
	ccs        constraint.ConstraintSystem
	config     common.SharedConfig
}

// NewProver creates an age prover with default config.
func NewProver() (*Prover, error) {
	return NewProverWithConfig(common.DefaultSharedConfig())
}

// NewProverWithConfig creates an age prover with custom config.
func NewProverWithConfig(cfg common.SharedConfig) (*Prover, error) {
	var circuit AgeCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("age circuit compile failed: %w", err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(ageProvingKeyData)); err != nil {
		return nil, fmt.Errorf("age proving key parse failed: %w", err)
	}

	return &Prover{
		provingKey: pk,
		ccs:        ccs,
		config:     cfg,
	}, nil
}

// GenerateAgeProof creates a proof for age verification.
func (p *Prover) GenerateAgeProof(birthYear int, currentYear int, limitAge int) ([]byte, error) {
	if currentYear == 0 {
		currentYear = p.config.TargetYear
	}
	if limitAge == 0 {
		limitAge = p.config.LimitAge
	}

	var publicCurr big.Int
	publicCurr.SetInt64(int64(currentYear))
	var publicLimit big.Int
	publicLimit.SetInt64(int64(limitAge))

	assignment := AgeCircuit{
		CurrentYear: publicCurr,
		LimitAge:    publicLimit,
		BirthYear:   birthYear,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("age witness creation failed: %w", err)
	}

	proof, err := groth16.Prove(p.ccs, p.provingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("age proof generation failed: %w", err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	return buf.Bytes(), nil
}

// AgeProvingKeyID returns the fingerprint of the embedded age proving key.
func AgeProvingKeyID() string {
	return EmbeddedAgeProvingKeyID
}

func blake2bAgeSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}
