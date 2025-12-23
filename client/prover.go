package client

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ghdehrl12345/identify_sdk/common"
	"github.com/ghdehrl12345/identify_sdk/core/circuits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

//go:embed user.pk
var provingKeyData []byte

//go:embed age.pk
var ageProvingKeyData []byte

var EmbeddedProvingKeyID = blake2bSumHex(provingKeyData)

type Policy struct {
	MinimumAge      int
	ChallengeWindow int
	Timezone        string
}

func DefaultPolicy() Policy {
	return Policy{MinimumAge: 20, ChallengeWindow: 0, Timezone: "UTC"}
}

type UserProver struct {
	provingKey groth16.ProvingKey
	agePK      groth16.ProvingKey
	ccs        constraint.ConstraintSystem
	ageCCS     constraint.ConstraintSystem
	policy     Policy
	config     common.SharedConfig
}

// NewUserProver: embed keys with default policy/config.
func NewUserProver() (*UserProver, error) {
	return NewUserProverWithPolicy(DefaultPolicy(), common.DefaultSharedConfig())
}

func NewUserProverWithPolicy(policy Policy, cfg common.SharedConfig) (*UserProver, error) {
	// Compile circuits
	var circuit circuits.UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("회로 컴파일 실패: %v", err)
	}
	var age circuits.AgeCircuit
	ageCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &age)
	if err != nil {
		return nil, fmt.Errorf("Age 회로 컴파일 실패: %v", err)
	}

	// Load proving keys
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(provingKeyData)); err != nil {
		return nil, fmt.Errorf("증명키 파싱 실패: %v", err)
	}
	agePK := groth16.NewProvingKey(ecc.BN254)
	if _, err := agePK.ReadFrom(bytes.NewReader(ageProvingKeyData)); err != nil {
		return nil, fmt.Errorf("Age 증명키 파싱 실패: %v", err)
	}

	return &UserProver{
		provingKey: pk,
		agePK:      agePK,
		ccs:        ccs,
		ageCCS:     ageCCS,
		policy:     policy,
		config:     cfg,
	}, nil
}

func NewUserProverFromPK(pkBytes []byte) (*UserProver, error) {
	return NewUserProverFromPKWithPolicy(pkBytes, DefaultPolicy(), common.DefaultSharedConfig())
}

func NewUserProverFromPKWithPolicy(pkBytes []byte, policy Policy, cfg common.SharedConfig) (*UserProver, error) {
	// Compile circuits
	var circuit circuits.UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("회로 컴파일 실패: %v", err)
	}
	var age circuits.AgeCircuit
	ageCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &age)
	if err != nil {
		return nil, fmt.Errorf("Age 회로 컴파일 실패: %v", err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return nil, fmt.Errorf("증명키 데이터 파싱 실패: %v", err)
	}
	agePK := groth16.NewProvingKey(ecc.BN254)
	if _, err := agePK.ReadFrom(bytes.NewReader(ageProvingKeyData)); err != nil {
		return nil, fmt.Errorf("Age 증명키 데이터 파싱 실패: %v", err)
	}

	return &UserProver{
		provingKey: pk,
		agePK:      agePK,
		ccs:        ccs,
		ageCCS:     ageCCS,
		policy:     policy,
		config:     cfg,
	}, nil
}

func CalculateCommitmentWithConfig(secret string, cfg common.SharedConfig) (string, string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", "", err
	}
	commit, _, _, _, err := computeCommitmentBundle(secret, salt, 0, cfg)
	return commit, salt, err
}

// CalculateCommitment derives a commitment with a random salt using default config.
func (u *UserProver) CalculateCommitment(secret string) (string, string, error) {
	return CalculateCommitmentWithConfig(secret, u.config)
}

func (u *UserProver) GenerateProof(secret string, birthYear int, currentYear int, limitAge int, challenge int, saltHex string) ([]byte, string, string, error) {
	if limitAge == 0 {
		limitAge = u.policy.MinimumAge
	}
	if currentYear == 0 {
		currentYear = u.config.TargetYear
	}
	commitment, binding, derived, saltInt, err := computeCommitmentBundle(secret, saltHex, challenge, u.config)
	if err != nil {
		return nil, "", "", err
	}

	var publicHashInt big.Int
	publicHashInt.SetString(commitment, 10)
	var bindingInt big.Int
	bindingInt.SetString(binding, 10)

	assignment := circuits.UserCircuit{
		PublicHash:  publicHashInt,
		Binding:     bindingInt,
		Salt:        saltInt,
		CurrentYear: currentYear,
		LimitAge:    limitAge,
		Challenge:   challenge,
		SecretKey:   derived,
		BirthYear:   birthYear,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, "", "", fmt.Errorf("위트니스 생성 실패: %v", err)
	}

	proof, err := groth16.Prove(u.ccs, u.provingKey, witness)
	if err != nil {
		return nil, "", "", fmt.Errorf("증명 생성 실패: %v", err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	return buf.Bytes(), commitment, binding, nil
}

// GenerateAgeProof creates a proof for AgeCircuit (CurrentYear - BirthYear >= LimitAge).
func (u *UserProver) GenerateAgeProof(birthYear int, currentYear int, limitAge int) ([]byte, error) {
	if limitAge == 0 {
		limitAge = u.policy.MinimumAge
	}
	if currentYear == 0 {
		currentYear = u.config.TargetYear
	}

	var publicCurr big.Int
	publicCurr.SetInt64(int64(currentYear))
	var publicLimit big.Int
	publicLimit.SetInt64(int64(limitAge))

	assignment := circuits.AgeCircuit{
		CurrentYear: publicCurr,
		LimitAge:    publicLimit,
		BirthYear:   birthYear,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("Age 위트니스 생성 실패: %v", err)
	}
	proof, err := groth16.Prove(u.ageCCS, u.agePK, witness)
	if err != nil {
		return nil, fmt.Errorf("Age 증명 생성 실패: %v", err)
	}
	var buf bytes.Buffer
	proof.WriteTo(&buf)
	return buf.Bytes(), nil
}

func GenerateSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ComputeCommitmentAndBinding exports commitment/binding derivation for callers (registration or server-side helpers).
func ComputeCommitmentAndBinding(secret string, saltHex string, challenge int, cfg common.SharedConfig) (string, string, error) {
	commit, bind, _, _, err := computeCommitmentBundle(secret, saltHex, challenge, cfg)
	return commit, bind, err
}

// ProvingKeyID returns the blake2b-256 fingerprint of the embedded proving key.
func ProvingKeyID() string {
	return EmbeddedProvingKeyID
}

func computeCommitmentBundle(secret string, saltHex string, challenge int, cfg common.SharedConfig) (commitment string, binding string, derived fr.Element, saltInt big.Int, err error) {
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", "", derived, saltInt, fmt.Errorf("salt decode 실패: %v", err)
	}
	saltInt.SetBytes(saltBytes)

	derivedBytes := argon2.IDKey([]byte(secret), saltBytes, cfg.ArgonIterations, cfg.ArgonMemory, common.ArgonThreads, common.ArgonKeyLen)

	var derivedInt big.Int
	derivedInt.SetBytes(derivedBytes)
	derived.SetBigInt(&derivedInt)

	var saltElem, derivedElem fr.Element
	saltElem.SetBigInt(&saltInt)
	derivedElem.SetBigInt(&derivedInt)

	commitHasher := mimc.NewMiMC()
	deBytes := derivedElem.Bytes()
	sBytes := saltElem.Bytes()
	commitHasher.Write(deBytes[:])
	commitHasher.Write(sBytes[:])
	commitBytes := commitHasher.Sum(nil)

	var commitInt big.Int
	commitInt.SetBytes(commitBytes)
	commitment = commitInt.String()

	chInt := big.NewInt(int64(challenge))
	bindHasher := mimc.NewMiMC()
	bindHasher.Write(commitInt.Bytes())
	bindHasher.Write(chInt.Bytes())
	bindBytes := bindHasher.Sum(nil)

	var bindInt big.Int
	bindInt.SetBytes(bindBytes)
	binding = bindInt.String()

	return commitment, binding, derived, saltInt, nil
}

func blake2bSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}
