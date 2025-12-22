package client

import (
	"bytes"
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ghdehrl12345/identify_sdk/core/circuits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

//go:embed user.pk
var provingKeyData []byte

type UserProver struct {
	provingKey groth16.ProvingKey
	ccs        constraint.ConstraintSystem
}

// NewUserProver: 임베딩된 증명키를 사용하여 초기화 (파일 경로 의존성 제거)
func NewUserProver() (*UserProver, error) {
	// 1. 회로 컴파일
	var circuit circuits.UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("회로 컴파일 실패: %v", err)
	}

	// 2. 임베딩된 데이터에서 키 로드
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewReader(provingKeyData))
	if err != nil {
		return nil, fmt.Errorf("증명키 파싱 실패: %v", err)
	}

	return &UserProver{
		provingKey: pk,
		ccs:        ccs,
	}, nil
}

// NewUserProverFromPK: 바이트 데이터에서 읽어오는 함수 (WASM/웹용)
func NewUserProverFromPK(pkBytes []byte) (*UserProver, error) {
	// 1. 회로 컴파일
	var circuit circuits.UserCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("회로 컴파일 실패: %v", err)
	}

	// 2. 바이트 배열에서 키 파싱
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewReader(pkBytes))
	if err != nil {
		return nil, fmt.Errorf("증명키 데이터 파싱 실패: %v", err)
	}

	return &UserProver{
		provingKey: pk,
		ccs:        ccs,
	}, nil
}

func (u *UserProver) CalculateCommitment(secret string) string {
	h := mimc.NewMiMC()
	h.Write([]byte(secret))
	hashResult := h.Sum(nil)

	var hashInt big.Int
	hashInt.SetBytes(hashResult)
	return hashInt.String()
}

func (u *UserProver) GenerateProof(secret string, birthYear int, currentYear int, limitAge int, challenge int) ([]byte, string, error) {
	commitment := u.CalculateCommitment(secret)
	var publicHashInt big.Int
	publicHashInt.SetString(commitment, 10)

	assignment := circuits.UserCircuit{
		PublicHash:  publicHashInt,
		CurrentYear: currentYear,
		LimitAge:    limitAge,
		Challenge:   challenge,

		SecretKey: generateSecretKeyElement(secret),
		BirthYear: birthYear,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, "", fmt.Errorf("위트니스 생성 실패: %v", err)
	}

	proof, err := groth16.Prove(u.ccs, u.provingKey, witness)
	if err != nil {
		return nil, "", fmt.Errorf("증명 생성 실패: %v", err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	return buf.Bytes(), commitment, nil
}

func generateSecretKeyElement(secret string) fr.Element {
	var e fr.Element
	h := mimc.NewMiMC()
	h.Write([]byte(secret))
	b := new(big.Int).SetBytes([]byte(secret))
	e.SetBigInt(b)
	return e
}
