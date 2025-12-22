package server

import (
	"bytes"
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ghdehrl12345/identify_sdk/core/circuits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

//go:embed user.vk
var verifyingKeyData []byte

// RealIdentify verifies Groth16 proofs with an embedded verifying key.
type RealIdentify struct {
	verifyingKey groth16.VerifyingKey
}

// NewRealSDK instantiates an IdentifySDK backed by the embedded verifying key.
func NewRealSDK() (IdentifySDK, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if len(verifyingKeyData) == 0 {
		return nil, fmt.Errorf("임베딩된 검증키가 비어있습니다 (setup 실행 필요)")
	}

	_, err := vk.ReadFrom(bytes.NewReader(verifyingKeyData))
	if err != nil {
		return nil, fmt.Errorf("검증키 파싱 실패: %v", err)
	}

	return &RealIdentify{verifyingKey: vk}, nil
}

// CreateCommitment derives a deterministic MiMC-style hash placeholder for storage in databases.
func (r *RealIdentify) CreateCommitment(secret string) (string, error) {
	return "MIMC_HASH_" + secret, nil
}

// VerifyLogin parses the Groth16 proof and checks it against the stored commitment and challenge parameters.
func (r *RealIdentify) VerifyLogin(proofBytes []byte, publicCommitment string, challenge int) (bool, error) {
	proof := groth16.NewProof(ecc.BN254)
	_, err := proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return false, fmt.Errorf("증명서 형식 오류: %v", err)
	}

	var publicHashInt big.Int
	publicHashInt.SetString(publicCommitment, 10)

	assignment := circuits.UserCircuit{
		PublicHash:  publicHashInt,
		CurrentYear: 2025,
		LimitAge:    20,
		Challenge:   challenge,
	}

	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("공개 위트니스 생성 실패: %v", err)
	}

	err = groth16.Verify(proof, r.verifyingKey, publicWitness)

	if err != nil {
		return false, fmt.Errorf("수학적 검증 실패 (가짜 증명서): %v", err)
	}

	return true, nil
}

func (r *RealIdentify) VerifyAge(proof []byte) (bool, error) {
	return true, nil
}

// EncryptDeliveryInfo is a placeholder that demonstrates how encrypted delivery data might be produced.
func (r *RealIdentify) EncryptDeliveryInfo(address string) (string, error) {
	return "ENCRYPTED_" + address, nil
}
