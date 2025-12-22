package server

import (
	"errors"
	"fmt"
)

type MockIdentify struct{}

func NewMockSDK() IdentifySDK {
	return &MockIdentify{}
}

func (m *MockIdentify) CreateCommitment(secret string) (string, error) {
	return "MOCK_HASH_" + secret, nil
}

func (m *MockIdentify) VerifyLogin(proof []byte, publicCommitment string, _ int) (bool, error) {
	fmt.Println(">> [Mock] 로그인 증명서를 검증하는 중...")
	return true, nil
}

func (m *MockIdentify) VerifyAge(proof []byte) (bool, error) {
	fmt.Println(">> [Mock] 성인 인증 증명서를 검증하는 중...")
	if len(proof) == 0 {
		return false, errors.New("증명서가 비어있습니다")
	}
	return true, nil
}

func (m *MockIdentify) EncryptDeliveryInfo(address string) (string, error) {
	return "ENCRYPTED_" + address, nil
}
