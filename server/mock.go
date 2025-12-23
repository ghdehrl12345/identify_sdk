package server

import (
	"errors"
	"fmt"

	"github.com/ghdehrl12345/identify_sdk/common"
)

type MockIdentify struct{}

func NewMockSDK() IdentifySDK {
	return &MockIdentify{}
}

func (m *MockIdentify) CreateCommitment(secret string) (string, string, error) {
	return "MOCK_HASH_" + secret, "deadbeef", nil
}

func (m *MockIdentify) VerifyLogin(proof []byte, publicCommitment string, _ string, _ int) (bool, error) {
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

func (m *MockIdentify) GetConfig() common.SharedConfig {
	return common.DefaultSharedConfig()
}
