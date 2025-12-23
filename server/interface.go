package server

import "github.com/ghdehrl12345/identify_sdk/common"

// IdentifySDK defines the contract that both the real implementation and mocks must satisfy.
// The interface exposes login, age verification, and secure delivery helpers that do not require
// storing sensitive inputs on the server.
type IdentifySDK interface {
	// CreateCommitment derives a salted commitment from a user-secret for storage.
	CreateCommitment(secret string) (commitment string, salt string, err error)
	// VerifyLogin checks whether a Groth16 proof matches the stored commitment/salt and the server-issued challenge and policy inputs.
	VerifyLogin(proof []byte, publicCommitment string, salt string, challenge int) (bool, error)
	// VerifyAge validates a proof asserting adulthood using the AgeCircuit and configured policy.
	VerifyAge(proof []byte) (isAdult bool, err error)
	// EncryptDeliveryInfo transforms the plaintext address using the courier's public key.
	EncryptDeliveryInfo(address string) (encryptedAddr string, err error)
	// GetConfig exposes the shared configuration (policy/KDF) to clients.
	GetConfig() common.SharedConfig
}
