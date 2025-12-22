package server

// IdentifySDK defines the contract that both the real implementation and mocks must satisfy.
// The interface exposes login, age verification, and secure delivery helpers that do not require
// storing sensitive inputs on the server.
type IdentifySDK interface {
	// CreateCommitment derives a MiMC commitment from a user-secret that can be persisted instead of the raw value.
	CreateCommitment(secret string) (commitment string, err error)
	// VerifyLogin checks whether a Groth16 proof matches the stored commitment and the server-issued challenge.
	VerifyLogin(proof []byte, publicCommitment string, challenge int) (bool, error)
	// VerifyAge validates a proof asserting adulthood without revealing the actual birth year.
	VerifyAge(proof []byte) (isAdult bool, err error)
	// EncryptDeliveryInfo transforms the plaintext address using the courier's public key.
	EncryptDeliveryInfo(address string) (encryptedAddr string, err error)
}
