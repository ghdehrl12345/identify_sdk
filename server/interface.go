package server

type IdentifySDK interface {
	RegisterUser(secret string) (commitment string, err error)

	VerifyLogin(proof []byte, publicCommitment string) (bool, error)

	VerifyAge(proof []byte) (isAdult bool, err error)

	ProcessSecureDelivery(encryptedAddress string) (deliveryToken string, err error)
}
