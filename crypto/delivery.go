package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// DeliveryEncryptor handles RSA-OAEP encryption for delivery information.
type DeliveryEncryptor struct {
	publicKey *rsa.PublicKey
}

// NewDeliveryEncryptor creates an encryptor from PEM data or file path.
func NewDeliveryEncryptor(pemData []byte) (*DeliveryEncryptor, error) {
	pub, err := parseRSAPublicKey(pemData)
	if err != nil {
		return nil, err
	}
	return &DeliveryEncryptor{publicKey: pub}, nil
}

// NewDeliveryEncryptorFromPath loads the public key from a file.
func NewDeliveryEncryptorFromPath(path string) (*DeliveryEncryptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	return NewDeliveryEncryptor(data)
}

// NewDeliveryEncryptorFromEnv loads the public key from environment variables.
func NewDeliveryEncryptorFromEnv() (*DeliveryEncryptor, error) {
	if pemData := os.Getenv("DELIVERY_PUBLIC_KEY"); pemData != "" {
		return NewDeliveryEncryptor([]byte(pemData))
	}
	if path := os.Getenv("DELIVERY_PUBLIC_KEY_PATH"); path != "" {
		return NewDeliveryEncryptorFromPath(path)
	}
	return nil, fmt.Errorf("no delivery public key configured")
}

// Encrypt encrypts the address using RSA-OAEP with SHA-256.
func (d *DeliveryEncryptor) Encrypt(address string) (string, error) {
	if d.publicKey == nil {
		return "", fmt.Errorf("public key not configured")
	}
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, d.publicKey, []byte(address), nil)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key parse failed: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type (RSA required)")
	}
	return pub, nil
}
