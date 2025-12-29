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

// MinRSAKeyBits is the minimum required RSA key size in bits.
// NIST recommends at least 2048 bits; we require 4096 for enhanced security.
const MinRSAKeyBits = 4096

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
	// Validate minimum key size for security
	if pub.N.BitLen() < MinRSAKeyBits {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d required)", pub.N.BitLen(), MinRSAKeyBits)
	}
	return pub, nil
}

// DeliveryDecryptor handles RSA-OAEP decryption for delivery information.
type DeliveryDecryptor struct {
	privateKey *rsa.PrivateKey
}

// NewDeliveryDecryptor creates a decryptor from PEM data.
func NewDeliveryDecryptor(pemData []byte) (*DeliveryDecryptor, error) {
	priv, err := parseRSAPrivateKey(pemData)
	if err != nil {
		return nil, err
	}
	return &DeliveryDecryptor{privateKey: priv}, nil
}

// NewDeliveryDecryptorFromPath loads the private key from a file.
func NewDeliveryDecryptorFromPath(path string) (*DeliveryDecryptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return NewDeliveryDecryptor(data)
}

// NewDeliveryDecryptorFromEnv loads the private key from environment variables.
func NewDeliveryDecryptorFromEnv() (*DeliveryDecryptor, error) {
	if pemData := os.Getenv("DELIVERY_PRIVATE_KEY"); pemData != "" {
		return NewDeliveryDecryptor([]byte(pemData))
	}
	if path := os.Getenv("DELIVERY_PRIVATE_KEY_PATH"); path != "" {
		return NewDeliveryDecryptorFromPath(path)
	}
	return nil, fmt.Errorf("no delivery private key configured")
}

// Decrypt decrypts the ciphertext using RSA-OAEP with SHA-256.
func (d *DeliveryDecryptor) Decrypt(ciphertext string) (string, error) {
	if d.privateKey == nil {
		return "", fmt.Errorf("private key not configured")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.privateKey, cipherBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}

	// Try PKCS#8 first
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			if rsaKey.N.BitLen() < MinRSAKeyBits {
				return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d required)", rsaKey.N.BitLen(), MinRSAKeyBits)
			}
			return rsaKey, nil
		}
		return nil, fmt.Errorf("unsupported key type (RSA required)")
	}

	// Try PKCS#1
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key parse failed: %w", err)
	}
	if key.N.BitLen() < MinRSAKeyBits {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d required)", key.N.BitLen(), MinRSAKeyBits)
	}
	return key, nil
}
