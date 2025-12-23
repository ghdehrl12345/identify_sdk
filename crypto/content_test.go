package crypto

import (
	"bytes"
	"testing"
)

func TestContentEncryptDecrypt(t *testing.T) {
	encryptor := NewContentEncryptor()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("Hello, this is a secret message!")

	ciphertext, err := encryptor.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("Ciphertext should not equal plaintext")
	}

	decrypted, err := encryptor.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted text does not match: got %s, want %s", decrypted, plaintext)
	}
}

func TestContentEncryptInvalidKeySize(t *testing.T) {
	encryptor := NewContentEncryptor()

	shortKey := make([]byte, 16) // Should be 32 bytes
	_, err := encryptor.Encrypt([]byte("test"), shortKey)
	if err == nil {
		t.Fatal("Expected error for invalid key size")
	}
}

func TestContentDecryptTamperedData(t *testing.T) {
	encryptor := NewContentEncryptor()

	key, _ := GenerateKey()
	plaintext := []byte("Secret data")

	ciphertext, _ := encryptor.Encrypt(plaintext, key)

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err := encryptor.Decrypt(ciphertext, key)
	if err == nil {
		t.Fatal("Expected error for tampered ciphertext")
	}
}
