// Package errors provides structured error codes for identify_sdk.
// Error code format: EXXXX where X is a digit.
// E1xxx: Authentication errors
// E2xxx: Key/Setup errors
// E3xxx: Cryptography errors
// E4xxx: Configuration errors
package errors

import (
	"fmt"
)

// Error represents a structured error with code and message.
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// New creates a new error with code and message.
func New(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap wraps an existing error with a code and message.
func Wrap(code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}

// Authentication errors (E1xxx)
var (
	ErrProofFormat      = New("E1001", "invalid proof format")
	ErrCommitmentParse  = New("E1002", "failed to parse commitment")
	ErrVerificationFail = New("E1003", "proof verification failed")
	ErrKeyNotFound      = New("E1004", "embedded key not found, run setup")
	ErrSaltParse        = New("E1005", "failed to parse salt")
	ErrBindingCompute   = New("E1006", "failed to compute binding")
	ErrWitnessCreate    = New("E1007", "failed to create witness")
	ErrProofGeneration  = New("E1008", "failed to generate proof")
	ErrCircuitCompile   = New("E1009", "failed to compile circuit")
	ErrMissingArguments = New("E1010", "missing required arguments")
	ErrChallengeExpired = New("E1011", "challenge expired")
	ErrChallengeInvalid = New("E1012", "challenge token invalid")
)

// Key/Setup errors (E2xxx)
var (
	ErrKeyParse    = New("E2001", "failed to parse key")
	ErrKeyWrite    = New("E2002", "failed to write key file")
	ErrKeyRead     = New("E2003", "failed to read key file")
	ErrKeyMismatch = New("E2004", "key fingerprint mismatch")
	ErrSetupFailed = New("E2005", "setup failed")
	ErrKeyRotation = New("E2006", "key rotation required")
)

// Cryptography errors (E3xxx)
var (
	ErrEncryptionFailed = New("E3001", "encryption failed")
	ErrDecryptionFailed = New("E3002", "decryption failed")
	ErrInvalidKeySize   = New("E3003", "invalid key size")
	ErrPEMDecode        = New("E3004", "PEM decode failed")
	ErrPublicKeyParse   = New("E3005", "failed to parse public key")
)

// Configuration errors (E4xxx)
var (
	ErrConfigNotFound  = New("E4001", "configuration not found")
	ErrPolicyMismatch  = New("E4002", "client/server policy mismatch")
	ErrInvalidConfig   = New("E4003", "invalid configuration")
	ErrTokenKeyMissing = New("E4004", "challenge token key not configured")
)
