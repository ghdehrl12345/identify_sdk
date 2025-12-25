package auth

import "encoding/base64"

// ProvingKeyBytes returns a copy of the embedded proving key bytes.
func ProvingKeyBytes() []byte {
	out := make([]byte, len(provingKeyData))
	copy(out, provingKeyData)
	return out
}

// ProvingKeyBase64 returns the embedded proving key as a base64 string.
func ProvingKeyBase64() string {
	return base64.StdEncoding.EncodeToString(provingKeyData)
}
