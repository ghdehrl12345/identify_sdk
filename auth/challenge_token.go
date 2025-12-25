package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ghdehrl12345/identify_sdk/common"
	sdkerrors "github.com/ghdehrl12345/identify_sdk/errors"
)

const ChallengeTokenVersion = "ct-v1"

// ChallengeTokenClaims represents the stateless challenge payload.
type ChallengeTokenClaims struct {
	UserID        string `json:"user_id"`
	Challenge     int    `json:"challenge"`
	ExpiresAt     int64  `json:"exp"`
	Nonce         string `json:"nonce"`
	VKID          string `json:"vk_id"`
	ParamsVersion string `json:"params_version"`
	Version       string `json:"v"`
}

// IssueChallengeToken creates a signed, stateless challenge token using HMAC-SHA256.
func IssueChallengeToken(secret []byte, claims ChallengeTokenClaims) (string, error) {
	if len(secret) == 0 {
		return "", sdkerrors.ErrTokenKeyMissing
	}
	if claims.ExpiresAt == 0 || claims.Challenge == 0 || claims.UserID == "" {
		return "", sdkerrors.ErrMissingArguments
	}
	if claims.Nonce == "" {
		nonce, err := generateNonce()
		if err != nil {
			return "", sdkerrors.Wrap(sdkerrors.ErrChallengeInvalid.Code, "nonce generation failed", err)
		}
		claims.Nonce = nonce
	}
	if claims.Version == "" {
		claims.Version = ChallengeTokenVersion
	}
	if claims.ParamsVersion == "" {
		claims.ParamsVersion = common.ParamsVersion(common.DefaultSharedConfig())
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", sdkerrors.Wrap(sdkerrors.ErrChallengeInvalid.Code, "payload encode failed", err)
	}
	sig := signHMAC(secret, payload)

	return encodeSegment(payload) + "." + encodeSegment(sig), nil
}

// ParseChallengeToken validates signature and decodes a stateless challenge token.
func ParseChallengeToken(token string, secret []byte) (ChallengeTokenClaims, error) {
	if len(secret) == 0 {
		return ChallengeTokenClaims{}, sdkerrors.ErrTokenKeyMissing
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return ChallengeTokenClaims{}, sdkerrors.ErrChallengeInvalid
	}
	payload, err := decodeSegment(parts[0])
	if err != nil {
		return ChallengeTokenClaims{}, sdkerrors.Wrap(sdkerrors.ErrChallengeInvalid.Code, "payload decode failed", err)
	}
	sig, err := decodeSegment(parts[1])
	if err != nil {
		return ChallengeTokenClaims{}, sdkerrors.Wrap(sdkerrors.ErrChallengeInvalid.Code, "signature decode failed", err)
	}
	expected := signHMAC(secret, payload)
	if !hmac.Equal(sig, expected) {
		return ChallengeTokenClaims{}, sdkerrors.ErrChallengeInvalid
	}

	var claims ChallengeTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ChallengeTokenClaims{}, sdkerrors.Wrap(sdkerrors.ErrChallengeInvalid.Code, "payload parse failed", err)
	}
	return claims, nil
}

// ValidateChallengeToken verifies signature, expiry, and policy key/version matching.
func ValidateChallengeToken(token string, secret []byte, now time.Time, expectedVKID, expectedParams string) (ChallengeTokenClaims, error) {
	claims, err := ParseChallengeToken(token, secret)
	if err != nil {
		return ChallengeTokenClaims{}, err
	}
	if claims.ExpiresAt <= now.Unix() {
		return ChallengeTokenClaims{}, sdkerrors.ErrChallengeExpired
	}
	if expectedVKID != "" && claims.VKID != expectedVKID {
		return ChallengeTokenClaims{}, sdkerrors.ErrChallengeInvalid
	}
	if expectedParams != "" && claims.ParamsVersion != expectedParams {
		return ChallengeTokenClaims{}, sdkerrors.ErrPolicyMismatch
	}
	if claims.Version != "" && claims.Version != ChallengeTokenVersion {
		return ChallengeTokenClaims{}, sdkerrors.ErrChallengeInvalid
	}
	return claims, nil
}

func signHMAC(secret []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func generateNonce() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("nonce rand failed: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
