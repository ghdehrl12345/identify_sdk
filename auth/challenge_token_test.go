package auth

import (
	"testing"
	"time"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
	sdkerrors "github.com/ghdehrl12345/identify_sdk/v2/errors"
)

func TestChallengeTokenRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	cfg := common.DefaultSharedConfig()
	claims := ChallengeTokenClaims{
		UserID:        "user-123",
		Challenge:     4242,
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		VKID:          "vk-abc",
		ParamsVersion: common.ParamsVersion(cfg),
	}

	token, err := IssueChallengeToken(secret, claims)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	got, err := ValidateChallengeToken(token, secret, time.Now(), claims.VKID, claims.ParamsVersion)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if got.UserID != claims.UserID || got.Challenge != claims.Challenge {
		t.Fatalf("claims mismatch: got %+v want %+v", got, claims)
	}
}

func TestChallengeTokenKeySet(t *testing.T) {
	keys := map[string][]byte{
		"k1": []byte("secret-1"),
		"k2": []byte("secret-2"),
	}
	claims := ChallengeTokenClaims{
		UserID:    "user-123",
		Challenge: 4242,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	token, err := IssueChallengeTokenWithKey(keys["k1"], "k1", claims)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	got, err := ValidateChallengeTokenWithKeySet(token, keys, time.Now(), "", "")
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if got.KeyID != "k1" {
		t.Fatalf("expected key id k1, got %s", got.KeyID)
	}
}

func TestChallengeTokenExpired(t *testing.T) {
	secret := []byte("test-secret")
	claims := ChallengeTokenClaims{
		UserID:    "user-123",
		Challenge: 1,
		ExpiresAt: time.Now().Add(-1 * time.Minute).Unix(),
	}
	token, err := IssueChallengeToken(secret, claims)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	_, err = ValidateChallengeToken(token, secret, time.Now(), "", "")
	if err == nil {
		t.Fatal("expected expiry error")
	}
	if err != sdkerrors.ErrChallengeExpired {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChallengeTokenInvalidSignature(t *testing.T) {
	secret := []byte("test-secret")
	claims := ChallengeTokenClaims{
		UserID:    "user-123",
		Challenge: 1,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	token, err := IssueChallengeToken(secret, claims)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	_, err = ValidateChallengeToken(token, []byte("wrong"), time.Now(), "", "")
	if err == nil {
		t.Fatal("expected invalid signature error")
	}
	if err != sdkerrors.ErrChallengeInvalid {
		t.Fatalf("unexpected error: %v", err)
	}
}
