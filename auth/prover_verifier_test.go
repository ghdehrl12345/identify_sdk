package auth

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
	sdkerrors "github.com/ghdehrl12345/identify_sdk/v2/errors"
)

func TestAuthProofVerification(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewUserProverWithPolicy(DefaultPolicy(), cfg)
	if err != nil {
		t.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		t.Fatalf("verifier init failed: %v", err)
	}

	secret := "test-secret"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	challenge := 4242

	proof, commitment, _, err := prover.GenerateProof(secret, 2000, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}

	ok, err := verifier.VerifyLogin(proof, commitment, salt, challenge)
	if err != nil || !ok {
		t.Fatalf("verification failed: %v", err)
	}

	if _, err := verifier.VerifyLogin(proof, commitment, salt, challenge+1); err == nil {
		t.Fatalf("expected verification failure for mismatched challenge")
	}
}

func TestAuthVerifyWithMeta(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewUserProverWithPolicy(DefaultPolicy(), cfg)
	if err != nil {
		t.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		t.Fatalf("verifier init failed: %v", err)
	}

	secret := "test-secret"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	challenge := 101

	proof, commitment, _, err := prover.GenerateProof(secret, 2000, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}

	_, err = verifier.VerifyLoginWithMeta(proof, commitment, salt, challenge, "bad-vk", common.ParamsVersion(cfg))
	if err != sdkerrors.ErrKeyMismatch {
		t.Fatalf("expected key mismatch error, got %v", err)
	}
}
