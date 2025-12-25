package age

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
	sdkerrors "github.com/ghdehrl12345/identify_sdk/v2/errors"
)

func TestAgeProofVerification(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewProverWithConfig(cfg)
	if err != nil {
		t.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		t.Fatalf("verifier init failed: %v", err)
	}

	proof, err := prover.GenerateAgeProof(2000, cfg.TargetYear, cfg.LimitAge)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}

	ok, err := verifier.VerifyAge(proof)
	if err != nil || !ok {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestAgeVerifyWithMeta(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewProverWithConfig(cfg)
	if err != nil {
		t.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		t.Fatalf("verifier init failed: %v", err)
	}

	proof, err := prover.GenerateAgeProof(2000, cfg.TargetYear, cfg.LimitAge)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}

	_, err = verifier.VerifyAgeWithMeta(proof, AgeVerifyingKeyID(), "bad-params")
	if err != sdkerrors.ErrPolicyMismatch {
		t.Fatalf("expected policy mismatch error, got %v", err)
	}
}
