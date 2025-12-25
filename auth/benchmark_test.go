package auth

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/common"
)

func BenchmarkVerifyLogin(b *testing.B) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewUserProverWithPolicy(DefaultPolicy(), cfg)
	if err != nil {
		b.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		b.Fatalf("verifier init failed: %v", err)
	}

	secret := "bench-secret"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	challenge := 4242

	proof, commitment, _, err := prover.GenerateProof(secret, 2000, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		b.Fatalf("proof generation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.VerifyLogin(proof, commitment, salt, challenge); err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewUserProverWithPolicy(DefaultPolicy(), cfg)
	if err != nil {
		b.Fatalf("prover init failed: %v", err)
	}

	secret := "bench-secret"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	challenge := 4242

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := prover.GenerateProof(secret, 2000, cfg.TargetYear, cfg.LimitAge, challenge, salt); err != nil {
			b.Fatalf("proof generation failed: %v", err)
		}
	}
}
