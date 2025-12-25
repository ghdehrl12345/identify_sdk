package age

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
)

func BenchmarkVerifyAge(b *testing.B) {
	cfg := common.DefaultSharedConfig()
	prover, err := NewProverWithConfig(cfg)
	if err != nil {
		b.Fatalf("prover init failed: %v", err)
	}
	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		b.Fatalf("verifier init failed: %v", err)
	}

	proof, err := prover.GenerateAgeProof(2000, cfg.TargetYear, cfg.LimitAge)
	if err != nil {
		b.Fatalf("proof generation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.VerifyAge(proof); err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}
