package server

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/client"
)

func TestCreateCommitmentDeterministic(t *testing.T) {
	ri := &RealIdentify{}
	first, err := ri.CreateCommitment("secret-123")
	if err != nil {
		t.Fatalf("CreateCommitment error: %v", err)
	}
	second, err := ri.CreateCommitment("secret-123")
	if err != nil {
		t.Fatalf("CreateCommitment error: %v", err)
	}
	if first != second {
		t.Fatalf("commitment not deterministic: %s vs %s", first, second)
	}
	if first == "" {
		t.Fatalf("commitment is empty")
	}
}

func TestVerifyLoginEndToEnd(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	secret := "password123"
	birth := 2000
	challenge := 4242

	proof, commitment, err := prover.GenerateProof(secret, birth, 2025, 20, challenge)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	ok, err := srv.VerifyLogin(proof, commitment, challenge)
	if err != nil {
		t.Fatalf("VerifyLogin error: %v", err)
	}
	if !ok {
		t.Fatalf("expected proof verification to succeed")
	}
}

func TestVerifyLoginRejectsBadProof(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	ok, err := srv.VerifyLogin([]byte("bad-proof"), "12345", 1)
	if err == nil {
		t.Fatalf("expected error for malformed proof, got ok=%v", ok)
	}
}

func TestVerifyLoginWithMismatchedCommitment(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	proof, _, err := prover.GenerateProof("password123", 2000, 2025, 20, 999)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	ok, err := srv.VerifyLogin(proof, "999999", 999)
	if err == nil || ok {
		t.Fatalf("expected mismatch to fail, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyLoginChallengeBinding(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	proof, commitment, err := prover.GenerateProof("password123", 2000, 2025, 20, 12345)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	// Correct challenge should pass
	ok, err := srv.VerifyLogin(proof, commitment, 12345)
	if err != nil || !ok {
		t.Fatalf("expected success, got ok=%v err=%v", ok, err)
	}

	// Wrong challenge should fail
	ok, err = srv.VerifyLogin(proof, commitment, 54321)
	if err == nil && ok {
		t.Fatalf("expected failure with wrong challenge, got ok=%v", ok)
	}
}

func TestVerifyLoginRandomChallenges(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	secret := "password123"
	birth := 2000
	for challenge := 1; challenge <= 5; challenge++ {
		proof, commitment, err := prover.GenerateProof(secret, birth, 2025, 20, challenge)
		if err != nil {
			t.Fatalf("GenerateProof challenge %d: %v", challenge, err)
		}
		ok, err := srv.VerifyLogin(proof, commitment, challenge)
		if err != nil || !ok {
			t.Fatalf("VerifyLogin failed at challenge %d: ok=%v err=%v", challenge, ok, err)
		}
	}
}

func BenchmarkVerifyLogin(b *testing.B) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{CurrentYear: 2025, LimitAge: 20})
	if err != nil {
		b.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		b.Fatalf("init prover: %v", err)
	}

	secret := "password123"
	birth := 2000
	challenge := 4242

	proof, commitment, err := prover.GenerateProof(secret, birth, 2025, 20, challenge)
	if err != nil {
		b.Fatalf("GenerateProof: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := srv.VerifyLogin(proof, commitment, challenge); err != nil {
			b.Fatalf("VerifyLogin: %v", err)
		}
	}
}
