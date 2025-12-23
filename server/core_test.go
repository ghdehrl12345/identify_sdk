package server

import (
	"testing"

	"github.com/ghdehrl12345/identify_sdk/client"
	"github.com/ghdehrl12345/identify_sdk/common"
)

func TestCreateCommitmentProducesValues(t *testing.T) {
	ri := &RealIdentify{}
	commit, salt, err := ri.CreateCommitment("secret-123")
	if err != nil {
		t.Fatalf("CreateCommitment error: %v", err)
	}
	if commit == "" || salt == "" {
		t.Fatalf("commitment/salt is empty")
	}
}

func TestVerifyLoginEndToEnd(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfg})
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

	salt, _ := client.GenerateSalt()
	proof, commitment, _, err := prover.GenerateProof(secret, birth, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	ok, err := srv.VerifyLogin(proof, commitment, salt, challenge)
	if err != nil {
		t.Fatalf("VerifyLogin error: %v", err)
	}
	if !ok {
		t.Fatalf("expected proof verification to succeed")
	}
}

func TestVerifyLoginRejectsBadProof(t *testing.T) {
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: common.DefaultSharedConfig()})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	ok, err := srv.VerifyLogin([]byte("bad-proof"), "12345", "deadbeef", 1)
	if err == nil {
		t.Fatalf("expected error for malformed proof, got ok=%v", ok)
	}
}

func TestVerifyLoginPolicyMismatch(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	cfgMismatch := cfg
	cfgMismatch.LimitAge = 25
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfgMismatch})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	salt, _ := client.GenerateSalt()
	// Proof generated with limitAge=20, currentYear=2025
	proof, commitment, _, err := prover.GenerateProof("password123", 2005, cfg.TargetYear, cfg.LimitAge, 777, salt)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	// Verification with stricter policy should fail
	ok, err := srv.VerifyLogin(proof, commitment, salt, 777)
	if err == nil && ok {
		t.Fatalf("expected failure with policy mismatch, got ok=%v", ok)
	}
}

func TestVerifyLoginWithMismatchedCommitment(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfg})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	salt, _ := client.GenerateSalt()
	proof, _, _, err := prover.GenerateProof("password123", 2000, cfg.TargetYear, cfg.LimitAge, 999, salt)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	ok, err := srv.VerifyLogin(proof, "999999", salt, 999)
	if err == nil || ok {
		t.Fatalf("expected mismatch to fail, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyAgeRejectsUnderage(t *testing.T) {
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	salt, _ := client.GenerateSalt()
	_, _, _, err = prover.GenerateProof("password123", 2010, 2025, 20, 1001, salt)
	if err == nil {
		t.Fatalf("expected proof generation to fail for underage")
	}
}

func TestVerifyLoginChallengeBinding(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfg})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	salt, _ := client.GenerateSalt()
	proof, commitment, _, err := prover.GenerateProof("password123", 2000, cfg.TargetYear, cfg.LimitAge, 12345, salt)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	// Correct challenge should pass
	ok, err := srv.VerifyLogin(proof, commitment, salt, 12345)
	if err != nil || !ok {
		t.Fatalf("expected success, got ok=%v err=%v", ok, err)
	}

	// Wrong challenge should fail
	ok, err = srv.VerifyLogin(proof, commitment, salt, 54321)
	if err == nil && ok {
		t.Fatalf("expected failure with wrong challenge, got ok=%v", ok)
	}
}

func TestVerifyLoginRandomChallenges(t *testing.T) {
	cfg := common.DefaultSharedConfig()
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfg})
	if err != nil {
		t.Fatalf("init server: %v", err)
	}
	prover, err := client.NewUserProver()
	if err != nil {
		t.Fatalf("init prover: %v", err)
	}

	secret := "password123"
	birth := 2000
	salt, _ := client.GenerateSalt()
	for challenge := 1; challenge <= 5; challenge++ {
		proof, commitment, _, err := prover.GenerateProof(secret, birth, cfg.TargetYear, cfg.LimitAge, challenge, salt)
		if err != nil {
			t.Fatalf("GenerateProof challenge %d: %v", challenge, err)
		}
		ok, err := srv.VerifyLogin(proof, commitment, salt, challenge)
		if err != nil || !ok {
			t.Fatalf("VerifyLogin failed at challenge %d: ok=%v err=%v", challenge, ok, err)
		}
	}
}

func BenchmarkVerifyLogin(b *testing.B) {
	cfg := common.DefaultSharedConfig()
	srv, err := NewRealSDKWithConfig(RealIdentifyConfig{Config: cfg})
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

	salt, _ := client.GenerateSalt()

	proof, commitment, _, err := prover.GenerateProof(secret, birth, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		b.Fatalf("GenerateProof: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := srv.VerifyLogin(proof, commitment, salt, challenge); err != nil {
			b.Fatalf("VerifyLogin: %v", err)
		}
	}
}
