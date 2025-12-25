package auth

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ghdehrl12345/identify_sdk/v2/common"
)

type authGolden struct {
	Proof       string `json:"proof"`
	Commitment  string `json:"commitment"`
	Salt        string `json:"salt"`
	Challenge   int    `json:"challenge"`
	BirthYear   int    `json:"birth_year"`
	TargetYear  int    `json:"target_year"`
	LimitAge    int    `json:"limit_age"`
	ParamsHash  string `json:"params_version"`
	VerifyingID string `json:"vk_id"`
}

func TestGoldenProofAuth(t *testing.T) {
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatalf("missing golden proof: %v", err)
	}

	var g authGolden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("golden parse failed: %v", err)
	}

	cfg := common.DefaultSharedConfig()
	if g.TargetYear != cfg.TargetYear || g.LimitAge != cfg.LimitAge {
		t.Fatalf("golden policy mismatch")
	}
	if g.VerifyingID != VerifyingKeyID() {
		t.Fatalf("vk id mismatch: %s != %s", g.VerifyingID, VerifyingKeyID())
	}
	if g.ParamsHash != common.ParamsVersion(cfg) {
		t.Fatalf("params version mismatch")
	}

	proofBytes, err := hex.DecodeString(g.Proof)
	if err != nil {
		t.Fatalf("proof hex decode failed: %v", err)
	}

	verifier, err := NewVerifierWithConfig(VerifierConfig{Config: cfg})
	if err != nil {
		t.Fatalf("verifier init failed: %v", err)
	}

	ok, err := verifier.VerifyLogin(proofBytes, g.Commitment, g.Salt, g.Challenge)
	if err != nil || !ok {
		t.Fatalf("golden verification failed: %v", err)
	}
}
