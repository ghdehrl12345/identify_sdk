package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ghdehrl12345/identify_sdk/age"
	"github.com/ghdehrl12345/identify_sdk/auth"
	"github.com/ghdehrl12345/identify_sdk/common"
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

type ageGolden struct {
	Proof       string `json:"proof"`
	BirthYear   int    `json:"birth_year"`
	TargetYear  int    `json:"target_year"`
	LimitAge    int    `json:"limit_age"`
	ParamsHash  string `json:"params_version"`
	VerifyingID string `json:"vk_id"`
}

func main() {
	cfg := common.DefaultSharedConfig()

	authProver, err := auth.NewUserProverWithPolicy(auth.DefaultPolicy(), cfg)
	if err != nil {
		panic(err)
	}
	ageProver, err := age.NewProverWithConfig(cfg)
	if err != nil {
		panic(err)
	}

	secret := "golden-secret"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	challenge := 4242
	birthYear := 2000

	proof, commitment, _, err := authProver.GenerateProof(secret, birthYear, cfg.TargetYear, cfg.LimitAge, challenge, salt)
	if err != nil {
		panic(err)
	}
	authOut := authGolden{
		Proof:       hex.EncodeToString(proof),
		Commitment:  commitment,
		Salt:        salt,
		Challenge:   challenge,
		BirthYear:   birthYear,
		TargetYear:  cfg.TargetYear,
		LimitAge:    cfg.LimitAge,
		ParamsHash:  common.ParamsVersion(cfg),
		VerifyingID: auth.VerifyingKeyID(),
	}

	ageProof, err := ageProver.GenerateAgeProof(birthYear, cfg.TargetYear, cfg.LimitAge)
	if err != nil {
		panic(err)
	}
	ageOut := ageGolden{
		Proof:       hex.EncodeToString(ageProof),
		BirthYear:   birthYear,
		TargetYear:  cfg.TargetYear,
		LimitAge:    cfg.LimitAge,
		ParamsHash:  common.ParamsVersion(cfg),
		VerifyingID: age.AgeVerifyingKeyID(),
	}

	writeJSON("auth/testdata/golden.json", authOut)
	writeJSON("age/testdata/golden.json", ageOut)
	fmt.Println("golden proofs written")
}

func writeJSON(path string, v interface{}) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		panic(err)
	}
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}
