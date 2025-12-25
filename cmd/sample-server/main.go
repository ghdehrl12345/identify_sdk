package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ghdehrl12345/identify_sdk/age"
	"github.com/ghdehrl12345/identify_sdk/auth"
	"github.com/ghdehrl12345/identify_sdk/common"
)

type policyResponse struct {
	Config struct {
		TargetYear      int    `json:"target_year"`
		LimitAge        int    `json:"limit_age"`
		ArgonMemory     uint32 `json:"argon_memory"`
		ArgonIterations uint32 `json:"argon_iterations"`
	} `json:"config"`
	ParamsVersion string `json:"params_version"`
	VKID          string `json:"vk_id"`
}

type provingKeyResponse struct {
	KeyType      string `json:"key_type"`
	ProvingKey   string `json:"proving_key"` // base64
	PKID         string `json:"pk_id"`
	ProofVersion string `json:"proof_version"`
}

type challengeRequest struct {
	UserID string `json:"user_id"`
	Salt   string `json:"salt"`
}

type challengeResponse struct {
	ChallengeToken string `json:"challenge_token"`
	Salt           string `json:"salt"`
	VKID           string `json:"vk_id"`
	ParamsVersion  string `json:"params_version"`
	KID            string `json:"kid,omitempty"`
	ExpiresIn      int    `json:"expires_in"`
}

type verifyRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Proof          string `json:"proof"`
	Commitment     string `json:"commitment"`
	Salt           string `json:"salt"`
	VKID           string `json:"vk_id"`
	ParamsVersion  string `json:"params_version"`
}

type verifyResponse struct {
	OK      bool   `json:"ok"`
	ErrCode string `json:"err_code,omitempty"`
	ErrMsg  string `json:"err_msg,omitempty"`
}

func main() {
	cfg := common.DefaultSharedConfig()
	tokenKey := []byte(os.Getenv("CHALLENGE_TOKEN_KEY"))
	kid := os.Getenv("CHALLENGE_TOKEN_KID")

	verifier, err := auth.NewVerifierWithConfig(auth.VerifierConfig{
		Config:   cfg,
		TokenKey: tokenKey,
	})
	if err != nil {
		log.Fatalf("verifier init failed: %v", err)
	}

	http.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		bundle := verifier.PolicyBundle()
		var resp policyResponse
		resp.Config.TargetYear = bundle.Config.TargetYear
		resp.Config.LimitAge = bundle.Config.LimitAge
		resp.Config.ArgonMemory = bundle.Config.ArgonMemory
		resp.Config.ArgonIterations = bundle.Config.ArgonIterations
		resp.ParamsVersion = bundle.ParamsVersion
		resp.VKID = bundle.VKID
		writeJSON(w, resp)
	})

	http.HandleFunc("/proving-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		keyType := r.URL.Query().Get("type")
		if keyType == "age" {
			writeJSON(w, provingKeyResponse{
				KeyType:      "age",
				ProvingKey:   age.ProvingKeyBase64(),
				PKID:         age.AgeProvingKeyID(),
				ProofVersion: age.ProofVersion,
			})
			return
		}
		writeJSON(w, provingKeyResponse{
			KeyType:      "auth",
			ProvingKey:   auth.ProvingKeyBase64(),
			PKID:         auth.ProvingKeyID(),
			ProofVersion: auth.ProofVersion,
		})
	})

	http.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req challengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.UserID == "" || req.Salt == "" {
			http.Error(w, "missing user_id or salt", http.StatusBadRequest)
			return
		}

		challenge, err := cryptoRandInt(1_000_000)
		if err != nil {
			http.Error(w, "failed to generate challenge", http.StatusInternalServerError)
			return
		}
		claims := auth.ChallengeTokenClaims{
			UserID:        req.UserID,
			Challenge:     challenge,
			ExpiresAt:     time.Now().Add(2 * time.Minute).Unix(),
			VKID:          auth.VerifyingKeyID(),
			ParamsVersion: common.ParamsVersion(cfg),
			KeyID:         kid,
		}
		token, err := auth.IssueChallengeTokenWithKey(tokenKey, kid, claims)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		resp := challengeResponse{
			ChallengeToken: token,
			Salt:           req.Salt,
			VKID:           claims.VKID,
			ParamsVersion:  claims.ParamsVersion,
			KID:            kid,
			ExpiresIn:      120,
		}
		writeJSON(w, resp)
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		proofBytes, err := hex.DecodeString(req.Proof)
		if err != nil {
			writeJSON(w, verifyResponse{OK: false, ErrCode: "E1001", ErrMsg: "invalid proof format"})
			return
		}

		bundle := verifier.PolicyBundle()
		if req.VKID != "" && req.VKID != bundle.VKID {
			writeJSON(w, verifyResponse{OK: false, ErrCode: "E2004", ErrMsg: "vk_id mismatch"})
			return
		}
		if req.ParamsVersion != "" && req.ParamsVersion != bundle.ParamsVersion {
			writeJSON(w, verifyResponse{OK: false, ErrCode: "E4002", ErrMsg: "params_version mismatch"})
			return
		}

		ok, err := verifier.VerifyLoginWithToken(proofBytes, req.Commitment, req.Salt, req.ChallengeToken)
		if err != nil {
			writeJSON(w, verifyResponse{OK: false, ErrCode: "E1003", ErrMsg: err.Error()})
			return
		}
		writeJSON(w, verifyResponse{OK: ok})
	})

	addr := ":8081"
	log.Printf("sample server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func cryptoRandInt(max int64) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 1, nil
}
