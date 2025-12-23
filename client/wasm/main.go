//go:build js && wasm

package main

import (
	"encoding/hex"
	"fmt"
	"syscall/js"

	"github.com/ghdehrl12345/identify_sdk/client"
	"github.com/ghdehrl12345/identify_sdk/common"
)

var prover *client.UserProver

// 1. 엔진 초기화 함수 (JS에서 호출)
func InitProver(this js.Value, p []js.Value) interface{} {
	fmt.Println("WASM: InitProver 호출됨")

	if len(p) < 1 {
		return "Error: expected args (userPkBytes[, configObject])"
	}

	pkJS := p[0]
	pkBytes := make([]byte, pkJS.Get("length").Int())
	js.CopyBytesToGo(pkBytes, pkJS)

	cfg := common.DefaultSharedConfig()
	if len(p) >= 2 && p[1].Type() == js.TypeObject {
		cfg = parseSharedConfig(p[1], cfg)
	}

	var err error
	prover, err = client.NewUserProverFromPKWithPolicy(pkBytes, client.DefaultPolicy(), cfg)

	if err != nil {
		fmt.Println("❌ [WASM] 엔진 초기화 실패:", err)
		return false
	}

	fmt.Println("✅ [WASM] 증명 엔진 로드 완료!")
	return true
}

// 2. 증명 생성 함수 (JS에서 호출)
func GenerateProofWrapper(this js.Value, p []js.Value) interface{} {
	if prover == nil {
		return "Error: Prover not initialized"
	}

	if len(p) < 5 {
		return "Error: expected args (secret, birthYear, config, challenge, saltHex)"
	}

	secret := p[0].String()
	birth := p[1].Int()
	cfg := parseSharedConfig(p[2], common.DefaultSharedConfig())
	challenge := p[3].Int()
	saltHex := p[4].String()

	// Go 함수 호출
	proofBytes, pubHash, binding, err := prover.GenerateProof(secret, birth, cfg.TargetYear, cfg.LimitAge, challenge, saltHex)
	if err != nil {
		return "Error: " + err.Error()
	}

	proofHex := hex.EncodeToString(proofBytes)

	result := map[string]interface{}{
		"proof":      proofHex,
		"hash":       pubHash,
		"binding":    binding,
		"salt":       saltHex,
		"pkId":       client.ProvingKeyID(),
		"policyYear": cfg.TargetYear,
		"limitAge":   cfg.LimitAge,
	}
	return js.ValueOf(result)
}

// GenerateAgeProofWrapper generates an age-only proof (no password/commitment).
// Args: birthYear, currentYear, limitAge
func GenerateAgeProofWrapper(this js.Value, p []js.Value) interface{} {
	if prover == nil {
		return "Error: Prover not initialized"
	}
	if len(p) < 2 {
		return "Error: expected args (birthYear, config)"
	}
	birth := p[0].Int()
	cfg := parseSharedConfig(p[1], common.DefaultSharedConfig())

	proofBytes, err := prover.GenerateAgeProof(birth, cfg.TargetYear, cfg.LimitAge)
	if err != nil {
		return "Error: " + err.Error()
	}
	proofHex := hex.EncodeToString(proofBytes)
	return js.ValueOf(map[string]interface{}{
		"proof":      proofHex,
		"pkId":       client.ProvingKeyID(),
		"policyYear": cfg.TargetYear,
		"limitAge":   cfg.LimitAge,
	})
}

func parseSharedConfig(jsVal js.Value, base common.SharedConfig) common.SharedConfig {
	if jsVal.Type() != js.TypeObject {
		return base
	}
	if v := jsVal.Get("targetYear"); v.Type() == js.TypeNumber {
		base.TargetYear = v.Int()
	} else if v := jsVal.Get("currentYear"); v.Type() == js.TypeNumber {
		base.TargetYear = v.Int()
	}
	if v := jsVal.Get("limitAge"); v.Type() == js.TypeNumber {
		base.LimitAge = v.Int()
	}
	if v := jsVal.Get("argonMemory"); v.Type() == js.TypeNumber {
		base.ArgonMemory = uint32(v.Int())
	}
	if v := jsVal.Get("argonIterations"); v.Type() == js.TypeNumber {
		base.ArgonIterations = uint32(v.Int())
	}
	return base
}

func main() {
	c := make(chan struct{}, 0)
	fmt.Println("👋 Hello from Go WebAssembly!")
	js.Global().Set("InitIdentify", js.FuncOf(InitProver))
	js.Global().Set("GenerateIdentifyProof", js.FuncOf(GenerateProofWrapper))
	js.Global().Set("GenerateAgeProof", js.FuncOf(GenerateAgeProofWrapper))
	<-c
}
