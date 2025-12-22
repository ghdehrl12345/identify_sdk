//go:build js && wasm

package main

import (
	"encoding/hex"
	"fmt"
	"syscall/js"

	"github.com/ghdehrl12345/identify_sdk/client"
)

var prover *client.UserProver

// 1. 엔진 초기화 함수 (JS에서 호출)
func InitProver(this js.Value, p []js.Value) interface{} {
	fmt.Println("WASM: InitProver 호출됨")

	// JS에서 넘겨준 PK 데이터 읽기
	pkJS := p[0]
	pkBytes := make([]byte, pkJS.Get("length").Int())
	js.CopyBytesToGo(pkBytes, pkJS)

	var err error
	prover, err = client.NewUserProverFromPK(pkBytes)

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

	secret := p[0].String()
	birth := p[1].Int()
	challenge := p[2].Int()

	// Go 함수 호출
	proofBytes, pubHash, err := prover.GenerateProof(secret, birth, 2025, 20, challenge)
	if err != nil {
		return "Error: " + err.Error()
	}

	proofHex := hex.EncodeToString(proofBytes)

	result := map[string]interface{}{
		"proof": proofHex,
		"hash":  pubHash,
	}
	return js.ValueOf(result)
}

func main() {
	c := make(chan struct{}, 0)
	fmt.Println("👋 Hello from Go WebAssembly!")
	js.Global().Set("InitIdentify", js.FuncOf(InitProver))
	js.Global().Set("GenerateIdentifyProof", js.FuncOf(GenerateProofWrapper))
	<-c
}
