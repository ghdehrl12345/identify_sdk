package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghdehrl12345/identify_sdk/core/circuits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	fmt.Println("🔨 [Setup] ZKP 회로 컴파일 및 키 생성을 시작합니다...")

	// 1. 회로 인스턴스 생성
	var myCircuit circuits.UserCircuit

	// 2. 회로 컴파일 (R1CS 제약 시스템으로 변환)
	// BN254 곡선을 사용합니다 (이더리움 표준)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		panic("회로 컴파일 실패: " + err.Error())
	}
	fmt.Printf(">> 회로 컴파일 완료 (제약 조건 수: %d)\n", ccs.GetNbConstraints())

	// 3. Setup (증명키 pk, 검증키 vk 생성)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic("Setup 실패: " + err.Error())
	}
	fmt.Println(">> 암호화 키 생성 완료")

	writeKeyFile := func(path string, writeFn func(io.Writer) (int64, error)) error {
		dir := filepath.Dir(path)
		if dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
		}

		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = writeFn(f)
		return err
	}

	pkTargets := []string{"build/user.pk", "client/user.pk"}
	for _, path := range pkTargets {
		if err := writeKeyFile(path, pk.WriteTo); err != nil {
			panic(fmt.Sprintf("증명키 저장 실패 (%s): %v", path, err))
		}
	}

	vkTargets := []string{"build/user.vk", "server/user.vk"}
	for _, path := range vkTargets {
		if err := writeKeyFile(path, vk.WriteTo); err != nil {
			panic(fmt.Sprintf("검증키 저장 실패 (%s): %v", path, err))
		}
	}

	fmt.Println("✅ [성공] build/, client/, server/ 경로에 키 파일이 업데이트되었습니다.")
}
