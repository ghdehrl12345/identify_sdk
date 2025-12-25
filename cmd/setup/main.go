package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghdehrl12345/identify_sdk/v2/age"
	"github.com/ghdehrl12345/identify_sdk/v2/auth"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/blake2b"
)

func main() {
	fmt.Println("🔨 [Setup] ZKP 회로 컴파일 및 키 생성을 시작합니다...")

	// 1. 회로 인스턴스 생성
	var myCircuit auth.UserCircuit
	var ageCircuit age.AgeCircuit

	// 2. 회로 컴파일 (R1CS 제약 시스템으로 변환)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		panic("회로 컴파일 실패: " + err.Error())
	}
	fmt.Printf(">> 회로 컴파일 완료 (제약 조건 수: %d)\n", ccs.GetNbConstraints())

	ageCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ageCircuit)
	if err != nil {
		panic("Age 회로 컴파일 실패: " + err.Error())
	}
	fmt.Printf(">> Age 회로 컴파일 완료 (제약 조건 수: %d)\n", ageCCS.GetNbConstraints())

	// 3. Setup (증명키 pk, 검증키 vk 생성)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic("Setup 실패: " + err.Error())
	}
	agePK, ageVK, err := groth16.Setup(ageCCS)
	if err != nil {
		panic("Age Setup 실패: " + err.Error())
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

	// User circuit keys - auth 모듈에 저장
	pkTargets := []string{"auth/user.pk"}
	for _, path := range pkTargets {
		if err := writeKeyFile(path, pk.WriteTo); err != nil {
			panic(fmt.Sprintf("증명키 저장 실패 (%s): %v", path, err))
		}
	}

	vkTargets := []string{"auth/user.vk"}
	for _, path := range vkTargets {
		if err := writeKeyFile(path, vk.WriteTo); err != nil {
			panic(fmt.Sprintf("검증키 저장 실패 (%s): %v", path, err))
		}
	}

	// Age circuit keys - age 모듈에 저장
	agePKTargets := []string{"age/age.pk"}
	for _, path := range agePKTargets {
		if err := writeKeyFile(path, agePK.WriteTo); err != nil {
			panic(fmt.Sprintf("Age 증명키 저장 실패 (%s): %v", path, err))
		}
	}
	ageVKTargets := []string{"age/age.vk"}
	for _, path := range ageVKTargets {
		if err := writeKeyFile(path, ageVK.WriteTo); err != nil {
			panic(fmt.Sprintf("Age 검증키 저장 실패 (%s): %v", path, err))
		}
	}

	fmt.Println("✅ [성공] auth/, age/ 경로에 키 파일이 업데이트되었습니다.")

	// Fingerprints for versioning
	pkBytes, _ := os.ReadFile("auth/user.pk")
	vkBytes, _ := os.ReadFile("auth/user.vk")
	agePkBytes, _ := os.ReadFile("age/age.pk")
	ageVkBytes, _ := os.ReadFile("age/age.vk")
	pkID := blake2b.Sum256(pkBytes)
	vkID := blake2b.Sum256(vkBytes)
	agePkID := blake2b.Sum256(agePkBytes)
	ageVkID := blake2b.Sum256(ageVkBytes)
	fmt.Printf("Proving Key ID: %s\n", hex.EncodeToString(pkID[:]))
	fmt.Printf("Verifying Key ID: %s\n", hex.EncodeToString(vkID[:]))
	fmt.Printf("Age Proving Key ID: %s\n", hex.EncodeToString(agePkID[:]))
	fmt.Printf("Age Verifying Key ID: %s\n", hex.EncodeToString(ageVkID[:]))
}
