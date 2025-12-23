package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/ghdehrl12345/identify_sdk/client"
	"github.com/ghdehrl12345/identify_sdk/common"
	"github.com/ghdehrl12345/identify_sdk/server"
)

func main() {
	fmt.Println("=== 🍺 주류 쇼핑몰 통합 시스템 가동 (정책/암호화 설정 적용) ===")

	shared := common.SharedConfig{
		TargetYear:      2025,
		LimitAge:        20,
		ArgonMemory:     common.ArgonMemory,
		ArgonIterations: common.ArgonIterations,
	}
	deliveryKeyPath := os.Getenv("DELIVERY_PUBLIC_KEY_PATH") // PEM RSA 공개키 경로

	// 서버 SDK 초기화 (정책 + RSA 공개키)
	srv, err := server.NewRealSDKWithConfig(server.RealIdentifyConfig{
		Config:                shared,
		DeliveryPublicKeyPath: deliveryKeyPath,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ [Server] ZKP 검증 엔진 로드 완료")

	// 클라이언트 SDK 초기화 (서버와 동일한 정책)
	cli, err := client.NewUserProverWithPolicy(client.DefaultPolicy(), shared)
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ [Client] ZKP 증명 엔진 로드 완료")

	mySecret := "password123"
	myBirth := 2000
	salt, _ := client.GenerateSalt()

	commitment, _, _ := client.ComputeCommitmentAndBinding(mySecret, salt, 0, shared)
	fmt.Printf("\n[1] 회원가입 요청: 해시값(%s...) 전송 (salt=%s)\n", commitment[:10], salt)

	serverDBCommitment := commitment
	serverDBSalt := salt
	fmt.Println("   -> 서버 DB 저장 완료")

	fmt.Println("\n[2] 로그인 시도 시작")
	rand.Seed(time.Now().UnixNano())
	serverChallenge := rand.Intn(99999)
	fmt.Printf("   -> [Server] 챌린지 발급: %d\n", serverChallenge)

	fmt.Println("   -> [Client] 증명서(Proof) 생성 중...")
	proofBytes, proofPublicHash, _, err := cli.GenerateProof(mySecret, myBirth, shared.TargetYear, shared.LimitAge, serverChallenge, serverDBSalt)
	if err != nil {
		panic("증명 생성 실패: " + err.Error())
	}
	fmt.Printf("   -> 증명서 생성 완료 (%d bytes)\n", len(proofBytes))

	fmt.Println("\n[3] 서버 검증 시작")
	if proofPublicHash != serverDBCommitment {
		fmt.Println("❌ 해시 불일치: 등록된 사용자가 아닙니다.")
		return
	}

	isLogin, err := srv.VerifyLogin(proofBytes, serverDBCommitment, serverDBSalt, serverChallenge)
	if err != nil {
		fmt.Printf("❌ 검증 에러: %v\n", err)
	} else if isLogin {
		fmt.Println("🎉 [성공] 안전하게 로그인 되었습니다! (성인 인증 & Replay Attack 방어됨)")
	} else {
		fmt.Println("❌ [실패] 검증 거부됨 (비밀번호 틀림, 미성년자, 혹은 챌린지 불일치)")
	}

	userAddr := "서울시 강남구 테헤란로 123"
	secureAddr, err := srv.EncryptDeliveryInfo(userAddr)
	if err != nil {
		fmt.Printf("❌ 배송 정보 암호화 실패: %v\n", err)
	} else {
		fmt.Printf("[배송] 암호화된 주소(Base64): %s\n", secureAddr)
	}
	fmt.Println("=== 상황 종료 ===")
}
