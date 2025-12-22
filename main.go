package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ghdehrl12345/identify_sdk/client"
	"github.com/ghdehrl12345/identify_sdk/server"
)

func main() {
	fmt.Println("=== 🍺 주류 쇼핑몰 통합 시스템 가동 (보안 강화 버전) ===")

	// 1. 서버 SDK 초기화 (Real 엔진 사용)
	// 임베딩된 user.vk 데이터를 사용하여 검증 준비
	srv, err := server.NewRealSDK()
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ [Server] ZKP 검증 엔진 로드 완료")

	// 2. 클라이언트 SDK 초기화 (Prover)
	// 임베딩된 user.pk 데이터를 사용하여 증명 준비
	cli, err := client.NewUserProver()
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ [Client] ZKP 증명 엔진 로드 완료")

	// --- [시나리오 시작] ---

	// 사용자 정보 (내 기기 속에만 있는 비밀)
	mySecret := "password123"
	myBirth := 2000 // 성인 (2025년 기준 25세)

	// =========================================================
	// Step A: 회원가입 (Commitment 생성)
	// =========================================================
	// 클라이언트가 비밀번호의 해시값만 계산해서 서버에 보냄
	myCommitment := cli.CalculateCommitment(mySecret)
	fmt.Printf("\n[1] 회원가입 요청: 해시값(%s...) 전송\n", myCommitment[:10])

	// 서버는 이 해시값만 DB에 저장 (비밀번호 원본은 절대 모름)
	serverDB_Commitment := myCommitment
	fmt.Println("   -> 서버 DB 저장 완료")

	// =========================================================
	// Step B: 로그인 시도 (챌린지-응답 프로세스)
	// =========================================================
	fmt.Println("\n[2] 로그인 시도 시작")

	// 1. 서버: 랜덤 챌린지 발급 ("자, 이 숫자 섞어서 증명해봐")
	// 매번 다른 숫자가 나오므로 해커가 옛날 증명서를 재사용할 수 없음
	rand.Seed(time.Now().UnixNano())
	serverChallenge := rand.Intn(99999)
	fmt.Printf("   -> [Server] 챌린지 발급: %d\n", serverChallenge)

	// 2. 클라이언트: 챌린지를 포함하여 증명서 생성
	// 입력: 비밀번호, 생년월일, 현재연도, 기준나이, **서버챌린지**
	fmt.Println("   -> [Client] 증명서(Proof) 생성 중...")
	proofBytes, proofPublicHash, err := cli.GenerateProof(mySecret, myBirth, 2025, 20, serverChallenge)
	if err != nil {
		panic("증명 생성 실패: " + err.Error())
	}
	fmt.Printf("   -> 증명서 생성 완료 (%d bytes)\n", len(proofBytes))

	// =========================================================
	// Step C: 서버 검증 (Verify)
	// =========================================================
	fmt.Println("\n[3] 서버 검증 시작")

	// 1. 해시값 일치 여부 확인 (클라이언트가 보낸 공개 입력값 vs DB 값)
	if proofPublicHash != serverDB_Commitment {
		fmt.Println("❌ 해시 불일치: 등록된 사용자가 아닙니다.")
		return
	}

	// 2. 영지식 증명 검증 (VerifyLogin)
	// 서버는 "내가 방금 보낸 챌린지(serverChallenge)"가 맞는지까지 수학적으로 확인함
	isLogin, err := srv.VerifyLogin(proofBytes, serverDB_Commitment, serverChallenge)

	if err != nil {
		fmt.Printf("❌ 검증 에러: %v\n", err)
	} else if isLogin {
		fmt.Println("🎉 [성공] 안전하게 로그인 되었습니다! (성인 인증 & Replay Attack 방어됨)")
	} else {
		fmt.Println("❌ [실패] 검증 거부됨 (비밀번호 틀림, 미성년자, 혹은 챌린지 불일치)")
	}
}
