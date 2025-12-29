# Identify SDK v2.1

[![Go Report Card](https://goreportcard.com/badge/github.com/ghdehrl12345/identify_sdk/v2)](https://goreportcard.com/report/github.com/ghdehrl12345/identify_sdk/v2)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Version](https://img.shields.io/badge/version-v2.1.0-green.svg)](https://github.com/ghdehrl12345/identify_sdk/releases/tag/v2.1.0)

**ZKP(영지식 증명) 기반 인증 라이브러리** - 비밀번호가 서버에 전송되지 않는 안전한 로그인 시스템을 구축합니다.

## 💡 ZKP 인증이란?

사용자가 **비밀번호를 알고 있다는 사실**만 증명하고, 비밀번호 자체는 전송하지 않는 인증 방식입니다.

```
[기존 방식]  클라이언트 --비밀번호--> 서버 (서버가 비밀번호 확인)
[ZKP 방식]  클라이언트 --증명(proof)--> 서버 (서버는 증명만 검증)
```

## 🔒 보안 범위 (정직한 설명)

### ✅ ZKP가 보호하는 것

| 공격 유형 | 기존 방식 | ZKP |
|----------|----------|-----|
| **네트워크 스니핑** | 비밀번호 노출 | ✅ 증명만 전송 (비밀번호 없음) |
| **서버 DB 해킹** | 해시 탈취 → 레인보우 테이블 | ✅ Argon2 + Salt + MiMC |
| **서버 관리자 악용** | 비밀번호 열람 가능 | ✅ 서버에 비밀번호 자체가 없음 |
| **MITM 공격** | 세션 하이재킹 | ✅ 챌린지 바인딩 |
| **Replay 공격** | 토큰 재사용 | ✅ JTI + 만료 시간 |

### ❌ ZKP가 보호하지 못하는 것

| 공격 유형 | 설명 |
|----------|------|
| **클라이언트 해킹** | 키로거, 악성코드 등으로 클라이언트가 해킹되면 비밀번호 노출 (모든 인증 시스템 공통) |
| **약한 비밀번호** | DB 해킹 후 브루트포스 가능 - **강력한 비밀번호 필수** |

### 💪 Commitment 브루트포스 난이도

DB가 해킹되어 `commitment + salt`가 노출된 경우:

| 비밀번호 유형 | 조합 수 | 예상 소요 시간* |
|--------------|--------|---------------|
| 6자리 숫자 PIN | 100만 | ~17분 ⚠️ |
| 8자리 영숫자 | 218조 | ~7,000년 |
| 12자리 영숫자+특수 | 10^23 | 사실상 불가능 |

*Argon2 기준 (iterations=3, memory=64MB), 고성능 GPU 1,000회/초 가정

> **결론**: 강력한 비밀번호 정책을 함께 적용해야 합니다.

## ✨ 주요 기능

| 모듈 | 기능 | 설명 |
|------|------|------|
| `auth` | **ZKP 로그인** | Groth16 기반 비밀번호 없는 인증 |
| `auth` | **Rate Limiting** | Brute-force 공격 방어 |
| `auth` | **키 로테이션** | 자동 키 만료 및 갱신 |
| `age` | **익명 성인 인증** | 생년 노출 없이 나이만 증명 |
| `commitment` | **MiMC 해시** | Argon2 + MiMC 기반 commitment |
| `audit` | **감사 로깅** | 비동기 인증 로그 기록 |
| `crypto` | **암호화 (부가)** | 배송정보/DM 암호화 |

## 📦 설치

```bash
go get github.com/ghdehrl12345/identify_sdk/v2@v2.1.0
```

## 🚀 빠른 시작

### 1. 회원가입 (Commitment 생성)

```go
import "github.com/ghdehrl12345/identify_sdk/v2/auth"

// 클라이언트에서 commitment 생성
prover, _ := auth.NewUserProver()
commitment, salt, _ := prover.CalculateCommitment("user_password")

// commitment와 salt를 서버 DB에 저장 (비밀번호는 저장 안 함!)
db.Save(userID, commitment, salt)
```

### 2. 로그인 (서버)

```go
// 챌린지 발급 (매 로그인마다 새로 발급)
claims := auth.ChallengeTokenClaims{
    UserID:    userID,
    Challenge: rand.Intn(1000000),
    ExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
}
token, _ := auth.IssueChallengeToken(secretKey, claims)
```

### 3. 로그인 (클라이언트)

```go
// 증명 생성
proof, _, _, _ := prover.GenerateProof(
    "user_password", 1990, cfg.TargetYear, cfg.LimitAge, challenge, salt,
)
```

### 4. 증명 검증 (서버)

```go
verifier, _ := auth.NewVerifier()
limiter := auth.NewMemoryRateLimiter(auth.DefaultRateLimitConfig())

if !limiter.AllowLogin(userID, clientIP) {
    return errors.New("너무 많은 시도")
}

ok, _ := verifier.VerifyLoginWithToken(proof, commitment, salt, token)
if !ok {
    limiter.RecordFailure(userID, clientIP)
}
```

## � CLI 도구

```bash
identify-cli generate-keys --output ./keys
identify-cli verify --proof proof.hex --commitment "..." --salt "..." --challenge 4242
identify-cli migrate --secret "password" --salt "..." --json
```

## ⚙️ 환경 변수

```bash
CHALLENGE_TOKEN_KEY="your-secret-key"  # 필수
```

## 🧪 테스트

```bash
go test ./... -v
```

## 📚 문서

- [SECURITY.md](SECURITY.md) - 보안 가이드
- [CHANGELOG.md](CHANGELOG.md) - 변경 이력

## 📄 License

MIT License © 2025 Identify SDK contributors.
