# Identify SDK v2.0

[![Go Report Card](https://goreportcard.com/badge/github.com/ghdehrl12345/identify_sdk)](https://goreportcard.com/report/github.com/ghdehrl12345/identify_sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Version](https://img.shields.io/badge/version-v2.0.0-green.svg)](https://github.com/ghdehrl12345/identify_sdk/releases)

**프라이버시 중심 보안 라이브러리**로, 홈쇼핑, SNS, 핀테크 등 다양한 프로젝트에서 필요한 보안 기능만 선택적으로 사용할 수 있습니다.

## 주요 기능

| 모듈 | 기능 | 사용 예시 |
|------|------|----------|
| `auth` | ZKP 기반 비밀번호 없는 로그인 | 모든 서비스 |
| `age` | 익명 성인 인증 | 주류/담배 쇼핑몰 |
| `crypto` | 배송정보/콘텐츠 암호화, 데이터 마스킹 | 이커머스, SNS DM |
| `commitment` | MiMC 해시 커밋먼트 | 인증 기반 서비스 |
| `audit` | 감사 로깅 | 금융/의료 서비스 |

## 설치

```bash
go get github.com/ghdehrl12345/identify_sdk@latest
```

## 프로젝트별 사용 예시

### 🛒 홈쇼핑: 로그인 + 배송 암호화

```go
import (
    "github.com/ghdehrl12345/identify_sdk/auth"
    "github.com/ghdehrl12345/identify_sdk/crypto"
)

// 서버: 로그인 검증
verifier, _ := auth.NewVerifier()
ok, _ := verifier.VerifyLogin(proofBytes, commitment, salt, challenge)

// 배송 정보 암호화
encryptor, _ := crypto.NewDeliveryEncryptorFromEnv()
encrypted, _ := encryptor.Encrypt("서울시 강남구 테헤란로 123")
```

### 📱 SNS: 로그인 + 성인 인증 + DM 암호화

```go
import (
    "github.com/ghdehrl12345/identify_sdk/auth"
    "github.com/ghdehrl12345/identify_sdk/age"
    "github.com/ghdehrl12345/identify_sdk/crypto"
)

// 성인 인증
ageVerifier, _ := age.NewVerifier()
isAdult, _ := ageVerifier.VerifyAge(ageProof)

// DM 암호화
content := crypto.NewContentEncryptor()
key, _ := crypto.GenerateKey()
ciphertext, _ := content.Encrypt([]byte("비밀 메시지"), key)
```

### 🏦 핀테크: 로그인 + 감사 로깅

```go
import (
    "github.com/ghdehrl12345/identify_sdk/auth"
    "github.com/ghdehrl12345/identify_sdk/audit"
)

// 감사 로거 설정
logger, _ := audit.NewJSONLoggerToFile("/var/log/audit.json")

// 로그인 시도 기록
verifier, _ := auth.NewVerifier()
ok, err := verifier.VerifyLogin(proofBytes, commitment, salt, challenge)
logger.LogAuthAttempt(userID, ok, map[string]string{"ip": clientIP})
```

## 모듈 구조

```
identify_sdk/
├── auth/           # ZKP 인증 (필수)
│   ├── prover.go   # 클라이언트: 증명 생성
│   └── verifier.go # 서버: 증명 검증
├── age/            # 성인 인증 (선택)
│   ├── prover.go
│   └── verifier.go
├── crypto/         # 암호화 유틸리티 (선택)
│   ├── delivery.go # RSA-OAEP 배송정보 암호화
│   ├── content.go  # AES-256-GCM 콘텐츠 암호화
│   └── masking.go  # 데이터 마스킹
├── commitment/     # MiMC 해시 (공통)
│   └── mimc.go
├── audit/          # 감사 로깅 (선택)
│   └── logger.go
└── common/         # 공유 설정
    └── config.go
```

## 마이그레이션 가이드 (v1 → v2)

### Import 경로 변경

```diff
-import "github.com/ghdehrl12345/identify_sdk/server"
-import "github.com/ghdehrl12345/identify_sdk/client"
+import "github.com/ghdehrl12345/identify_sdk/auth"
+import "github.com/ghdehrl12345/identify_sdk/age"
```

### 함수명 변경

```diff
-sdk, _ := server.NewRealSDK()
-ok, _ := sdk.VerifyLogin(proof, commitment, salt, challenge)
+verifier, _ := auth.NewVerifier()
+ok, _ := verifier.VerifyLogin(proof, commitment, salt, challenge)
```

## 보안 노트

- ⚠️ **Argon2 iteration**이 v2.0에서 1→3으로 강화됨. 기존 commitment는 재생성 필요.
- ⚠️ **PEM 키 파일**은 환경변수 또는 KMS로 관리. 저장소에 커밋 금지.
- 챌린지는 매 로그인마다 새로 발급하여 Replay Attack 방어.
- 클라이언트와 서버 간 정책(currentYear, limitAge) 동기화 필수.

## 테스트

```bash
# 전체 테스트
go test ./... -v

# 특정 모듈 테스트
go test ./crypto/... -v
go test ./auth/... -v
```

## License

MIT License © 2025 Identify SDK contributors.
