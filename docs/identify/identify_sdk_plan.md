# identify_sdk 개선 로드맵 + API 시그니처 (Codex용)

## 목적
- SNS 같은 실서비스에서 identify_sdk를 “핵심 보안 엔진”으로 바로 적용할 수 있게 한다.
- 서비스 팀이 추가 설계 없이도 안전한 인증/복구/운영을 구현할 수 있게 한다.

## 이 문서가 왜 필요한가
- 현재 SDK는 알고리즘 핵심은 좋지만, “프로토콜 표준화/복구/운영/멀티플랫폼”이 부족하다.
- 아래 항목을 SDK에 추가하면 **도입 비용이 크게 줄고**, “보안 고민을 줄여주는 라이브러리”라는 메시지가 더 설득력 있다.

## 개선 로드맵 (Phase 기반)

### Phase 1: 표준화 + 호환성 안정
- 인코딩/포맷 표준 확정 (HEX vs Base64, 길이 제한)
- `proof_version`, `vk_id`, `params_version` 포함
- 테스트 벡터/샘플 E2E 제공 (Go/WASM)

### Phase 2: Stateless challenge + 운영 안정성
- 서버 상태 없는 challenge token 지원
- TTL/리플레이 방지 정책 내장
- 에러 코드 표준화 (운영 모니터링 가능)

### Phase 3: 복구/기기 변경 체계
- Key backup 암호화 API
- Social recovery 설계 문서 + 예제
- 기기 등록/해지 프로토콜 가이드

### Phase 4: 멀티 플랫폼 확장
- TS/Node, iOS, Android 동일 API 시그니처
- WASM 초기화/캐시 최적화 API

## 공통 모델 (API 시그니처)

### 타입
```ts
type Commitment = string; // hex
type Salt = string;       // hex (16~32 bytes)
type Proof = string;      // hex or base64
type ChallengeToken = string; // base64url, stateless

interface ProofResult {
  proof: Proof;
  commitment: Commitment;
  salt: Salt;
  proof_version: string;
  vk_id: string;
  params_version: string;
}

interface VerifyResult {
  ok: boolean;
  err_code?: string;
  err_msg?: string;
}
```

## 클라이언트 SDK (TS/WASM)

```ts
// init
init(): Promise<void>;

// 회원가입: commitment 생성
createCommitment(secret: string, salt?: Salt): { commitment: Commitment; salt: Salt };

// 로그인용 proof 생성
generateProof(
  secret: string,
  birthYear: number,
  currentYear: number,
  limitAge: number,
  challenge: number,
  salt: Salt
): ProofResult;

// stateless challenge 토큰을 쓰는 버전 (서버 상태 없음)
generateProofWithToken(
  secret: string,
  birthYear: number,
  challengeToken: ChallengeToken,
  salt: Salt
): ProofResult;

// 복구용
encryptKeyBackup(plainKey: string, pin: string): string;
decryptKeyBackup(encrypted: string, pin: string): string;
```

## 서버 SDK (Go)

```go
// init verifier
verifier, _ := auth.NewVerifier()

// challenge (stateful)
challenge, _ := svc.GenerateChallenge(userID)

// challenge (stateless)
token, _ := svc.IssueChallengeToken(userID, ttl)
// -> token includes userID, challenge, exp, signature

// verify (stateful)
ok, err := svc.VerifyLogin(userID, proofBytes, commitment, salt, challenge)

// verify (stateless)
ok, err := svc.VerifyLoginWithToken(proofBytes, commitment, salt, token)
```

## Stateless Challenge Token (권장 스펙)
- payload: `{ user_id, challenge, exp, nonce, vk_id, params_version }`
- 서명: HMAC-SHA256 또는 Ed25519
- 인코딩: base64url

## 에러 코드 표준 (예시)
- `AUTH001` invalid_proof
- `AUTH002` challenge_expired
- `AUTH003` challenge_invalid
- `AUTH004` user_not_found
- `AUTH005` version_mismatch

## 판단: “라이브러리에 추가하면 좋은가?”
- 결론: **예. 반드시 좋은 방향**이다.
- 이유: SDK가 “알고리즘 제공”을 넘어 **서비스 적용까지 책임지는 제품**이 된다.
- 특히 Stateless challenge / 복구 체계 / 표준 에러코드는 대기업 도입에 필수다.

