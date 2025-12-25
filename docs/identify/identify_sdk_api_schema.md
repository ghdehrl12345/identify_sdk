# identify_sdk API Definition (with JSON Schema)

## Overview
This document defines the standard wire formats and schema contracts for identify_sdk integration.

## Encodings
- Commitment: decimal string (field element)
- Salt: hex string (16~32 bytes)
- Proof: hex or base64 (explicitly declared in response)
- ChallengeToken: base64url

## Common Types (TypeScript)
```ts
type Commitment = string; // decimal string
type Salt = string;       // hex (16~32 bytes)
type Proof = string;      // hex or base64
type ChallengeToken = string; // base64url

interface ProofResult {
  proof: Proof;
  commitment: Commitment;
  salt: Salt;
  proof_version: string;
  vk_id: string;
  params_version: string;
}

interface PolicyBundle {
  config: {
    target_year: number;
    limit_age: number;
    argon_memory: number;
    argon_iterations: number;
  };
  params_version: string;
  vk_id: string;
}

interface VerifyResult {
  ok: boolean;
  err_code?: string;
  err_msg?: string;
}
```

## JSON Schema

### 1) Register Request
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "RegisterRequest",
  "type": "object",
  "required": ["username", "commitment", "salt"],
  "properties": {
    "username": { "type": "string", "minLength": 3, "maxLength": 30 },
    "commitment": { "type": "string", "pattern": "^[0-9]+$" },
    "salt": { "type": "string", "pattern": "^[0-9a-fA-F]+$" }
  }
}
```

### 2) Challenge Request
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ChallengeRequest",
  "type": "object",
  "required": ["username"],
  "properties": {
    "username": { "type": "string" }
  }
}
```

### 3) Challenge Response (stateful)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ChallengeResponse",
  "type": "object",
  "required": ["user_id", "challenge", "salt", "current_year", "limit_age", "vk_id", "params_version"],
  "properties": {
    "user_id": { "type": "string", "format": "uuid" },
    "challenge": { "type": "integer" },
    "salt": { "type": "string", "pattern": "^[0-9a-fA-F]+$" },
    "current_year": { "type": "integer" },
    "limit_age": { "type": "integer" },
    "vk_id": { "type": "string" },
    "params_version": { "type": "string" },
    "kid": { "type": "string" },
    "kid": { "type": "string" },
    "expires_in": { "type": "integer" }
  }
}
```

### 4) Challenge Response (stateless)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ChallengeTokenResponse",
  "type": "object",
  "required": ["challenge_token", "salt", "vk_id", "params_version", "expires_in"],
  "properties": {
    "challenge_token": { "type": "string" },
    "salt": { "type": "string", "pattern": "^[0-9a-fA-F]+$" },
    "vk_id": { "type": "string" },
    "params_version": { "type": "string" },
    "expires_in": { "type": "integer" }
  }
}
```

### 5) Login Request (stateful)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "LoginRequest",
  "type": "object",
  "required": ["user_id", "challenge", "proof", "vk_id", "params_version"],
  "properties": {
    "user_id": { "type": "string", "format": "uuid" },
    "challenge": { "type": "integer" },
    "proof": { "type": "string" },
    "vk_id": { "type": "string" },
    "params_version": { "type": "string" },
    "proof_version": { "type": "string" }
  }
}
```

### 6) Login Request (stateless)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "LoginWithTokenRequest",
  "type": "object",
  "required": ["challenge_token", "proof", "vk_id", "params_version"],
  "properties": {
    "challenge_token": { "type": "string" },
    "proof": { "type": "string" },
    "vk_id": { "type": "string" },
    "params_version": { "type": "string" },
    "proof_version": { "type": "string" }
  }
}
```

### 7) Password Reset Request
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ResetPasswordRequest",
  "type": "object",
  "required": ["token", "commitment", "salt"],
  "properties": {
    "token": { "type": "string" },
    "commitment": { "type": "string", "pattern": "^[0-9]+$" },
    "salt": { "type": "string", "pattern": "^[0-9a-fA-F]+$" }
  }
}
```

### 8) Error Response
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ErrorResponse",
  "type": "object",
  "required": ["error"],
  "properties": {
    "error": { "type": "string" },
    "code": { "type": "string" }
  }
}
```

### 9) Policy Bundle Response
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PolicyBundleResponse",
  "type": "object",
  "required": ["config", "params_version", "vk_id"],
  "properties": {
    "config": {
      "type": "object",
      "required": ["target_year", "limit_age", "argon_memory", "argon_iterations"],
      "properties": {
        "target_year": { "type": "integer" },
        "limit_age": { "type": "integer" },
        "argon_memory": { "type": "integer" },
        "argon_iterations": { "type": "integer" }
      }
    },
    "params_version": { "type": "string" },
    "vk_id": { "type": "string" }
  }
}
```

## Error Codes (stable)
- E1001 invalid proof format
- E1003 proof verification failed
- E1011 challenge expired
- E1012 challenge token invalid
- E2004 key fingerprint mismatch
- E4002 policy mismatch
