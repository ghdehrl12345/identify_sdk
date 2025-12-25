# identify_sdk PRD / Spec (Codex-friendly)

## 1. Goal
Provide a production-ready authentication SDK that enables ZKP-based login without handling raw passwords, while minimizing integration and operational burden for service teams.

## 2. Non-Goals
- This SDK does not replace full IAM systems.
- This SDK does not implement full account lifecycle or billing.

## 3. Target Users
- Web and mobile teams integrating ZKP-based login.
- Backend teams operating scalable authentication services.

## 4. Core Value
- Strong security with reduced password handling.
- Clear protocol standardization and versioning.
- Stateless challenge support for easy scaling.
- Recoverability (device change, key backup) as a first-class feature.

## 5. Feature Scope

### Phase 1: Standardization and Compatibility
- Standard encoding format definition (hex/base64, length constraints)
- Proof and key metadata fields included in outputs
- Policy bundle endpoint for client sync (params_version + vk_id)
- E2E test vectors and sample flows (Go + WASM)

### Phase 2: Stateless Challenge and Ops Stability
- Stateless challenge token issuance and verification
- Built-in TTL and replay prevention policy
- Standardized error codes for monitoring
- Token signing key rotation support (kid)

### Phase 3: Recovery and Device Change
- Key backup encryption/decryption APIs
- Social recovery reference flow and docs
- Device registration / revocation guidance

### Phase 4: Multi-Platform Expansion
- TS/Node, iOS, Android unified API design
- WASM init and cache optimization helpers

## 6. System Requirements
- Deterministic commitment generation
- Consistent proof verification across languages
- Backward compatibility with version metadata
- Minimal latency impact for proof generation

## 7. API Principles
- Same function names and payload shapes across platforms
- Clear error codes with stable identifiers
- Stateless challenge token support for horizontal scaling

## 8. Security Requirements
- Replay prevention and TTL enforcement
- Challenge token signed (HMAC-SHA256 or Ed25519)
- Version mismatch explicitly surfaced
- No server-side exposure of raw secrets
- Policy bundle must be the single source of truth for client config

## 9. Success Metrics
- Time-to-integrate <= 1 day for standard flow
- Stateless flow reduces infrastructure dependency (no DB/Redis)
- Zero known compatibility regressions across SDK versions

## 10. Deliverables
- SDKs: Go (server), WASM/TS (client), Docs, Test vectors
- Reference flow documentation: register -> challenge -> login -> recovery
