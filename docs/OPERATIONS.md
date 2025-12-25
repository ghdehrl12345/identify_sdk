# Operations Guide

## Logging

- Log every verification attempt with outcome (success/failure) and reason code.
- Do not log secrets, salts, proofs, or raw birth year values.
- Include request metadata (timestamp, user ID, IP, user agent) for audit trails.

## Monitoring

Recommended metrics:
- Proof verification success rate
- Verification latency (p50/p95/p99)
- Challenge token expiry rate
- Policy mismatch rate (params_version / vk_id mismatch)
- RSA encryption failure rate (delivery)

## Key Management

- Store HMAC token keys and RSA public keys in KMS or a dedicated secret manager.
- Rotate token signing keys on a regular schedule and keep a short overlap window.
- Rotate proving/verifying keys when circuits change, and publish new `vk_id` to clients.

## Incident Response

- If verification failures spike, check policy drift and key mismatch first.
- If token validation fails, check HMAC key rotation and `kid` mapping.
- For leaked keys, rotate immediately and invalidate tokens issued with the compromised key.
