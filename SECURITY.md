# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v2.1.x  | ✅ Active |
| < v2.1  | ❌ Not supported |

## Reporting a Vulnerability

Please use one of the following channels:

1. **GitHub Security Advisories** (preferred): Create a private advisory in this repository
2. **Email**: Contact maintainers privately before public disclosure

We aim to:
- Acknowledge within **48 hours**
- Provide remediation plan within **7 days** for confirmed issues

## Security Features

### Authentication

| Feature | Description |
|---------|-------------|
| **ZKP Groth16** | Password never leaves the client |
| **JTI Token ID** | Prevents replay attacks with unique token IDs |
| **Challenge Binding** | H(commitment, challenge) binds proof to session |
| **Rate Limiting** | Built-in brute-force protection |

### Cryptography

| Feature | Specification |
|---------|---------------|
| **RSA** | Minimum 4096-bit keys enforced |
| **AES** | AES-256-GCM with random nonce |
| **Argon2id** | iterations=3, memory=64MB, threads=4 |
| **Salt** | 256-bit (32 bytes) random |
| **HMAC** | SHA-256 for token signing |

### Key Management

- **Fingerprinting**: blake2b-256 for key identity
- **Rotation**: `KeyManager` with auto-expiry and notifications
- **PolicyBundle**: Server→Client policy synchronization

## Security Best Practices

### ✅ Do

- Issue a **fresh challenge** for every login attempt
- Use **environment variables** or **KMS** for key storage
- Enable **TLS** for all network communication
- Sync client/server policies via `PolicyBundle()`
- Use `AsyncJSONLogger` for audit logging in production

### ❌ Don't

- Never commit PEM keys to repositories
- Never reuse challenge tokens
- Never use RSA keys smaller than 4096 bits
- Never disable rate limiting in production

## Environment Variables

```bash
# Required for delivery encryption
DELIVERY_PUBLIC_KEY_PATH=/secure/path/public.pem
DELIVERY_PRIVATE_KEY_PATH=/secure/path/private.pem

# Required for stateless tokens
CHALLENGE_TOKEN_KEY=<32+ byte secret>
```

## Key Rotation

```go
manager := auth.NewMemoryKeyManager()
manager.RegisterVersion(auth.KeyVersion{
    VKID:      auth.VerifyingKeyID(),
    CreatedAt: time.Now(),
    ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
})

rotator := auth.NewAutoKeyRotator(manager, config, func(e auth.KeyRotationEvent) {
    log.Printf("Key event: %s", e.Message)
})
rotator.Start()
```

## Audit Logging

All authentication attempts should be logged:

```go
logger.LogAuthAttempt(userID, success, map[string]string{
    "ip":       clientIP,
    "user_agent": userAgent,
})
```

## Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| gnark | ZKP circuits | v0.13.0 |
| gnark-crypto | MiMC, bn254 | v0.18.1 |
| golang.org/x/crypto | Argon2, blake2b | v0.39.0 |

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for security-related updates.
