# Changelog

All notable changes to this project will be documented in this file.

## [v2.1.0] - 2025-12-29

### Added

- **JTI Token ID**: Unique token IDs for replay attack prevention
- **TokenStore Interface**: `MemoryTokenStore` for JTI tracking
- **RateLimiter**: `MemoryRateLimiter` with configurable thresholds
- **DeliveryDecryptor**: RSA-OAEP decryption for delivery information
- **AsyncJSONLogger**: Non-blocking audit logging with buffering
- **KeyManager**: Key version management and rotation support
- **AutoKeyRotator**: Automatic key expiration monitoring
- **Commitment Migration**: CLI tool and API for v1→v2 upgrade
- **Environment Config**: `GetArgonConfig(env)` for dev/prod separation

### Changed

- **TargetYear**: Now uses dynamic `time.Now().Year()` instead of hardcoded value
- **Salt Length**: Increased from 16 to 32 bytes (256-bit)
- **RSA Minimum**: Enforced 4096-bit minimum key size
- **WASM Errors**: Sanitized in production mode via `NODE_ENV`

### Security

- Argon2id: iterations=3, memory=64MB (production)
- Challenge tokens include JTI field
- RSA keys below 4096-bit are rejected
- Error messages hide internal details in production

## [v2.0.0] - 2025-12-01

Initial v2 release with modular architecture.

### Features

- ZKP Groth16 authentication
- Age verification
- Delivery encryption (RSA-OAEP)
- Content encryption (AES-256-GCM)
- Data masking
- Audit logging
- CLI tools
