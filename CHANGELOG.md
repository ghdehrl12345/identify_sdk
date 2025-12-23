# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-12-23

### ⚠️ Breaking Changes

- **Module restructuring**: Package paths have changed
  - `server` → `auth` (for verification)
  - `client` → `auth` (for proving)
  - Age verification moved to `age` module
  - Encryption utilities moved to `crypto` module
- **Argon2 iterations increased**: 1 → 3 for security. Existing commitments must be regenerated.

### Added

- **Modular architecture**: Each feature can be imported independently
  - `auth/` - ZKP-based passwordless authentication
  - `age/` - Anonymous age verification
  - `crypto/` - Encryption utilities (delivery, content, masking)
  - `commitment/` - MiMC hash commitment
  - `audit/` - Audit logging interface
- **AES-256-GCM content encryption** (`crypto/content.go`)
- **Data masking utilities** (`crypto/masking.go`)
  - `MaskEmail()`, `MaskPhone()`, `MaskName()`, `MaskCreditCard()`
- **Audit logging** (`audit/logger.go`)
  - JSON logger for compliance requirements
  - NoOp logger for testing

### Changed

- Replaced deprecated `ioutil.ReadFile` with `os.ReadFile`
- Improved error messages with Go 1.13+ error wrapping

### Removed

- PEM key files from repository (now managed via environment variables)

### Security

- Argon2 iterations increased from 1 to 3
- PEM keys must be loaded from environment variables or KMS

---

## [1.0.0] - 2025-01-01

### Added

- Initial release
- ZKP-based passwordless login with MiMC + Groth16
- Anonymous age verification
- RSA-OAEP delivery info encryption
- WASM support for browser clients
- npm package for JavaScript integration
