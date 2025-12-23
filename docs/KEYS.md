# Key Fingerprints & Versioning

- Embedded proving key ID: `client.ProvingKeyID()` (blake2b-256 of `client/user.pk`)
- Embedded verifying key ID: `server.VerifyingKeyID()` (blake2b-256 of `server/user.vk`)
- `cmd/setup` prints both IDs after regenerating keys. Capture them in release notes and configuration.
- Optional enforcement: set `ExpectedVK` in `server.NewRealSDKWithConfig` to reject mismatched verifying keys at startup.
- When circuits change, regenerate keys (`make setup`), update fingerprints, and bump version.
