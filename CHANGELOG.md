# Changelog

## [Unreleased]
- Add additional negative and property-based tests around challenge/commitment verification.
- Document security considerations and release workflow.
- Configurable server policy parameters (current year, age limit) via `NewRealSDKWithConfig`.
- CI matrix across Go 1.21/1.22 with WASM artifacts.
- Benchmarks and expanded regression tests for verification.

## [v1.0.0]
- Initial public release with embedded proving/verifying keys, MiMC commitment hashing, Groth16 login/age verification, and WASM client.***
