# Identify SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/ghdehrl12345/identify_sdk)](https://goreportcard.com/report/github.com/ghdehrl12345/identify_sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Version](https://img.shields.io/badge/version-v1.0.0-green.svg)](https://github.com/ghdehrl12345/identify_sdk/releases)

Identify SDK is a zero-knowledge authentication toolkit that lets shopping malls and fintech services verify users without collecting passwords or birthdays. The SDK combines MiMC commitments with Groth16 proofs to deliver **No-DB** passwordless login, anonymous age verification, and WASM-ready clients while keeping user secrets on their device.

## Installation

```bash
go get github.com/ghdehrl12345/identify_sdk@latest
```

All module imports must use the full path (e.g. `github.com/ghdehrl12345/identify_sdk/server`).

## Quick Start (Server)

```go
package main

import (
	"fmt"

	"github.com/ghdehrl12345/identify_sdk/server"
)

func main() {
	sdk, err := server.NewRealSDK()
	if err != nil {
		panic(err)
	}

	ok, err := sdk.VerifyLogin([]byte("fake-proof"), "1234567890", 4242)
	if err != nil {
		fmt.Println("verify failed:", err)
		return
	}
	fmt.Println("login result:", ok)
}
```

`server.NewRealSDK` loads the embedded verifying key, so no external files are needed once `client/user.pk` and `server/user.vk` are committed.

## Quick Start (Client)

```go
package main

import (
	"fmt"

	"github.com/ghdehrl12345/identify_sdk/client"
)

func main() {
	prover, err := client.NewUserProver()
	if err != nil {
		panic(err)
	}

	proof, commitment, err := prover.GenerateProof("password123", 2000, 2025, 20, 4242)
	if err != nil {
		panic(err)
	}

	fmt.Printf("proof bytes=%d, commitment=%s\n", len(proof), commitment)
}
```

The client compiles the circuit, loads the embedded proving key, and returns both the serialized proof and the MiMC commitment that should be stored in your database.

## Browser / WASM Integration

- Build the WASM bundle: `GOOS=js GOARCH=wasm go build -o html/identify.wasm github.com/ghdehrl12345/identify_sdk/client/wasm`
- Serve the `html/` folder (e.g., `make serve`) and load `wasm_exec.js` + `identify.wasm` in your page.
- JavaScript API:
  - `InitIdentify(pkBytes)` to initialize the prover with a proving key (embed or fetch).
  - `GenerateIdentifyProof(secret, birthYear, challenge)` returns `{ proof, hash }` where `hash` matches the stored commitment.

## API Reference (Core)

- `server.NewRealSDK()` → `IdentifySDK`
- `IdentifySDK.CreateCommitment(secret string)` → MiMC commitment string for storage.
- `IdentifySDK.VerifyLogin(proof []byte, publicCommitment string, challenge int)` → `bool`, validates password + age + challenge binding.
- `client.NewUserProver()` → prover with embedded `client/user.pk`.
- `prover.GenerateProof(secret string, birthYear, currentYear, limitAge, challenge int)` → `proofBytes, commitment`.

## Architecture

```
+------------------+        Challenge/Proof        +-----------------+
|  Frontend / WASM | <---------------------------> |    Client SDK   |
|  (InitIdentify)  |                               | (MiMC + Groth16)|
+------------------+                               +-----------------+
                                                      |
                                                      | Proof, Public Hash
                                                      v
                                              +-----------------+
                                              |    Server SDK   |
                                              | (VerifyLogin)   |
                                              +-----------------+
                                                      |
                                                      | On-chain optional verifier
                                                      v
                                              +-----------------+
                                              | Blockchain /   |
                                              | Compliance Log |
                                              +-----------------+
```

## Development Workflow

- `cmd/setup`: recompiles the circuit and regenerates proving/verifying keys (writes to `client/user.pk` and `server/user.vk` for embedding).
- `client/wasm`: exposes the prover to JavaScript via WebAssembly.
- `main.go`: end-to-end scenario for quick validation.

See the `Makefile` for convenience targets (`make setup`, `make wasm`, `make run`, `make serve`, `make clean`).

## Release & Compatibility

- CI matrix builds against Go `1.21.x` and `1.22.x` and uploads the WASM artifact per version.
- Track changes in `CHANGELOG.md`; tag releases (e.g., `v1.0.0`) after regenerating keys if circuits change.
- If you need to replace the embedded keys after a circuit update, rerun `make setup` and commit `client/user.pk` and `server/user.vk`.

## Security Notes

- Proofs bind to a server-issued `challenge` to prevent replay attacks; always issue a fresh challenge per login.
- Secrets and birth years never leave the client; only commitments and proofs are transmitted.
- Regenerate and commit `client/user.pk` and `server/user.vk` after any circuit change; mismatch will break verification.
- Configure `CurrentYear` and `LimitAge` via `server.NewRealSDKWithConfig` so policy changes don’t require code rewrites.
- For production, manage secrets and key rotation through your KMS and rotate proving/verifying keys when circuits evolve.

## Compliance & Observability

- See `SECURITY.md` for reporting channels and operational notes.
- Consider SBOM and license scans in your CI pipeline; publish WASM artifacts from CI for transparency.
- Add structured logging around verification results and integrate with your SIEM/monitoring stack.***

## License

MIT License © 2025 Identify SDK contributors.
