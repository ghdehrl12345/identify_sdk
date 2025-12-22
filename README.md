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

## License

MIT License © 2025 Identify SDK contributors.
