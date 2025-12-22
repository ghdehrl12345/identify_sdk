SHELL := /bin/sh
GO     ?= go

.PHONY: setup wasm run serve clean

setup:
	@echo ">> Generating proving/verifying keys"
	$(GO) run ./cmd/setup

wasm:
	@echo ">> Building WebAssembly prover"
	GOOS=js GOARCH=wasm $(GO) build -o html/identify.wasm ./client/wasm

run:
	@echo ">> Running end-to-end demo"
	GOCACHE=$(PWD)/.gocache $(GO) run ./main.go

serve:
	@echo ">> Serving html/ on http://localhost:8080"
	cd html && python3 -m http.server 8080

clean:
	@echo ">> Cleaning build artifacts"
	rm -rf build html/identify.wasm .gocache
