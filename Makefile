SHELL := /bin/sh
GO     ?= go
GOCACHE ?= $(PWD)/.gocache
DIST_NPM := npm/dist

.PHONY: setup wasm run clean npm-prep build-all bench compliance golden

clean:
	@echo ">> Cleaning build artifacts"
	rm -rf $(DIST_NPM) $(GOCACHE)

setup:
	@echo ">> Generating proving/verifying keys"
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/setup

wasm:
	@echo ">> Building WebAssembly prover"
	mkdir -p $(DIST_NPM)
	GOCACHE=$(GOCACHE) GOOS=js GOARCH=wasm $(GO) build -o $(DIST_NPM)/identify.wasm ./wasm

npm-prep:
	@echo ">> Preparing npm/dist assets"
	mkdir -p $(DIST_NPM)
	cp "$(shell $(GO) env GOROOT)/lib/wasm/wasm_exec.js" $(DIST_NPM)/
	cp auth/user.pk age/age.pk $(DIST_NPM)/

build-all: clean setup wasm npm-prep
	@echo ">> All artifacts ready in $(DIST_NPM) and client/server embeds"

run:
	@echo ">> Running identify-cli help"
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/identify-cli --help

bench:
	@echo ">> Running benchmarks"
	GOCACHE=$(GOCACHE) $(GO) test -bench=. -benchmem ./auth ./age ./crypto

compliance:
	@echo ">> Generating SBOM and license report"
	./scripts/compliance.sh

golden:
	@echo ">> Generating golden proofs"
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/golden-gen
