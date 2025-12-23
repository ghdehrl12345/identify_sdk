SHELL := /bin/sh
GO     ?= go
GOCACHE ?= $(PWD)/.gocache
DIST_NPM := npm/dist

.PHONY: setup wasm run serve clean embed npm-prep build-all bench

clean:
	@echo ">> Cleaning build artifacts"
	rm -rf build $(DIST_NPM) html/identify.wasm $(GOCACHE)

setup:
	@echo ">> Generating proving/verifying keys"
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/setup

embed:
	@echo ">> Copying keys for Go embeds"
	mkdir -p client server
	cp build/user.pk client/user.pk
	cp build/user.vk server/user.vk
	cp build/age.pk client/age.pk
	cp build/age.vk server/age.vk

wasm:
	@echo ">> Building WebAssembly prover"
	mkdir -p $(DIST_NPM)
	GOCACHE=$(GOCACHE) GOOS=js GOARCH=wasm $(GO) build -o $(DIST_NPM)/identify.wasm ./client/wasm
	cp $(DIST_NPM)/identify.wasm html/identify.wasm

npm-prep:
	@echo ">> Preparing npm/dist assets"
	mkdir -p $(DIST_NPM)
	cp html/wasm_exec.js $(DIST_NPM)/
	cp build/user.pk build/age.pk $(DIST_NPM)/

build-all: clean setup embed wasm npm-prep
	@echo ">> All artifacts ready in $(DIST_NPM) and client/server embeds"

run:
	@echo ">> Running end-to-end demo"
	GOCACHE=$(GOCACHE) $(GO) run ./main.go

serve:
	@echo ">> Serving html/ on http://localhost:8080"
	cd html && python3 -m http.server 8080

bench:
	@echo ">> Running benchmarks"
	GOCACHE=$(GOCACHE) $(GO) test -bench=. -benchmem ./server
