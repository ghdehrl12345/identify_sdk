# Testing & Benchmarks

## Unit / Integration

- `go test ./...` – default unit coverage, including server proof verification cases (success, malformed proof, challenge binding, commitment mismatch, random challenges).
- `make run` – identify-cli 도움말 확인.
- `make golden` – 회로 변경 리그레션용 golden proof 생성.

## Benchmarks

- `make bench` runs `go test -bench=. -benchmem ./auth ./age ./crypto` to measure throughput.

## WASM Integration (Manual E2E)

- `make wasm` builds `npm/dist/identify.wasm`.

## WASM Smoke Test (Node)

- `cd npm && npm test` runs a Node-based smoke test that builds `dist/` and generates a proof via WASM.

## Property / Regression Ideas

- Randomize challenges across a wider range and assert mismatched challenges always fail verification.
- Store golden proofs/commitments for a known circuit version; rerun after circuit changes to catch regressions.
- Add fuzz targets (Go 1.22+ `go test -fuzz`) for proof parsing inputs to harden against malformed data.***
