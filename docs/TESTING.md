# Testing & Benchmarks

## Unit / Integration

- `go test ./...` – default unit coverage, including server proof verification cases (success, malformed proof, challenge binding, commitment mismatch, random challenges).
- `make run` – end-to-end demo using embedded keys.

## Benchmarks

- `make bench` runs `go test -bench=. -benchmem ./server` to measure verification throughput.

## WASM Integration (Manual E2E)

- `make wasm` builds `html/identify.wasm`.
- `make serve` to host `html/` locally; open the page and exercise `InitIdentify` and `GenerateIdentifyProof` to validate the browser path.

## WASM Smoke Test (Node)

- `cd npm && npm test` runs a Node-based smoke test that builds `dist/` and generates a proof via WASM.

## Property / Regression Ideas

- Randomize challenges across a wider range and assert mismatched challenges always fail verification.
- Store golden proofs/commitments for a known circuit version; rerun after circuit changes to catch regressions.
- Add fuzz targets (Go 1.22+ `go test -fuzz`) for proof parsing inputs to harden against malformed data.***
