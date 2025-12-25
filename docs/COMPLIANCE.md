# Compliance Artifacts

This repository provides automation for generating compliance artifacts:

## SBOM

- Preferred: CycloneDX (`cyclonedx-gomod`)
- Fallback: `go list -m -json all` output

## License Report

- Preferred: `go-licenses report ./...`
- Fallback: module list output

## Vulnerability Scan

- Optional: `govulncheck ./...`

Run locally:

```bash
make compliance
```

Artifacts are written to `sbom/`, `licenses/`, and `vuln/`. In CI, these are uploaded as build artifacts.
