#!/usr/bin/env sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SBOM_DIR="${ROOT_DIR}/sbom"
LICENSE_DIR="${ROOT_DIR}/licenses"
VULN_DIR="${ROOT_DIR}/vuln"

mkdir -p "${SBOM_DIR}" "${LICENSE_DIR}" "${VULN_DIR}"

if command -v cyclonedx-gomod >/dev/null 2>&1; then
  cyclonedx-gomod mod -licenses -output "${SBOM_DIR}/cyclonedx.json" -type json
else
  go list -m -json all > "${SBOM_DIR}/go-modules.json"
fi

if command -v go-licenses >/dev/null 2>&1; then
  go-licenses report ./... > "${LICENSE_DIR}/licenses.txt"
else
  go list -m -json all > "${LICENSE_DIR}/go-modules.json"
fi

if command -v govulncheck >/dev/null 2>&1; then
  govulncheck ./... > "${VULN_DIR}/govulncheck.txt" || true
fi
