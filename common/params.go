package common

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// ParamsVersion returns a stable fingerprint for shared policy/KDF parameters.
func ParamsVersion(cfg SharedConfig) string {
	payload := fmt.Sprintf("%d-%d-%d-%d", cfg.TargetYear, cfg.LimitAge, cfg.ArgonMemory, cfg.ArgonIterations)
	sum := blake2b.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
