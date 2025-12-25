package main

import (
	"fmt"
	"runtime"

	"github.com/ghdehrl12345/identify_sdk/v2/auth"
)

func cmdVersion() {
	fmt.Printf(`identify-cli version %s

Build Info:
  Go version:    %s
  OS/Arch:       %s/%s

Key Fingerprints:
  Proving Key:   %s
  Verifying Key: %s
`, version, runtime.Version(), runtime.GOOS, runtime.GOARCH,
		truncateID(auth.ProvingKeyID()),
		truncateID(auth.VerifyingKeyID()))
}

func truncateID(id string) string {
	if len(id) > 16 {
		return id[:16] + "..."
	}
	return id
}
