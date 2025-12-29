package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ghdehrl12345/identify_sdk/v2/commitment"
)

func cmdMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	secret := fs.String("secret", "", "User secret/password (required)")
	salt := fs.String("salt", "", "Current salt in hex (required)")
	oldCommitment := fs.String("old-commitment", "", "Old v1 commitment for verification (optional)")
	v1Iter := fs.Uint("v1-iterations", 1, "v1 Argon2 iterations")
	v2Iter := fs.Uint("v2-iterations", 3, "v2 Argon2 iterations")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Parse(args)

	if *secret == "" || *salt == "" {
		fmt.Fprintln(os.Stderr, "Error: --secret and --salt are required")
		fs.Usage()
		os.Exit(1)
	}

	cfg := commitment.MigrationConfig{
		V1Iterations: uint32(*v1Iter),
		V1Memory:     64 * 1024,
		V2Iterations: uint32(*v2Iter),
		V2Memory:     64 * 1024,
	}

	var result commitment.MigrationResult
	if *oldCommitment != "" {
		result = commitment.VerifyAndMigrate(*secret, *salt, *oldCommitment, cfg)
	} else {
		result = commitment.MigrateCommitment(*secret, *salt, cfg)
	}

	if *jsonOutput {
		out := map[string]interface{}{
			"success":        result.Success,
			"old_commitment": result.OldCommitment,
			"new_commitment": result.NewCommitment,
			"salt":           result.Salt,
		}
		if result.Error != nil {
			out["error"] = result.Error.Error()
		}
		json.NewEncoder(os.Stdout).Encode(out)
		return
	}

	if !result.Success {
		fmt.Fprintf(os.Stderr, "Migration failed: %v\n", result.Error)
		os.Exit(1)
	}

	fmt.Println("Migration successful!")
	fmt.Println()
	fmt.Println("Old commitment (v1):", result.OldCommitment)
	fmt.Println("New commitment (v2):", result.NewCommitment)
	fmt.Println("Salt:", result.Salt)
	fmt.Println()
	fmt.Println("⚠️  Update your database with the new commitment value.")
}
