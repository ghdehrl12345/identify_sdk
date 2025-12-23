package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/ghdehrl12345/identify_sdk/auth"
	"github.com/ghdehrl12345/identify_sdk/common"
)

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	proofHex := fs.String("proof", "", "Proof bytes in hex format")
	commitment := fs.String("commitment", "", "Public commitment (decimal string)")
	salt := fs.String("salt", "", "Salt in hex format")
	challenge := fs.Int("challenge", 0, "Challenge value")
	targetYear := fs.Int("year", 2025, "Target year for age verification")
	limitAge := fs.Int("age", 20, "Minimum age requirement")
	fs.Parse(args)

	if *proofHex == "" || *commitment == "" || *salt == "" {
		fmt.Fprintln(os.Stderr, "E1010: Missing required arguments")
		fmt.Fprintln(os.Stderr, "\nUsage: identify-cli verify --proof <hex> --commitment <decimal> --salt <hex> --challenge <int>")
		os.Exit(1)
	}

	proofBytes, err := hex.DecodeString(*proofHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E1001: Invalid proof format: %v\n", err)
		os.Exit(1)
	}

	cfg := common.SharedConfig{
		TargetYear:      *targetYear,
		LimitAge:        *limitAge,
		ArgonMemory:     common.ArgonMemory,
		ArgonIterations: common.ArgonIterations,
	}

	verifier, err := auth.NewVerifierWithConfig(auth.VerifierConfig{Config: cfg})
	if err != nil {
		fmt.Fprintf(os.Stderr, "E1004: Failed to initialize verifier: %v\n", err)
		os.Exit(1)
	}

	ok, err := verifier.VerifyLogin(proofBytes, *commitment, *salt, *challenge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E1003: Verification failed: %v\n", err)
		os.Exit(1)
	}

	if ok {
		fmt.Println("✅ Verification SUCCESS: Proof is valid")
		os.Exit(0)
	} else {
		fmt.Println("❌ Verification FAILED: Proof is invalid")
		os.Exit(1)
	}
}
