package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ghdehrl12345/identify_sdk/age"
	"github.com/ghdehrl12345/identify_sdk/auth"
)

func cmdGenerateKeys(args []string) {
	fs := flag.NewFlagSet("generate-keys", flag.ExitOnError)
	output := fs.String("output", ".", "Output directory for key files")
	fs.Parse(args)

	fmt.Println("🔨 [generate-keys] Compiling circuits and generating keys...")

	// Compile auth circuit
	var authCircuit auth.UserCircuit
	authCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &authCircuit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2001: Failed to compile auth circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">> Auth circuit compiled (constraints: %d)\n", authCCS.GetNbConstraints())

	// Compile age circuit
	var ageCircuit age.AgeCircuit
	ageCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ageCircuit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2002: Failed to compile age circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">> Age circuit compiled (constraints: %d)\n", ageCCS.GetNbConstraints())

	// Setup keys
	authPK, authVK, err := groth16.Setup(authCCS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2003: Failed to setup auth keys: %v\n", err)
		os.Exit(1)
	}

	agePK, ageVK, err := groth16.Setup(ageCCS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2004: Failed to setup age keys: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(">> Keys generated successfully")

	// Ensure output directory exists
	if err := os.MkdirAll(*output, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "E2005: Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Write key files
	writeKey := func(path string, writeFn func(io.Writer) (int64, error)) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = writeFn(f)
		return err
	}

	files := map[string]func(io.Writer) (int64, error){
		filepath.Join(*output, "user.pk"): authPK.WriteTo,
		filepath.Join(*output, "user.vk"): authVK.WriteTo,
		filepath.Join(*output, "age.pk"):  agePK.WriteTo,
		filepath.Join(*output, "age.vk"):  ageVK.WriteTo,
	}

	for path, fn := range files {
		if err := writeKey(path, fn); err != nil {
			fmt.Fprintf(os.Stderr, "E2006: Failed to write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf(">> Written: %s\n", path)
	}

	fmt.Println("✅ [generate-keys] All keys generated successfully!")
}
