package main

import (
	"fmt"
	"os"
)

const version = "2.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate-keys":
		cmdGenerateKeys(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "version":
		cmdVersion()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`identify-cli - ZKP Security Toolkit

Usage:
  identify-cli <command> [options]

Commands:
  generate-keys   Generate proving and verifying keys
  verify          Verify a ZKP proof
  version         Show version information
  help            Show this help message

Examples:
  identify-cli generate-keys --output ./keys
  identify-cli verify --proof proof.hex --commitment "123..." --salt "abc..." --challenge 4242
  identify-cli version

Run 'identify-cli <command> --help' for more information on a command.`)
}
