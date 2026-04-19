// Package main implements the VIM command-line interface.
//
// vim-cli is the primary developer-facing tool for querying the
// Vulnerability Inheritance Map graph. This is a pre-alpha build;
// only the "identity" subcommand is functional — it demonstrates
// the trilateral identity layer (pURL + SWHID + TLSH) on local files.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/abduljaleel/vim/pkg/identity"
)

// version is set at build time via -ldflags.
var version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("vim-cli %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	case "identity":
		runIdentity(os.Args[2:])
	case "similarity":
		runSimilarity(os.Args[2:])
	case "query", "lineage", "ingest":
		fmt.Printf("%s: not yet implemented (see docs/rfcs/ for roadmap)\n", os.Args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// runIdentity prints the LineageID of a file, demonstrating the
// trilateral identity resolution layer.
func runIdentity(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli identity <file> [pURL]")
		os.Exit(1)
	}
	content, err := readFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	var pkg *identity.PURL
	if len(args) > 1 {
		p, err := identity.ParsePURL(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "parsing pURL: %v\n", err)
			os.Exit(1)
		}
		pkg = &p
	}

	id := identity.ComputeLineageID(content, pkg)
	fmt.Printf("File:  %s\n", args[0])
	fmt.Printf("Size:  %d bytes\n", len(content))
	fmt.Printf("SWHID: %s\n", id.SWHID.String())
	if id.PURL != nil {
		fmt.Printf("pURL:  %s\n", id.PURL.String())
	}
	if id.HasFuzzy() {
		fmt.Printf("TLSH:  %s\n", id.TLSH.Hex)
	} else {
		fmt.Println("TLSH:  (not computed — input too small or low entropy)")
	}
}

// runSimilarity compares two files and prints their TLSH distance.
func runSimilarity(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli similarity <file1> <file2>")
		os.Exit(1)
	}
	a, err := readFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	b, err := readFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	idA := identity.ComputeLineageID(a, nil)
	idB := identity.ComputeLineageID(b, nil)

	fmt.Printf("%s -> SWHID %s\n", args[0], idA.SWHID.ObjectID)
	fmt.Printf("%s -> SWHID %s\n", args[1], idB.SWHID.ObjectID)

	if idA.ExactMatch(idB) {
		fmt.Println("Result: EXACT match (byte-identical)")
		return
	}

	if !idA.HasFuzzy() || !idB.HasFuzzy() {
		fmt.Println("Result: files differ; TLSH unavailable for at least one input")
		return
	}

	dist, err := idA.TLSH.Distance(idB.TLSH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLSH distance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("TLSH distance: %d\n", dist)
	switch {
	case dist <= 30:
		fmt.Println("Result: HIGH similarity (likely same code, minor edits)")
	case dist <= 100:
		fmt.Println("Result: MODERATE similarity (possibly related / patched variant)")
	default:
		fmt.Println("Result: LOW similarity (likely unrelated)")
	}
}

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func printUsage() {
	fmt.Print(`vim-cli — Vulnerability Inheritance Map CLI

Usage:
  vim-cli <command> [flags]

Commands:
  identity <file> [pURL]   Compute LineageID (SWHID + TLSH + optional pURL)
  similarity <a> <b>       Compare two files via TLSH distance
  query                    Query the lineage graph (pre-alpha, not implemented)
  lineage                  Show lineage for a code unit (pre-alpha)
  ingest                   Ingest data from a source (pre-alpha)
  version                  Print the CLI version
  help                     Show this help

This project is in pre-alpha development.
See https://github.com/abduljaleel/vim
`)
}
