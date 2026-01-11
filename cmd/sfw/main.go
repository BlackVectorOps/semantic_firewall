// Package main provides the sfw CLI tool for semantic fingerprinting of Go source files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	semanticfw "github.com/BlackVectorOps/semantic_firewall"
)

// FunctionFingerprint represents the JSON output for a single function.
type FunctionFingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

// FileOutput represents the JSON output for a single file.
type FileOutput struct {
	File         string                `json:"file"`
	Functions    []FunctionFingerprint `json:"functions"`
	ErrorMessage string                `json:"error,omitempty"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sfw - Semantic Firewall CLI

Generate semantic fingerprints for Go source files.

Usage:
  sfw check <file.go|directory>    Fingerprint a file or all .go files in a directory

Examples:
  sfw check main.go                Fingerprint a single file
  sfw check ./pkg/                 Fingerprint all Go files in a directory
  sfw check .                      Fingerprint current directory

Output:
  JSON to stdout, one object per file.

`)
	}

	if len(os.Args) < 3 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	target := os.Args[2]

	switch cmd {
	case "check":
		if err := runCheck(target); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

func runCheck(target string) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", target, err)
	}

	var files []string

	if info.IsDir() {
		entries, err := filepath.Glob(filepath.Join(target, "*.go"))
		if err != nil {
			return fmt.Errorf("glob failed: %w", err)
		}
		// Filter out test files
		for _, f := range entries {
			if !isTestFile(f) {
				files = append(files, f)
			}
		}
	} else {
		files = []string{target}
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	for _, file := range files {
		output := processFile(file)
		if err := encoder.Encode(output); err != nil {
			return fmt.Errorf("json encode failed: %w", err)
		}
	}

	return nil
}

func processFile(filename string) FileOutput {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	f, err := os.Open(absPath)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	results, err := semanticfw.FingerprintSource(absPath, string(src), semanticfw.DefaultLiteralPolicy)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	output := FileOutput{
		File:      filename,
		Functions: make([]FunctionFingerprint, 0, len(results)),
	}

	for _, r := range results {
		output.Functions = append(output.Functions, FunctionFingerprint{
			Function:    r.FunctionName,
			Fingerprint: r.Fingerprint,
			File:        r.Filename,
			Line:        r.Line,
		})
	}

	return output
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) > 8 && base[len(base)-8:] == "_test.go"
}
