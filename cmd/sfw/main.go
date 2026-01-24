// -- ./cmd/sfw/main.go --
// Package main provides the sfw CLI tool for semantic fingerprinting and malware scanning of Go source files.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// -- Main Entry Point --

func main() {
	// Configure help text
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sfw - Semantic Firewall CLI

A Semantic Malware Scanner for Go source files.

Usage:
  sfw check [--strict] <file.go|directory>    Fingerprint a file or recursively scan a directory
  sfw diff <old.go> <new.go>                  Semantic diff between two Go files
  sfw audit <old.go> <new.go> "<message>"     Audit a commit for deception using Semantic Analysis + LLM
  sfw index <file.go> --name <name>           Index a malware sample into the signature database
  sfw scan <file.go|directory> --db <path>    Scan code against the signature database
  sfw migrate --from <json> --to <db>         Migrate JSON signatures to PebbleDB
  sfw stats --db <path>                       Show database statistics

Commands:
  check   Generate semantic fingerprints (Level 1: Signal)
  diff    Compute semantic delta using the Zipper algorithm (Level 2: Context)
  audit   Verify if commit message matches structural code changes (Level 3: Intent)
          Uses internal diff engine and optional LLM API to detect "Lies".
          Flags:
            --api-key     API Key (OpenAI or Gemini). REQUIRED.
            --model       LLM Model (default: gpt-4o, supports gemini-1.5-pro)
            --api-base    Custom API Base URL (for testing/proxying)

  index   Index a reference malware sample (Lab Phase)
  scan    Scan target code for malware signatures (Hunter Phase)
  migrate Migrate legacy JSON database to PebbleDB format
  stats   Display database statistics
  version Display CLI and Engine version
Examples:
  sfw check ./cmd/app
  sfw diff old.go new.go
  sfw audit old.go new.go "fix typo" --api-key sk-...
  sfw index malware.go --name "Beacon_v1" --severity CRITICAL
  sfw scan ./src --db signatures.db
  sfw version
`)
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// -- Flag Definitions --

	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	strictCheck := checkCmd.Bool("strict", false, "Enable strict mode validation")
	checkScan := checkCmd.Bool("scan", false, "Enable security scanning")
	checkDB := checkCmd.String("db", "", "Path to signatures database")

	diffCmd := flag.NewFlagSet("diff", flag.ExitOnError)

	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	auditApiKey := auditCmd.String("api-key", "", "API Key (WARNING: Prefer ENV vars to avoid history leaks)")
	// Security: Default updated to gpt-4o per 2026 standards (Reasoning Optimized)
	auditModel := auditCmd.String("model", "gpt-4o", "LLM Model to use")
	auditApiBase := auditCmd.String("api-base", "", "Custom API Base URL")

	indexCmd := flag.NewFlagSet("index", flag.ExitOnError)
	indexName := indexCmd.String("name", "", "Signature name (required)")
	indexSeverity := indexCmd.String("severity", "HIGH", "Severity level: CRITICAL, HIGH, MEDIUM, LOW")
	indexCategory := indexCmd.String("category", "malware", "Signature category")
	indexDB := indexCmd.String("db", "", "Path to signatures database")

	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanDB := scanCmd.String("db", "", "Path to signatures database")
	scanThreshold := scanCmd.Float64("threshold", 0.75, "Match confidence threshold")
	scanExact := scanCmd.Bool("exact", false, "Use exact topology matching only")
	scanDeps := scanCmd.Bool("deps", false, "Scan imported dependencies")
	scanDepsDepth := scanCmd.String("deps-depth", "direct", "Dependency depth: direct or transitive")

	migrateCmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	migrateFrom := migrateCmd.String("from", "", "Source JSON database path")
	migrateTo := migrateCmd.String("to", "", "Destination PebbleDB database path")

	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)
	statsDB := statsCmd.String("db", "", "Path to PebbleDB database")

	// -- Command Routing --

	switch cmd {
	case "check":
		if err := checkCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if checkCmd.NArg() < 1 {
			checkCmd.Usage()
			os.Exit(1)
		}
		if err := runCheck(checkCmd.Arg(0), *strictCheck, *checkScan, resolveDBPath(*checkDB)); err != nil {
			exitError(err)
		}

	case "diff":
		if err := diffCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if diffCmd.NArg() < 2 {
			diffCmd.Usage()
			os.Exit(1)
		}
		if err := runDiff(diffCmd.Arg(0), diffCmd.Arg(1)); err != nil {
			exitError(err)
		}

	case "audit":
		if err := auditCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if auditCmd.NArg() < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sfw audit <old.go> <new.go> \"<commit message>\"")
			os.Exit(1)
		}
		apiKey := *auditApiKey
		// Security: Warn on flag usage, check env vars if flag is empty
		if apiKey != "" {
			fmt.Fprintln(os.Stderr, "warning: passing API key via flag is insecure; use OPENAI_API_KEY or GEMINI_API_KEY environment variables.")
		} else {
			if strings.HasPrefix(strings.ToLower(*auditModel), "gemini") {
				apiKey = os.Getenv("GEMINI_API_KEY")
			} else {
				apiKey = os.Getenv("OPENAI_API_KEY")
			}
		}

		// Security: Refuse the easy path. No Simulation.
		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "Error: API Key is required for audit. Set --api-key or OPENAI_API_KEY/GEMINI_API_KEY.")
			os.Exit(1)
		}

		exitCode, err := runAudit(os.Stdout, auditCmd.Arg(0), auditCmd.Arg(1), auditCmd.Arg(2), apiKey, *auditModel, *auditApiBase)
		if err != nil {
			exitError(err)
		}
		// Security: Fail with non-zero exit code if LIE or ERROR
		if exitCode != 0 {
			os.Exit(exitCode)
		}

	case "index":
		if err := indexCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if indexCmd.NArg() < 1 || *indexName == "" {
			indexCmd.Usage()
			os.Exit(1)
		}
		if err := runIndex(indexCmd.Arg(0), *indexName, *indexSeverity, *indexCategory, resolveDBPath(*indexDB)); err != nil {
			exitError(err)
		}

	case "scan":
		if err := scanCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if scanCmd.NArg() < 1 {
			scanCmd.Usage()
			os.Exit(1)
		}
		opts := ScanOptions{
			DBPath:    resolveDBPath(*scanDB),
			Threshold: *scanThreshold,
			ExactOnly: *scanExact,
			ScanDeps:  *scanDeps,
			DepsDepth: *scanDepsDepth,
		}
		if err := runScan(scanCmd.Arg(0), opts); err != nil {
			exitError(err)
		}

	case "migrate":
		if err := migrateCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if *migrateFrom == "" || *migrateTo == "" {
			migrateCmd.Usage()
			os.Exit(1)
		}
		if err := runMigrate(*migrateFrom, *migrateTo); err != nil {
			exitError(err)
		}

	case "stats":
		if err := statsCmd.Parse(os.Args[2:]); err != nil {
			exitError(err)
		}
		if err := runStats(resolveDBPath(*statsDB)); err != nil {
			exitError(err)
		}
	case "version":
		fmt.Println("Semantic Firewall CLI")
		// Automatically pulls "v2.4.1" from the build tag, or "(devel)" if running locally
		fmt.Printf("Build: %s\n", semanticfw.EngineVersion())
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		if suggestion := suggestCommand(cmd); suggestion != "" {
			fmt.Fprintf(os.Stderr, "Did you mean '%s'?\n", suggestion)
		}
		flag.Usage()
		os.Exit(1)
	}
}
