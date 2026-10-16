package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v5/internal/cli"
	"github.com/BlackVectorOps/semantic_firewall/v5/internal/llm"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
	version "github.com/BlackVectorOps/semantic_firewall/v5/pkg/version"
)

// Package main provides the sfw CLI tool for semantic fingerprinting and malware scanning of Go source files.

// -- Main Entry Point --

func main() {
	// -- Internal Worker Dispatch --
	// This entry point allows the CLI to act as its own sandboxed worker.
	// It bypasses the standard flag parsing to invoke logic directly.
	if len(os.Args) > 1 && os.Args[1] == "internal-worker" {
		if err := runWorker(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Worker Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// -- Standard CLI --

	// Decide here, not in a worker: a worker uses what its parent decided.
	cli.ConfigureTypeCache()

	// Configure help text
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sfw - Semantic Firewall CLI

A Semantic Malware Scanner for Go source files.

Usage (flags must come before file arguments):
  sfw check [--strict] <file.go|directory>    Fingerprint a file or recursively scan a directory
  sfw diff <old.go> <new.go>                  Semantic diff between two Go files
  sfw diff --batch <pairs-file>               Diff many file pairs, loading each tree once
  sfw deps diff <old-dir> <new-dir>           Diff the dependencies two module trees compile in
  sfw audit <old.go> <new.go> "<message>"     Audit a commit for deception using Semantic Analysis + LLM
  sfw index --name <name> <file.go>           Index a malware sample into the signature database
  sfw scan --db <path> <file.go|directory>    Scan code against the signature database
  sfw migrate --from <json> --to <db>         Migrate JSON signatures to PebbleDB
  sfw stats --db <path>                       Show database statistics

Commands:
  check   Generate semantic fingerprints (Level 1: Signal)
  diff    Compute semantic delta using the Zipper algorithm (Level 2: Context)
  deps    deps diff: compare the third-party code compiled into two trees of a
          module (functions, newly reachable capabilities, unanalyzed files)
  audit   Verify if commit message matches structural code changes (Level 3: Intent)
          Uses internal diff engine and optional LLM API to detect "Lies".
          Flags:
            --api-key     API key for the model's provider. Prefer the
                          ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
                          environment variables. Needed only when the diff has
                          high-risk changes to verify; for Claude models the
                          Anthropic SDK's own credential chain also applies.
            --model       LLM model (default: claude-opus-5-5; also gpt-*, gemini-*)
            --api-base    Custom API Base URL (for testing/proxying)
            --no-sandbox  Disable gVisor/Namespace isolation

  index   Index a reference malware sample (Lab Phase)
  scan    Scan target code for malware signatures (Hunter Phase)
  migrate Migrate legacy JSON database to PebbleDB format
  stats   Display database statistics
  version Display CLI and Engine version
Examples:
  sfw check ./cmd/app
  sfw diff old.go new.go
  sfw deps diff ../base .
  ANTHROPIC_API_KEY=... sfw audit old.go new.go "fix typo"
  sfw index --name "Beacon_v1" --severity CRITICAL malware.go
  sfw scan --db signatures.db ./src
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
	checkNoSandbox := checkCmd.Bool("no-sandbox", false, "Disable gVisor/Namespace isolation")

	diffCmd := flag.NewFlagSet("diff", flag.ExitOnError)
	diffNoSandbox := diffCmd.Bool("no-sandbox", false, "Disable gVisor/Namespace isolation")
	diffBatch := diffCmd.String("batch", "", "File of NUL-terminated old/new path pairs to diff in one run")

	depsDiffCmd := flag.NewFlagSet("deps diff", flag.ExitOnError)
	depsDiffNoSandbox := depsDiffCmd.Bool("no-sandbox", false, "Disable gVisor/Namespace isolation")

	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	auditApiKey := auditCmd.String("api-key", "", "API Key (WARNING: Prefer ENV vars to avoid history leaks)")
	auditModel := auditCmd.String("model", models.ModelClaudeOpus, "LLM model: claude-* (default), gpt-*/o*, or gemini-*")
	auditApiBase := auditCmd.String("api-base", "", "Custom API Base URL")
	auditNoSandbox := auditCmd.Bool("no-sandbox", false, "Disable gVisor/Namespace isolation")

	indexCmd := flag.NewFlagSet("index", flag.ExitOnError)
	indexName := indexCmd.String("name", "", "Signature name (required)")
	indexSeverity := indexCmd.String("severity", "HIGH", "Severity level: CRITICAL, HIGH, MEDIUM, LOW")
	indexCategory := indexCmd.String("category", "malware", "Signature category")
	indexDB := indexCmd.String("db", "", "Path to signatures database")

	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanDB := scanCmd.String("db", "", "Path to signatures database")
	scanThreshold := scanCmd.Float64("threshold", models.DefaultScanThreshold, "Match confidence threshold")
	scanExact := scanCmd.Bool("exact", false, "Use exact topology matching only")
	scanDeps := scanCmd.Bool("deps", false, "Scan imported dependencies")
	scanDepsDepth := scanCmd.String("deps-depth", "direct", "Dependency depth: direct or transitive")
	scanNoSandbox := scanCmd.Bool("no-sandbox", false, "Disable gVisor/Namespace isolation")

	migrateCmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	migrateFrom := migrateCmd.String("from", "", "Source JSON database path")
	migrateTo := migrateCmd.String("to", "", "Destination PebbleDB database path")

	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)
	statsDB := statsCmd.String("db", "", "Path to PebbleDB database")

	// -- Command Routing --

	switch cmd {
	case "check":
		if err := checkCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if checkCmd.NArg() < 1 {
			checkCmd.Usage()
			os.Exit(1)
		}
		if err := cli.RunCheck(checkCmd.Arg(0), *strictCheck, *checkScan, cli.ResolveDBPath(*checkDB), *checkNoSandbox); err != nil {
			cli.ExitError(err)
		}

	case "diff":
		if err := diffCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if *diffBatch != "" {
			if diffCmd.NArg() != 0 {
				fmt.Fprintln(os.Stderr, "Usage: sfw diff --batch <pairs-file> (no positional arguments)")
				os.Exit(1)
			}
			if err := cli.RunDiffBatch(*diffBatch, *diffNoSandbox); err != nil {
				cli.ExitError(err)
			}
			break
		}
		if diffCmd.NArg() < 2 {
			diffCmd.Usage()
			os.Exit(1)
		}
		if err := cli.RunDiff(diffCmd.Arg(0), diffCmd.Arg(1), *diffNoSandbox); err != nil {
			cli.ExitError(err)
		}

	case "deps":
		if len(os.Args) < 3 || os.Args[2] != "diff" {
			fmt.Fprintln(os.Stderr, "Usage: sfw deps diff [--no-sandbox] <old-module-dir> <new-module-dir>")
			os.Exit(1)
		}
		if err := depsDiffCmd.Parse(os.Args[3:]); err != nil {
			cli.ExitError(err)
		}
		if depsDiffCmd.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sfw deps diff [--no-sandbox] <old-module-dir> <new-module-dir>")
			os.Exit(1)
		}
		if err := cli.RunDepsDiff(depsDiffCmd.Arg(0), depsDiffCmd.Arg(1), *depsDiffNoSandbox); err != nil {
			cli.ExitError(err)
		}

	case "audit":
		if err := auditCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if auditCmd.NArg() < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sfw audit <old.go> <new.go> \"<commit message>\"")
			os.Exit(1)
		}
		apiKey := *auditApiKey
		// Warn on flag usage, check env vars if flag is empty
		if apiKey != "" {
			fmt.Fprintln(os.Stderr, "warning: passing API key via flag is insecure; use ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY environment variables.")
		} else {
			apiKey = os.Getenv(llm.APIKeyEnvVar(*auditModel))
		}

		// A key is only needed when the diff contains high-risk changes for
		// the LLM to verify; RunAudit fails closed if one is needed but absent.

		exitCode, err := cli.RunAudit(os.Stdout, auditCmd.Arg(0), auditCmd.Arg(1), auditCmd.Arg(2), apiKey, *auditModel, *auditApiBase, *auditNoSandbox)
		if err != nil {
			cli.ExitError(err)
		}
		// Fail with non-zero exit code if LIE or ERROR
		if exitCode != 0 {
			os.Exit(exitCode)
		}

	case "index":
		if err := indexCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if indexCmd.NArg() < 1 || *indexName == "" {
			indexCmd.Usage()
			os.Exit(1)
		}
		if err := cli.RunIndex(indexCmd.Arg(0), *indexName, *indexSeverity, *indexCategory, cli.ResolveDBPath(*indexDB)); err != nil {
			cli.ExitError(err)
		}

	case "scan":
		if err := scanCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if scanCmd.NArg() < 1 {
			scanCmd.Usage()
			os.Exit(1)
		}
		opts := models.ScanOptions{
			DBPath:    cli.ResolveDBPath(*scanDB),
			Threshold: *scanThreshold,
			ExactOnly: *scanExact,
			ScanDeps:  *scanDeps,
			DepsDepth: *scanDepsDepth,
		}
		if err := cli.RunScan(scanCmd.Arg(0), opts, *scanNoSandbox); err != nil {
			cli.ExitError(err)
		}

	case "migrate":
		if err := migrateCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if *migrateFrom == "" || *migrateTo == "" {
			migrateCmd.Usage()
			os.Exit(1)
		}
		if err := cli.RunMigrate(*migrateFrom, *migrateTo); err != nil {
			cli.ExitError(err)
		}

	case "stats":
		if err := statsCmd.Parse(os.Args[2:]); err != nil {
			cli.ExitError(err)
		}
		if err := cli.RunStats(cli.ResolveDBPath(*statsDB)); err != nil {
			cli.ExitError(err)
		}
	case "version":
		fmt.Println("Semantic Firewall CLI")
		// Automatically pulls "v2.4.1" from the build tag, or "(devel)" if running locally
		fmt.Printf("Build: %s\n", version.EngineVersion())
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		if suggestion := cli.SuggestCommand(cmd); suggestion != "" {
			fmt.Fprintf(os.Stderr, "Did you mean '%s'?\n", suggestion)
		}
		flag.Usage()
		os.Exit(1)
	}
}

// -- Worker Implementation --

// Handles the sandboxed execution logic.
// It reconstructs flags manually because the worker receives raw args.
func runWorker(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no worker command")
	}
	cmd := args[0]
	fsys := cli.RealFileSystem{}
	pkgLoader := cli.RealPackageLoader{}

	switch cmd {
	case "check":
		// Flag parsing mirrors the CLI but routes to RunCheckLogic
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		strict := fs.Bool("strict", false, "")
		scan := fs.Bool("scan", false, "")
		db := fs.String("db", "", "")
		target := fs.String("target", "", "")

		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		// Ensure DB path is resolved even in worker context
		resolvedDB := cli.ResolveDBPath(*db)
		return cli.RunCheckLogic(fsys, *target, *strict, *scan, resolvedDB)

	case "diff":
		// sfw internal-worker diff <old> <new>
		if len(args) != 3 {
			return fmt.Errorf("diff worker requires arguments (old <path> new <path>); got %d", len(args)-1)
		}
		return cli.RunDiffLogic(fsys, os.Stdout, args[1], args[2])

	case "diff-batch":
		// sfw internal-worker diff-batch <pairs-file>
		if len(args) != 2 {
			return fmt.Errorf("diff-batch worker requires a pairs file; got %d arguments", len(args)-1)
		}
		return cli.RunDiffBatchLogic(fsys, os.Stdout, args[1])

	case "deps-diff":
		// sfw internal-worker deps-diff <old-dir> <new-dir>
		if len(args) != 3 {
			return fmt.Errorf("deps-diff worker requires two directories; got %d arguments", len(args)-1)
		}
		return cli.RunDepsDiffLogic(os.Stdout, args[1], args[2])

	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		db := fs.String("db", "", "")
		target := fs.String("target", "", "")
		threshold := fs.Float64("threshold", models.DefaultScanThreshold, "")
		exact := fs.Bool("exact", false, "")
		deps := fs.Bool("deps", false, "")
		depsDepth := fs.String("deps-depth", "direct", "")

		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		opts := models.ScanOptions{
			DBPath:    cli.ResolveDBPath(*db),
			Threshold: *threshold,
			ExactOnly: *exact,
			ScanDeps:  *deps,
			DepsDepth: *depsDepth,
		}
		return cli.RunScanLogic(fsys, pkgLoader, *target, opts)
	}

	return fmt.Errorf("unknown worker cmd: %s", cmd)
}
