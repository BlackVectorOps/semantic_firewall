// -- internal/cli/check.go --
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pebbledb"
	"golang.org/x/sync/errgroup"
)

// -- Public API --

func RunCheck(target string, strictMode bool, enableScan bool, dbPath string, noSandbox bool) error {
	cleanTarget := filepath.Clean(target)
	sb := RealSandboxer{}
	fsys := RealFileSystem{}

	// Resolve database path BEFORE entering the sandbox.
	if enableScan && dbPath == "" {
		dbPath = ResolveDBPath("")
	}
	// Ensure we are working with an absolute path for consistency
	if dbPath != "" {
		if abs, err := filepath.Abs(dbPath); err == nil {
			dbPath = abs
		}
	}

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{"--target", cleanTarget}
		if strictMode {
			args = append(args, "--strict")
		}
		if enableScan {
			args = append(args, "--scan")
		}

		var inputs []string
		inputs = append(inputs, cleanTarget)

		// Only pass DB path if scan mode is enabled and path is non-empty
		if enableScan && dbPath != "" {
			args = append(args, "--db", dbPath)
			inputs = append(inputs, dbPath)
		}

		return SandboxExec(sb, os.Stdout, os.Stderr, "check", args, inputs...)
	}

	return RunCheckLogic(fsys, cleanTarget, strictMode, enableScan, dbPath)
}

// -- Core Logic --

func RunCheckLogic(fsys FileSystem, target string, strictMode bool, enableScan bool, dbPath string) error {
	files, err := CollectFiles(fsys, target)
	if err != nil {
		return fmt.Errorf("collect files failed: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	var scanner SignatureScanner

	if enableScan {
		if IsJSON(dbPath) {
			js := jsondb.NewScanner()
			if err := js.LoadDatabase(dbPath); err != nil {
				return fmt.Errorf("fatal: could not load json database: %w", err)
			}
			scanner = js
		} else {
			// PebbleDB takes a LOCK file even when read-only; the helper
			// makes the database writable inside the sandbox.
			safeDBPath, cleanup, err := PrepareSandboxDB(dbPath)
			if err != nil {
				return fmt.Errorf("fatal: failed to prepare database environment: %w", err)
			}
			defer cleanup()

			opts := pebbledb.DefaultPebbleScannerOptions()
			opts.ReadOnly = true
			ps, err := pebbledb.NewPebbleScanner(safeDBPath, opts)
			if err != nil {
				return fmt.Errorf("fatal: could not open signature database: %w", err)
			}
			defer ps.Close()
			scanner = ps
		}
	}

	results, hasErrors := ProcessFilesParallel(fsys, files, strictMode, scanner)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("json encode failed: %w", err)
	}

	if strictMode && hasErrors {
		return fmt.Errorf("strict mode: errors encountered during processing")
	}

	return nil
}

// -- Processing & Analysis --

// ProcessFilesParallel fingerprints files (see api.FingerprintFiles) and,
// with a scanner, scans each function once: a function listed under
// several files (the package initializer) is scanned under the first. A
// file whose load fails, or whose scan panics, gets an ErrorMessage and
// sets hasErrors.
func ProcessFilesParallel(fsys FileSystem, files []string, strictMode bool, scanner SignatureScanner) ([]models.FileOutput, bool) {
	fingerprints := api.FingerprintFiles(fsys, files, strictMode)

	var (
		results   = make([]models.FileOutput, len(files))
		hasErrors atomic.Bool
		scanned   = make(map[funcKey]bool)
		keys      = funcKeys{}
	)
	g := new(errgroup.Group)
	g.SetLimit(runtime.GOMAXPROCS(0))

	for i, f := range files {
		fp, ok := fingerprints[f]
		if !ok {
			fp.Err = fmt.Errorf("no fingerprint result for %s", f)
		}
		if fp.Err != nil {
			results[i] = models.FileOutput{File: f, ErrorMessage: fp.Err.Error()}
			hasErrors.Store(true)
			continue
		}
		var toScan []diff.FingerprintResult
		if scanner != nil {
			dir := fileDir(f)
			for _, r := range fp.Results {
				if k := keys.of(dir, r); r.GetSSAFunction() != nil && !scanned[k] {
					scanned[k] = true
					toScan = append(toScan, r)
				}
			}
		}
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "warning: panic recovered analyzing %s: %v\n", f, r)
					results[i] = models.FileOutput{File: f, ErrorMessage: fmt.Sprintf("panic during analysis: %v", r)}
					hasErrors.Store(true)
				}
			}()
			results[i] = fileOutput(f, fp.Results, toScan, scanner)
			if results[i].ErrorMessage != "" {
				hasErrors.Store(true)
			}
			return nil
		})
	}
	_ = g.Wait()

	return results, hasErrors.Load()
}

// fileOutput lists a file's fingerprinted functions and the alerts for the
// functions of toScan. A panic scanning one function is the file's
// ErrorMessage; the file's other functions are still scanned, since some of
// them (the package initializer) are scanned under this file only.
func fileOutput(filename string, results, toScan []diff.FingerprintResult, scanner SignatureScanner) models.FileOutput {
	output := models.FileOutput{
		File:      filename,
		Functions: make([]models.FunctionFingerprint, 0, len(results)),
	}
	for _, r := range results {
		output.Functions = append(output.Functions, models.FunctionFingerprint{
			Function:    r.FunctionName,
			Fingerprint: r.Fingerprint,
			File:        r.Filename,
			Line:        r.Line,
		})
	}
	for _, r := range toScan {
		alerts, panicked := scanResult(r, scanner)
		if panicked != nil {
			fmt.Fprintf(os.Stderr, "warning: panic recovered analyzing %s in %s: %v\n", r.FunctionName, filename, panicked)
			if output.ErrorMessage == "" {
				output.ErrorMessage = fmt.Sprintf("panic during analysis: %v", panicked)
			}
		}
		output.ScanResults = append(output.ScanResults, alerts...)
	}
	return output
}

// scanResult scans one function, returning a panic's value instead of
// propagating it.
func scanResult(r diff.FingerprintResult, scanner SignatureScanner) (alerts []detection.ScanResult, panicked any) {
	defer func() { panicked = recover() }()
	topo := extractTopology(r.GetSSAFunction())
	if topo == nil {
		return nil, nil
	}
	alerts, err := scanner.ScanTopology(topo, resultName(r))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error scanning topology for %s: %v\n", r.FunctionName, err)
		return nil, nil
	}
	return alerts, nil
}
