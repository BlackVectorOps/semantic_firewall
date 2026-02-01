// -- internal/cli/check.go --
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
	"golang.org/x/sync/errgroup"
)

// -- Constants --

const (
	MaxSourceFileSize = 10 * 1024 * 1024
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
			// Stability Fix: Use shared helper to ensure DB is writable in sandbox.
			// PebbleDB requires a LOCK file even for read-only access.
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

	// Efficiency Upgrade: Execute analysis in parallel
	results, hasErrors, err := ProcessFilesParallel(fsys, files, strictMode, scanner)
	if err != nil {
		return err
	}

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

func ProcessFilesParallel(fsys FileSystem, files []string, strictMode bool, scanner SignatureScanner) ([]models.FileOutput, bool, error) {
	var (
		results   = make([]models.FileOutput, len(files))
		hasErrors bool
		mu        sync.Mutex
	)

	g, ctx := errgroup.WithContext(context.Background())
	// Limit concurrency to avoid thrashing on smaller instances
	g.SetLimit(runtime.GOMAXPROCS(0))

	for i, file := range files {
		idx := i
		f := file
		g.Go(func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Robustness: Recover from panics in SSA generation to protect the run
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "warning: panic recovered analyzing %s: %v\n", f, r)
				}
			}()

			output := ProcessFile(fsys, f, strictMode, scanner)

			mu.Lock()
			results[idx] = output
			if output.ErrorMessage != "" {
				hasErrors = true
			}
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, false, err
	}

	return results, hasErrors, nil
}

func ProcessFile(fsys FileSystem, filename string, strictMode bool, scanner SignatureScanner) models.FileOutput {
	absPath, err := fsys.Abs(filename)
	if err != nil {
		return models.FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	info, err := fsys.Stat(absPath)
	if err != nil {
		return models.FileOutput{File: filename, ErrorMessage: "stat failed: " + err.Error()}
	}
	if info.Size() > MaxSourceFileSize {
		return models.FileOutput{
			File:         filename,
			ErrorMessage: fmt.Sprintf("file exceeds maximum analysis size of %d bytes", MaxSourceFileSize),
		}
	}

	src, err := fsys.ReadFile(absPath)
	if err != nil {
		return models.FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	results, err := diff.FingerprintSourceAdvanced(absPath, string(src), ir.DefaultLiteralPolicy, strictMode)
	if err != nil {
		return models.FileOutput{File: filename, ErrorMessage: err.Error()}
	}

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

		if scanner != nil {
			fn := r.GetSSAFunction()
			if fn != nil {
				topo := topology.ExtractTopology(fn)
				if topo != nil {
					alerts, scanErr := scanner.ScanTopology(topo, r.FunctionName)
					if scanErr == nil {
						output.ScanResults = append(output.ScanResults, alerts...)
					} else {
						fmt.Fprintf(os.Stderr, "error scanning topology for %s: %v\n", r.FunctionName, scanErr)
					}
				}
			}
		}
	}

	return output
}
