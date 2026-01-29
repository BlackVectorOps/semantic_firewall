// -- internal/cli/check.go --
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
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

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{"--target", cleanTarget}
		if strictMode {
			args = append(args, "--strict")
		}
		if enableScan {
			args = append(args, "--scan")
		}
		if dbPath != "" {
			args = append(args, "--db", dbPath)
		}

		return SandboxExec(sb, os.Stdout, os.Stderr, "check", args, cleanTarget, dbPath)
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
				fmt.Fprintf(os.Stderr, "warning: could not load json database: %v\n", err)
			} else {
				scanner = js
			}
		} else {
			opts := pebbledb.DefaultPebbleScannerOptions()
			opts.ReadOnly = true
			ps, err := pebbledb.NewPebbleScanner(dbPath, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not open signature database: %v\n", err)
			} else {
				defer ps.Close()
				scanner = ps
			}
		}
	}

	var results []models.FileOutput
	hasErrors := false

	for _, file := range files {
		output := ProcessFile(fsys, file, strictMode, scanner)
		if output.ErrorMessage != "" {
			hasErrors = true
		}
		results = append(results, output)
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

	// Use helper to read with limit
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
