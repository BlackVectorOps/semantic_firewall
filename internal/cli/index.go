// -- internal/cli/index.go --
package cli

import (
	"encoding/json"
	"fmt"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pebbledb"
	"golang.org/x/tools/go/ssa"
)

func RunIndex(target, name, severity, category, dbPath string) error {
	fsys := RealFileSystem{}
	files, err := CollectFiles(fsys, target)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	results := fingerprintFiles(fsys, files)
	if len(results) == 0 {
		return fmt.Errorf("no functions found to index in %s", target)
	}

	var indexed []detection.Signature
	var totalSigs int
	isJSON := IsJSON(dbPath)

	if !isJSON {
		indexed, totalSigs, err = RunIndexPebble(results, name, severity, category, dbPath)
	} else {
		indexed, totalSigs, err = RunIndexJSON(results, name, severity, category, dbPath)
	}
	if err != nil {
		return err
	}

	output := struct {
		Message   string                `json:"message"`
		Indexed   []detection.Signature `json:"indexed"`
		Database  string                `json:"database"`
		TotalSigs int                   `json:"total_signatures"`
		Backend   string                `json:"backend"`
	}{
		Message:   fmt.Sprintf("Indexed %d functions from %s", len(indexed), target),
		Indexed:   indexed,
		Database:  dbPath,
		TotalSigs: totalSigs,
		Backend:   map[bool]string{true: models.BackendJSON, false: models.BackendPebbleDB}[isJSON],
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func RunIndexPebble(results []diff.FingerprintResult, name, severity, category, dbPath string) ([]detection.Signature, int, error) {
	scanner, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		return nil, 0, err
	}
	defer scanner.Close()

	existingCount, err := scanner.CountSignatures()
	if err != nil {
		return nil, 0, err
	}
	var sigs []detection.Signature

	catRunes := []rune(category)
	catShort := category
	if len(catRunes) > 3 {
		catShort = string(catRunes[:3])
	}

	processedCount := 0
	for _, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := topology.ExtractTopology(fn)
		if topo == nil || isImportOnlyInit(fn, topo) {
			continue
		}

		processedCount++
		funcName := resultName(result)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(result.Filename))

		sig := detection.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d-%d", strings.ToUpper(catShort), time.Now().Unix(), existingCount+processedCount)
		sig.Metadata = detection.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}
		sigs = append(sigs, sig)
	}

	var sigPtrs []*detection.Signature
	for i := range sigs {
		sigPtrs = append(sigPtrs, &sigs[i])
	}

	if err := scanner.AddSignatures(sigPtrs); err != nil {
		return nil, 0, err
	}
	finalCount, err := scanner.CountSignatures()
	if err != nil {
		return nil, 0, fmt.Errorf("count signatures: %w", err)
	}
	return sigs, finalCount, nil
}

func RunIndexJSON(results []diff.FingerprintResult, name, severity, category, dbPath string) ([]detection.Signature, int, error) {
	scanner := jsondb.NewScanner()
	if _, err := os.Stat(dbPath); err == nil {
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return nil, 0, err
		}
	}

	catRunes := []rune(category)
	catShort := category
	if len(catRunes) > 3 {
		catShort = string(catRunes[:3])
	}

	initialCount, err := scanner.CountSignatures()
	if err != nil {
		return nil, 0, fmt.Errorf("count signatures: %w", err)
	}
	var indexed []detection.Signature

	for _, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := topology.ExtractTopology(fn)
		if topo == nil || isImportOnlyInit(fn, topo) {
			continue
		}

		funcName := resultName(result)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(result.Filename))

		sig := detection.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d-%d", strings.ToUpper(catShort), time.Now().Unix(), initialCount+len(indexed)+1)
		sig.Metadata = detection.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}

		indexed = append(indexed, sig)
	}

	if err := scanner.AddSignatures(indexed); err != nil {
		return nil, 0, err
	}

	if err := scanner.SaveDatabase(dbPath); err != nil {
		return nil, 0, err
	}
	total, err := scanner.CountSignatures()
	if err != nil {
		return nil, 0, fmt.Errorf("count signatures: %w", err)
	}
	return indexed, total, nil
}

// isImportOnlyInit reports whether fn is a package initializer that only runs
// its imports' initializers. Its topology depends on nothing but the import
// set, so a signature built from it matches any package that imports the same
// packages -- an index of a reverse shell would flag every program importing
// net and os/exec.
func isImportOnlyInit(fn *ssa.Function, topo *topology.FunctionTopology) bool {
	return fn.Synthetic == "package initializer" && len(topo.CallTargets) == 0 && len(topo.StringLiterals) == 0
}
