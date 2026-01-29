// -- internal/cli/index.go --
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
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

	var results []diff.FingerprintResult
	for _, file := range files {
		res, err := LoadAndFingerprint(fsys, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", file, err)
			continue
		}
		results = append(results, res...)
	}

	if len(results) == 0 {
		return fmt.Errorf("no functions found to index in %s", target)
	}

	var indexed []detection.Signature
	var totalSigs int
	isJSON := IsJSON(dbPath)

	if !isJSON {
		indexed, totalSigs, err = RunIndexPebble(target, results, name, severity, category, dbPath)
	} else {
		indexed, totalSigs, err = RunIndexJSON(target, results, name, severity, category, dbPath)
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
		Backend:   map[bool]string{true: "json", false: "pebbledb"}[isJSON],
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func RunIndexPebble(target string, results []diff.FingerprintResult, name, severity, category, dbPath string) ([]detection.Signature, int, error) {
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
		if topo == nil {
			continue
		}

		processedCount++
		funcName := ShortFunctionName(result.FunctionName)
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
	finalCount, _ := scanner.CountSignatures()
	return sigs, finalCount, nil
}

func RunIndexJSON(target string, results []diff.FingerprintResult, name, severity, category, dbPath string) ([]detection.Signature, int, error) {
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

	initialCount := len(scanner.GetDatabase().Signatures)
	var indexed []detection.Signature

	for _, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := topology.ExtractTopology(fn)
		if topo == nil {
			continue
		}

		funcName := ShortFunctionName(result.FunctionName)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(result.Filename))

		sig := detection.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d-%d", strings.ToUpper(catShort), time.Now().Unix(), initialCount+len(indexed)+1)
		sig.Metadata = detection.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}

		scanner.AddSignature(&sig)
		indexed = append(indexed, sig)
	}

	if err := scanner.SaveDatabase(dbPath); err != nil {
		return nil, 0, err
	}
	return indexed, len(scanner.GetDatabase().Signatures), nil
}
