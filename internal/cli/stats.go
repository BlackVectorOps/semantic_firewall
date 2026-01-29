// -- internal/cli/stats.go --
package cli

import (
	"encoding/json"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
)

func RunStats(dbPath string) error {
	fsys := RealFileSystem{}
	fileSize, _ := GetPathSize(fsys, dbPath)

	if IsJSON(dbPath) {
		scanner := jsondb.NewScanner()
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return err
		}
		db := scanner.GetDatabase()
		output := struct {
			Database          string `json:"database"`
			Backend           string `json:"backend"`
			Version           string `json:"version"`
			SignatureCount    int    `json:"signature_count"`
			TopoIndexCount    int    `json:"topology_index_count,omitempty"`
			EntropyIndexCount int    `json:"entropy_index_count,omitempty"`
			FileSizeBytes     int64  `json:"file_size_bytes"`
			FileSizeHuman     string `json:"file_size_human"`
		}{
			Database:       dbPath,
			Backend:        "json",
			Version:        db.Version,
			SignatureCount: len(db.Signatures),
			FileSizeBytes:  fileSize,
			FileSizeHuman:  HumanizeBytes(fileSize),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	opts := pebbledb.DefaultPebbleScannerOptions()
	opts.ReadOnly = true
	scanner, err := pebbledb.NewPebbleScanner(dbPath, opts)
	if err != nil {
		return err
	}
	defer scanner.Close()

	stats, err := scanner.Stats()
	if err != nil {
		return err
	}

	output := struct {
		Database          string `json:"database"`
		Backend           string `json:"backend"`
		SignatureCount    int    `json:"signature_count"`
		TopoIndexCount    int    `json:"topology_index_count"`
		EntropyIndexCount int    `json:"entropy_index_count"`
		FileSizeBytes     int64  `json:"file_size_bytes"`
		FileSizeHuman     string `json:"file_size_human"`
	}{
		Database:          dbPath,
		Backend:           "pebbledb",
		SignatureCount:    stats.SignatureCount,
		TopoIndexCount:    stats.TopoIndexCount,
		EntropyIndexCount: stats.EntropyIndexCount,
		FileSizeBytes:     fileSize,
		FileSizeHuman:     HumanizeBytes(fileSize),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
