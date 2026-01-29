// -- internal/cli/migrate.go --
package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
)

func RunMigrate(fromPath, toPath string) error {
	scanner, err := pebbledb.NewPebbleScanner(toPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		return err
	}
	defer scanner.Close()

	count, err := scanner.MigrateFromJSON(fromPath)
	if err != nil {
		return err
	}

	output := struct {
		Message string `json:"message"`
		Source  string `json:"source"`
		Dest    string `json:"destination"`
		Count   int    `json:"signatures_migrated"`
	}{
		Message: fmt.Sprintf("Successfully migrated %d signatures", count),
		Source:  fromPath,
		Dest:    toPath,
		Count:   count,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
