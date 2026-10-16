package testutil

import "github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"

// GetFunctionNames extracts function names from results for easier verification.
// Exported for use in external test packages.
func GetFunctionNames(results []diff.FingerprintResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.FunctionName
	}
	return names
}
