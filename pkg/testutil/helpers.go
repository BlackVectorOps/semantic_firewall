package testutil

import (
	"regexp"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
)

// FindResult searches for a FingerprintResult by function name.
// It supports both exact matches and suffix matches (e.g., "functionName" matches "pkg.functionName").
// Exported for use in external test packages.
func FindResult(results []diff.FingerprintResult, Name string) *diff.FingerprintResult {
	// First try exact match
	for i := range results {
		if results[i].FunctionName == Name {
			return &results[i]
		}
	}
	// Then try suffix match for package-qualified names (e.g., "main" matches "testmod.main")
	for i := range results {
		// Match if the name is the suffix after the last "." for non-method functions
		// or matches with a potential package prefix
		funcName := results[i].FunctionName
		if strings.HasSuffix(funcName, "."+Name) {
			return &results[i]
		}
		// Also handle cases like "(*Type).Method" where we just search for "Method"
		if strings.HasSuffix(funcName, Name) && len(funcName) > len(Name) {
			// Make sure we're at a word boundary
			prevChar := funcName[len(funcName)-len(Name)-1]
			if prevChar == '.' || prevChar == ')' {
				return &results[i]
			}
		}
	}
	return nil
}

// GetFunctionNames extracts function names from results for easier verification.
// Exported for use in external test packages.
func GetFunctionNames(results []diff.FingerprintResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.FunctionName
	}
	return names
}

// CheckIRPattern checks IR against a pattern using regex, abstracting register names.
// Exported for use in external test packages.
func CheckIRPattern(t *testing.T, ir string, pattern string) {
	// 1. Escape the input pattern so regex meta-characters (like [, ], (, )) are treated literally.
	escapedPattern := regexp.QuoteMeta(pattern)

	// 2. Replace the placeholder <vN> with the regex pattern for registers.
	// Regex pattern: (?:[vp]\d+|fv\d+) matches vN, pN, or fvN
	// We must match the escaped version of the placeholder (e.g., \<vN\>).
	placeholder := regexp.QuoteMeta("<vN>")
	regexPattern := strings.ReplaceAll(escapedPattern, placeholder, `(?:[vp]\d+|fv\d+)`)

	// 3. Replace <ANY> with a non-greedy wildcard match for any characters
	anyPlaceholder := regexp.QuoteMeta("<ANY>")
	regexPattern = strings.ReplaceAll(regexPattern, anyPlaceholder, `[^>]+`)

	match, err := regexp.MatchString(regexPattern, ir)
	if err != nil {
		t.Fatalf("Invalid regex pattern generated from: %s\nRegex: %s\nError: %v", pattern, regexPattern, err)
	}
	if !match {
		t.Errorf("Expected pattern not found in IR.\nPattern: %s\nRegex: %s\nActual IR:\n%s", pattern, regexPattern, ir)
	}
}

// ShortFuncName returns the short function name without package prefix.
// Exported for use in external test packages.
func ShortFuncName(fullName string) string {
	return diff.ShortFuncName(fullName)
}

// GenerateTopologyHashExported exports the generateTopologyHash function for testing.
func GenerateTopologyHashExported(topo *topology.FunctionTopology) string {
	return detection.GenerateTopologyHash(topo)
}

// ComputeTopologySimilarityExported exports the computeTopologySimilarity function for testing.
func ComputeTopologySimilarityExported(topo *topology.FunctionTopology, sig detection.Signature) float64 {
	return detection.ComputeTopologySimilarity(topo, sig)
}

// MatchCallsExported exports the matchCalls function for testing.
func MatchCallsExported(topo *topology.FunctionTopology, required []string) (score float64, matched, missing []string) {
	return detection.MatchCalls(topo, required)
}

// FormatEntropyKeyExported exports the formatEntropyKey function for testing.
func FormatEntropyKeyExported(entropy float64, id string) string {
	return pebbledb.FormatEntropyKey(entropy, id)
}
