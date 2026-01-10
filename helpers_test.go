package semanticfw

import (
	"regexp"
	"strings"
	"testing"
)

// findResult searches for a FingerprintResult by function name.
// It supports both exact matches and suffix matches (e.g., "functionName" matches "pkg.functionName").
func findResult(results []FingerprintResult, name string) *FingerprintResult {
	// First try exact match
	for i := range results {
		if results[i].FunctionName == name {
			return &results[i]
		}
	}
	// Then try suffix match for package-qualified names (e.g., "main" matches "testmod.main")
	for i := range results {
		// Match if the name is the suffix after the last "." for non-method functions
		// or matches with a potential package prefix
		funcName := results[i].FunctionName
		if strings.HasSuffix(funcName, "."+name) {
			return &results[i]
		}
		// Also handle cases like "(*Type).Method" where we just search for "Method"
		if strings.HasSuffix(funcName, name) && len(funcName) > len(name) {
			// Make sure we're at a word boundary
			prevChar := funcName[len(funcName)-len(name)-1]
			if prevChar == '.' || prevChar == ')' {
				return &results[i]
			}
		}
	}
	return nil
}

// getFunctionNames extracts function names from results for easier verification.
func getFunctionNames(results []FingerprintResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.FunctionName
	}
	return names
}

// checkIRPattern checks IR against a pattern using regex, abstracting register names.
func checkIRPattern(t *testing.T, ir string, pattern string) {
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
