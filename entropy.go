package semanticfw

import (
	"math"
)

// Returns the Shannon entropy of a byte slice.
// Result ranges from 0.0 (completely uniform/predictable) to 8.0 (maximum randomness).
// High entropy (>7.0) often indicates packed/encrypted code.
// Normal code typically has entropy between 4.5 and 6.5.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies using fixed-size array (faster than map)
	var frequencies [256]int
	for _, b := range data {
		frequencies[b]++
	}

	// Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
	var entropy float64
	total := float64(len(data))

	for _, count := range frequencies {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Returns entropy normalized to 0.0-1.0 range.
// Useful for direct comparison and threshold checks.
func CalculateEntropyNormalized(data []byte) float64 {
	return CalculateEntropy(data) / 8.0
}

// Captures entropy characteristics for malware analysis.
type EntropyProfile struct {
	// Overall entropy of the function body
	Overall float64

	// Entropy of string literals within the function
	StringLiteralEntropy float64

	// Entropy classification
	Classification EntropyClass
}

// Categorizes entropy levels for quick analysis.
type EntropyClass int

const (
	EntropyLow    EntropyClass = iota // < 4.0: Simple/sparse code
	EntropyNormal                     // 4.0-6.5: Typical compiled code
	EntropyHigh                       // 6.5-7.5: Potentially obfuscated
	EntropyPacked                     // > 7.5: Likely packed/encrypted
)

func (c EntropyClass) String() string {
	switch c {
	case EntropyLow:
		return "LOW"
	case EntropyNormal:
		return "NORMAL"
	case EntropyHigh:
		return "HIGH"
	case EntropyPacked:
		return "PACKED"
	default:
		return "UNKNOWN"
	}
}

// Determines the entropy class from a raw entropy value.
func ClassifyEntropy(entropy float64) EntropyClass {
	switch {
	case entropy < 4.0:
		return EntropyLow
	case entropy < 6.5:
		return EntropyNormal
	case entropy < 7.5:
		return EntropyHigh
	default:
		return EntropyPacked
	}
}

// Builds a complete entropy profile for analysis.
func CalculateEntropyProfile(bodyBytes []byte, stringLiterals []string) EntropyProfile {
	overall := CalculateEntropy(bodyBytes)

	// Calculate average entropy of string literals
	var stringEntropy float64
	if len(stringLiterals) > 0 {
		var total float64
		for _, s := range stringLiterals {
			total += CalculateEntropy([]byte(s))
		}
		stringEntropy = total / float64(len(stringLiterals))
	}

	return EntropyProfile{
		Overall:              overall,
		StringLiteralEntropy: stringEntropy,
		Classification:       ClassifyEntropy(overall),
	}
}

// Calculates the absolute difference between two entropy values.
// Used for fuzzy matching: two functions with similar entropy are more likely related.
func EntropyDistance(e1, e2 float64) float64 {
	return math.Abs(e1 - e2)
}

// Returns true if two entropy values are within the given tolerance.
// Default tolerance of 0.5 is recommended for malware family matching.
func EntropyMatch(e1, e2, tolerance float64) bool {
	return EntropyDistance(e1, e2) <= tolerance
}
