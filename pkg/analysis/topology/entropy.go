package topology

import (
	"math"
)

// Returns the Shannon entropy of a byte slice, in bits per byte: 0.0 when
// every byte is the same, 8.0 when all 256 values are equally frequent.
// Encrypted or compressed data is close to 8.
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

// Captures entropy characteristics for malware analysis.
type EntropyProfile struct {
	// Overall is the entropy of the bytes the profile was built from.
	// ExtractTopology builds it from the function's string literals,
	// concatenated, so it equals FunctionTopology.EntropyScore.
	Overall float64

	// Entropy of string literals within the function
	StringLiteralEntropy float64

	// Entropy classification
	Classification EntropyClass
}

// Categorizes entropy levels for quick analysis.
type EntropyClass int

const (
	EntropyLow    EntropyClass = iota // < 4.0: short or repetitive
	EntropyNormal                     // 4.0-6.5: typical text
	EntropyHigh                       // 6.5-7.5: dense, possibly encoded
	EntropyPacked                     // > 7.5: likely encrypted or compressed
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

// Builds an entropy profile of data and, separately, of each string literal.
func CalculateEntropyProfile(data []byte, stringLiterals []string) EntropyProfile {
	overall := CalculateEntropy(data)

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
