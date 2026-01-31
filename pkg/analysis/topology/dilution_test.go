package topology_test

import (
	"math"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

func TestEntropyDilution(t *testing.T) {
	t.Parallel()

	// 1. Generate High Entropy String
	// Using all 256 byte values guarantees max entropy (8.0)
	var b []byte
	for i := 0; i < 256; i++ {
		b = append(b, byte(i))
	}
	highEntropyStr := string(b)
	highEntropyScore := topology.CalculateEntropy(b)

	// Verify our test payload is actually high entropy
	if highEntropyScore < 7.9 {
		t.Fatalf("Failed to setup high entropy test payload: got %f, want ~8.0", highEntropyScore)
	}

	// 2. Create Diluted Scenario
	// One high entropy payload + many low entropy strings
	var literals []string
	literals = append(literals, highEntropyStr)

	// Add 50KB of low entropy "junk" (repeating 'a')
	// This simulates an attacker padding code with strings to lower overall entropy
	padding := strings.Repeat("a", 50)
	for i := 0; i < 1000; i++ {
		literals = append(literals, padding)
	}

	// 3. Simulate Old Behavior (Concatenation)
	var sb strings.Builder
	for _, s := range literals {
		sb.WriteString(s)
	}
	concatenatedBytes := []byte(sb.String())
	dilutedEntropy := topology.CalculateEntropy(concatenatedBytes)

	// The concatenated entropy should be severely diluted (dominated by 'a')
	if dilutedEntropy > 2.0 {
		t.Errorf("Test Setup Failed: Dilution didn't lower entropy enough. Got %f", dilutedEntropy)
	}

	// 4. Test New Behavior (Profile Calculation)
	profile := topology.CalculateEntropyProfile(concatenatedBytes, literals)

	// Check if MaxStringEntropy correctly caught the payload
	if math.Abs(profile.MaxStringEntropy-highEntropyScore) > 0.001 {
		t.Errorf("MaxStringEntropy mismatch: got %f, want %f", profile.MaxStringEntropy, highEntropyScore)
	}

	// 5. Verify Robust Score Calculation (as used in ExtractTopology)
	// Logic: score = max(overall, max_string)
	robustScore := math.Max(profile.Overall, profile.MaxStringEntropy)

	if robustScore < 7.9 {
		t.Errorf("Security Fix Failed: Robust score %f did not detect hidden payload (score %f)", robustScore, highEntropyScore)
	} else {
		t.Logf("Success: Diluted entropy was %f, but robust score was %f", dilutedEntropy, robustScore)
	}
}
