package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// PROOF OF EQUIVALENCE
// The following three functions are syntactically distinct but semantically identical.
// The Semantic Firewall (sfw) proves this by generating identical fingerprints for all three.

// Implementation 1: Idiomatic Go Range Loop
const srcRange = `package main
func sum(items []int) int {
	total := 0
	for _, x := range items {
		total += x
	}
	return total
}
`

// Implementation 2: C-Style Index Loop
const srcIndex = `package main
func sum(items []int) int {
	total := 0
	for i := 0; i < len(items); i++ {
		total += items[i]
	}
	return total
}
`

// Implementation 3: Raw Goto Loop (The "Assembly" Approach)
const srcGoto = `package main
func sum(items []int) int {
	total := 0
	i := 0
loop:
	if i >= len(items) {
		goto done
	}
	total += items[i]
	i++
	goto loop
done:
	return total
}
`

func main() {
	// Use a temporary directory for the virtual files to avoid package name conflicts
	// with the actual project files in the root directory.
	tmpDir := os.TempDir()

	// 1. Analyze

	resRange, err := semanticfw.FingerprintSource(filepath.Join(tmpDir, "range.go"), srcRange, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		log.Fatalf("Failed to analyze range loop: %v", err)
	}

	resIndex, err := semanticfw.FingerprintSource(filepath.Join(tmpDir, "index.go"), srcIndex, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		log.Fatalf("Failed to analyze index loop: %v", err)
	}

	resGoto, err := semanticfw.FingerprintSource(filepath.Join(tmpDir, "goto.go"), srcGoto, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		log.Fatalf("Failed to analyze goto loop: %v", err)
	}

	// 2. Extract Fingerprints
	// We access the first function found in each file (which is 'sum')
	if len(resRange) == 0 || len(resIndex) == 0 || len(resGoto) == 0 {
		log.Fatalf("Analysis returned no functions (parsing failed?)")
	}

	h1 := resRange[0].Fingerprint
	h2 := resIndex[0].Fingerprint
	h3 := resGoto[0].Fingerprint

	// 3. Verify
	fmt.Printf("\n[Semantic Firewall Proof]\n")
	fmt.Printf("1. Range Loop Hash:  %s\n", h1)
	fmt.Printf("2. Index Loop Hash:  %s\n", h2)
	fmt.Printf("3. Goto Loop Hash:   %s\n", h3)

	if h1 == h2 && h2 == h3 {
		fmt.Printf("\n[SUCCESS] All three implementations are logically identical.\n")
		os.Exit(0)
	} else {
		log.Fatalf("\n[FAIL] Logic divergence detected.\n")
	}
}
