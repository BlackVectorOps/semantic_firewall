package semanticfw

import (
	"fmt"
	"path/filepath"
	"testing"
)

// Verifies that the Authority logic in main.go correctly attests logic.
func TestSemanticAttestation(t *testing.T) {
	// 1. Reference Implementation (Golden Logic)
	const srcSecure = `package main
import "runtime"
func main() {
	key := []byte("secret_entropy")
	defer wipe(key) 
	print(string(key))
}
func wipe(b []byte) {
	for i := range b { b[i] = 0 }
	runtime.KeepAlive(b)
}`

	// 2. Refactored Implementation (Semantic Match)
	// Uses 'entropy' instead of 'key', 'buf' instead of 'b'.
	// This should produce the SAME fingerprint if the canonicalizer works.
	const srcRefactored = `package main
import "runtime"
func main() {
	entropy := []byte("secret_entropy")
	defer wipe(entropy) 
	print(string(entropy))
}
func wipe(buf []byte) {
	for x := range buf { buf[x] = 0 }
	runtime.KeepAlive(buf)
}`

	// 3. Compromised Implementation (Semantic Mismatch)
	const srcInsecure = `package main
func main() {
	key := []byte("secret_entropy")
	print(string(key))
}`

	// Helper to extract the main function result specifically
	getMainResult := func(results []FingerprintResult) *FingerprintResult {
		return findResult(results, "main")
	}

	// Create an isolated environment for the test
	tempDir, cleanup := setupTestEnv(t, "attest-test-")
	defer cleanup()
	targetFile := filepath.Join(tempDir, "main.go")

	// Generate fingerprints
	resSecure, err := FingerprintSource(targetFile, srcSecure, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Failed to fingerprint secure src: %v", err)
	}

	resRefactored, err := FingerprintSource(targetFile, srcRefactored, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Failed to fingerprint refactored src: %v", err)
	}

	resInsecure, err := FingerprintSource(targetFile, srcInsecure, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Failed to fingerprint insecure src: %v", err)
	}

	mainSecure := getMainResult(resSecure)
	mainRefactored := getMainResult(resRefactored)
	mainInsecure := getMainResult(resInsecure)

	if mainSecure == nil || mainRefactored == nil || mainInsecure == nil {
		t.Fatalf("CRITICAL: Fingerprints were not generated for main.")
	}

	hSecure := mainSecure.Fingerprint
	hRefactored := mainRefactored.Fingerprint
	hInsecure := mainInsecure.Fingerprint

	fmt.Printf("\n[+] Semantic Attestation Authority Results:\n")
	fmt.Printf("    Golden Hash:   %s\n", hSecure)
	fmt.Printf("    Target Hash:   %s\n", hRefactored)
	fmt.Printf("    Compromised:   %s\n", hInsecure)

	// Verifies that the Refactored version receives Attestation
	if hSecure == hRefactored {
		fmt.Println("    [OK] Logic verified. Attestation Signature: [SUCCESS]")
	} else {
		// DEBUG: Print the IR diff to understand why it failed
		t.Errorf("FAIL: Syntax changes broke the logic verification.")
		t.Logf("\n--- Golden IR ---\n%s\n", mainSecure.CanonicalIR)
		t.Logf("\n--- Target IR ---\n%s\n", mainRefactored.CanonicalIR)
	}

	// Verifies that the Insecure version fails Attestation
	if hSecure != hInsecure {
		fmt.Println("    [!] Logic mismatch. Attestation Signature: [FAILED]")
	} else {
		t.Errorf("FAIL: Security regression was not detected.")
	}
}
