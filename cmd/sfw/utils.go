// -- ./cmd/sfw/utils.go --
// utils.go
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// -- Utilities --

func resolveDBPath(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv("SFW_DB_PATH"); env != "" {
		return env
	}
	candidates := []string{
		"./signatures.db",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".sfw", "signatures.db"))
	}
	candidates = append(candidates,
		"/usr/local/share/sfw/signatures.db",
		"/var/lib/sfw/signatures.db",
	)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "./signatures.db"
}

func levenshtein(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)
	if n > m {
		r1, r2 = r2, r1
		n, m = m, n
	}
	current := make([]int, n+1)
	for i := 0; i <= n; i++ {
		current[i] = i
	}
	for j := 1; j <= m; j++ {
		previous := current[0]
		current[0] = j
		for i := 1; i <= n; i++ {
			temp := current[i]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			current[i] = min(min(current[i-1]+1, current[i]+1), previous+cost)
			previous = temp
		}
	}
	return current[n]
}

func suggestCommand(cmd string) string {
	commands := []string{"check", "diff", "audit", "index", "scan", "migrate", "stats"}
	bestMatch := ""
	minDist := 100
	for _, c := range commands {
		dist := levenshtein(cmd, c)
		if dist < minDist {
			minDist = dist
			bestMatch = c
		}
	}
	if minDist <= 2 {
		return bestMatch
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func humanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	// BUG FIX: Prevent panic if exp exceeds available suffixes
	suffixes := "KMGTPE"
	if exp >= len(suffixes) {
		exp = len(suffixes) - 1
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), suffixes[exp])
}

// Recursive file walker
func collectFiles(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.HasSuffix(target, ".go") && !isTestFile(target) {
			return []string{target}, nil
		}
		return nil, nil
	}
	var files []string
	err = filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !isTestFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) >= 8 && base[len(base)-8:] == "_test.go"
}

// Helper to read file safely with size limit
func readSourceFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Check file size first to fail fast on massive files
	info, err := f.Stat()
	if err == nil && info.Size() > MaxSourceFileSize {
		return nil, fmt.Errorf("file exceeds maximum supported size of %d bytes", MaxSourceFileSize)
	}

	return io.ReadAll(io.LimitReader(f, MaxSourceFileSize+1))
}

// loadAndFingerprint reads a file and generates semantic fingerprints.
// Deprecated: Use loadAndFingerprintIsolated for diff operations to avoid package collisions.
func loadAndFingerprint(filename string) ([]semanticfw.FingerprintResult, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	// Use safe reader
	src, err := readSourceFile(absPath)
	if err != nil {
		return nil, err
	}
	return semanticfw.FingerprintSource(absPath, string(src), semanticfw.DefaultLiteralPolicy)
}

// Copies the target file to a unique temporary directory before fingerprinting.
// This prevents "redeclared in this block" errors when 'old.go' and 'new.go'
// are in the same directory and both belong to the same package.
func FingerprintIsolated(filename string) ([]semanticfw.FingerprintResult, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	src, err := readSourceFile(absPath)
	if err != nil {
		return nil, err
	}

	// Create a secure temporary directory
	tmpDir, err := os.MkdirTemp("", "sfw-iso-")
	if err != nil {
		return nil, fmt.Errorf("failed to create isolation dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write the source to the temp dir with the same base name
	baseName := filepath.Base(absPath)
	tmpFile := filepath.Join(tmpDir, baseName)
	if err := os.WriteFile(tmpFile, src, 0600); err != nil {
		return nil, fmt.Errorf("failed to write isolated file: %w", err)
	}

	// Fingerprint the isolated file
	results, err := semanticfw.FingerprintSource(tmpFile, string(src), semanticfw.DefaultLiteralPolicy)
	if err != nil {
		return nil, err
	}

	// Rewrite the filename in the results back to the original path
	// so the user sees the file they asked for, not the temp path.
	for i := range results {
		results[i].Filename = absPath
	}

	return results, nil
}

func shortFunctionName(fullName string) string {
	lastSlash := strings.LastIndex(fullName, "/")
	name := fullName
	if lastSlash >= 0 {
		name = fullName[lastSlash+1:]
	}
	depth := 0
	for i, ch := range name {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '.':
			if depth == 0 {
				return name[i+1:]
			}
		}
	}
	return name
}

func isJSON(path string) bool {
	return strings.HasSuffix(path, ".json")
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
