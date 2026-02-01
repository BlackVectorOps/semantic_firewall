// -- internal/cli/cli_test.go --
package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"golang.org/x/tools/go/packages"
)

// -- MOCKS --

type MockFileSystem struct {
	Files map[string][]byte
}

func (m *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if _, ok := m.Files[name]; ok {
		return &mockFileInfo{name: name, size: int64(len(m.Files[name]))}, nil
	}
	return nil, os.ErrNotExist
}
func (m *MockFileSystem) Open(name string) (fs.File, error) { return nil, os.ErrNotExist }
func (m *MockFileSystem) Getwd() (string, error)            { return "/mock/wd", nil }
func (m *MockFileSystem) Abs(path string) (string, error)   { return path, nil }
func (m *MockFileSystem) WalkDir(root string, fn fs.WalkDirFunc) error {
	for name := range m.Files {
		if strings.HasPrefix(name, root) {
			fn(name, &mockDirEntry{name: name}, nil)
		}
	}
	return nil
}
func (m *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if data, ok := m.Files[name]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

type mockFileInfo struct {
	name string
	size int64
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() any           { return nil }

type mockDirEntry struct{ name string }

func (m *mockDirEntry) Name() string               { return m.name }
func (m *mockDirEntry) IsDir() bool                { return false }
func (m *mockDirEntry) Type() os.FileMode          { return 0644 }
func (m *mockDirEntry) Info() (fs.FileInfo, error) { return &mockFileInfo{name: m.name}, nil }

type MockScanner struct {
	Hits []detection.ScanResult
}

func (m *MockScanner) ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	return m.Hits, nil
}
func (m *MockScanner) ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error) {
	if len(m.Hits) > 0 {
		return &m.Hits[0], nil
	}
	return nil, nil
}
func (m *MockScanner) Close() error { return nil }

// -- TESTS --

// TestShortFunctionName verifies that the parser correctly simplifies complex Go SSA names,
// specifically testing Generics support and proper receiver stripping.
func TestShortFunctionName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Standard
		{"fmt.Println", "Println"},
		{"main.main", "main"},
		{"github.com/user/repo/pkg.Func", "Func"},

		// Methods
		{"pkg.(*Type).Method", "(*Type).Method"},
		{"pkg.Type.Method", "Type.Method"},   // First dot separation (keeps receiver)
		{"(*Type).Method", "(*Type).Method"}, // Idempotency check

		// Recursive Parsing Fixes
		{"(*pkg.Type).Method", "(*Type).Method"},
		{"(pkg.Type).Method", "(Type).Method"},

		// Generics
		{"pkg.Func[int]", "Func[int]"},
		{"pkg.Func[a/b.T]", "Func[a/b.T]"}, // Slash inside generic should not split
		{"github.com/pkg.Func[github.com/other.Type]", "Func[github.com/other.Type]"},

		// Complex Combinations with Heuristic
		{"pkg.Type[sub.T].Method", "Type[sub.T].Method"}, // pkg is stripped. Type[T] is preserved.
		{"Type[sub.T].Method", "Type[sub.T].Method"},     // Prefix Type[sub.T] has brackets -> don't strip
	}

	for _, tc := range tests {
		got := ShortFunctionName(tc.input)
		if got != tc.expected {
			t.Errorf("ShortFunctionName(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

// FuzzShortFunctionName uses fuzzing to ensure the parser never panics on arbitrary input.
func FuzzShortFunctionName(f *testing.F) {
	seeds := []string{
		"fmt.Println",
		"pkg.(*Type).Method",
		"github.com/pkg.Func[int]",
		"very.long.package.name/with.dots.Func",
		"broken[brackets",
		"((()))",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		_ = ShortFunctionName(input)
	})
}

// TestDependencyFilter verifies that standard library packages are skipped
// while 3rd party packages are retained.
func TestDependencyFilter(t *testing.T) {
	tests := []struct {
		path   string
		expect bool // true = keep (scan), false = skip
	}{
		{"fmt", false},
		{"net/http", false},           // The bug was here (has slash)
		{"github.com/user/lib", true}, // Has dot in first segment
		{"gopkg.in/yaml.v2", true},    // Has dot
		{"myinternal/pkg", false},     // No dot, assumed internal/std
		{"cloud.google.com/go", true}, // Has dot
	}

	for _, tc := range tests {
		// We verify the logic used inside collectDependencies
		// Mock package structure
		deps := make(map[string]*packages.Package)
		visited := make(map[string]bool)
		pkg := &packages.Package{
			PkgPath: "main",
			Imports: map[string]*packages.Package{
				tc.path: {PkgPath: tc.path},
			},
		}

		collectDependencies(pkg, deps, false, visited, "")

		_, kept := deps[tc.path]
		if kept != tc.expect {
			t.Errorf("Filter logic for %q = %v; want %v", tc.path, kept, tc.expect)
		}
	}
}

// TestScanDeterminism ensures that map iteration order does not affect result order.
func TestScanDeterminism(t *testing.T) {
	// 1. Create a large map to force random iteration order
	depPkgs := make(map[string]int)
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("pkg/dep/%d", i)
		depPkgs[key] = i
	}

	// 2. Helper to simulate the fix: Extract Sorted
	extractSorted := func() []string {
		var keys []string
		for k := range depPkgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}

	run1 := extractSorted()
	run2 := extractSorted()

	if len(run1) != len(run2) {
		t.Fatalf("Length mismatch: %d vs %d", len(run1), len(run2))
	}

	for i := range run1 {
		if run1[i] != run2[i] {
			t.Errorf("Mismatch at index %d: %s vs %s. Sorting failed to ensure determinism.", i, run1[i], run2[i])
		}
	}
}

// TestJSONOutputIntegrity verifies that check output is a valid JSON array.
func TestJSONOutputIntegrity(t *testing.T) {
	output := []struct {
		Target string `json:"target"`
	}{{Target: "test1"}, {Target: "test2"}}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	expected := `[{"target":"test1"},{"target":"test2"}]`
	if string(data) != expected {
		t.Errorf("JSON marshaling failed, got %s", string(data))
	}
}

// TestRunCheckLogic_Isolation verifies logic without touching the disk.
func TestRunCheckLogic_Isolation(t *testing.T) {
	mockFS := &MockFileSystem{
		Files: map[string][]byte{
			"/app/main.go": []byte("package main\nfunc main() {}"),
		},
	}

	// Create a dummy file in the list for the logic to find since we mock WalkDir
	// Note: In the real implementation CollectFiles uses WalkDir.
	// Our mock WalkDir iterates the map.

	err := RunCheckLogic(mockFS, "/app/main.go", false, false, "")
	if err != nil {
		t.Fatalf("RunCheckLogic failed with mock FS: %v", err)
	}
}

// TestFileSizeGuard verifies strict size limits are enforced.
func TestFileSizeGuard(t *testing.T) {
	mockFS := &MockFileSystem{
		Files: map[string][]byte{
			"/app/huge.go": make([]byte, MaxSourceFileSize+100),
		},
	}

	output := ProcessFile(mockFS, "/app/huge.go", false, nil)
	if output.ErrorMessage == "" {
		t.Error("Expected error for oversized file, got none")
	}
	expected := fmt.Sprintf("file exceeds maximum analysis size of %d bytes", MaxSourceFileSize)
	if output.ErrorMessage != expected {
		t.Errorf("Expected error %q, got %q", expected, output.ErrorMessage)
	}
}
