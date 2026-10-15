package diff_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
)

// TestFingerprintTree_SyntheticGoMod covers the no-real-go.mod path: loader
// synthesizes a go.mod via overlay so the package resolves through a canonical
// module path instead of falling back to "command-line-arguments".
func TestFingerprintTree_SyntheticGoMod(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package configloader

import "fmt"

func Greet(name string) string {
	return fmt.Sprintf("hello, %s", name)
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	results, meta, err := diff.FingerprintTree(dir, nil, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintTree: %v", err)
	}

	if meta.HadGoMod {
		t.Errorf("expected HadGoMod=false; got true (ModulePath=%q)", meta.ModulePath)
	}
	if !meta.SynthesizedGoMod {
		t.Errorf("expected SynthesizedGoMod=true; got false")
	}
	if !strings.HasPrefix(meta.ModulePath, "synthetic.local/") {
		t.Errorf("expected synthetic ModulePath to start with synthetic.local/; got %q", meta.ModulePath)
	}

	if !containsFunctionLike(results, "Greet") {
		t.Errorf("expected results to include Greet; got %v", funcNamesOf(results))
	}
}

// TestFingerprintTree_RealGoMod covers the path where rootDir has a real
// go.mod: loader uses the declared module path, no synthesis.
func TestFingerprintTree_RealGoMod(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const modulePath = "example.com/treetestreal"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module "+modulePath+"\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	src := `package realmod

func Hi() string { return "hi" }
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	results, meta, err := diff.FingerprintTree(dir, nil, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintTree: %v", err)
	}

	if !meta.HadGoMod {
		t.Errorf("expected HadGoMod=true; got false")
	}
	if meta.SynthesizedGoMod {
		t.Errorf("expected SynthesizedGoMod=false; got true (ModulePath=%q)", meta.ModulePath)
	}
	if meta.ModulePath != modulePath {
		t.Errorf("expected ModulePath=%q; got %q", modulePath, meta.ModulePath)
	}

	if !containsFunctionLike(results, "Hi") {
		t.Errorf("expected results to include Hi; got %v", funcNamesOf(results))
	}
}

// TestFingerprintTree_SiblingFiles confirms tree-mode load pulls in siblings,
// addressing the sibling-symbol-missing failure category from the pilot.
func TestFingerprintTree_SiblingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mainSrc := `package multi

func PublicEntry() int { return helper() }
`
	siblingSrc := `package multi

func helper() int { return 42 }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0o644); err != nil {
		t.Fatalf("write main: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(siblingSrc), 0o644); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	results, meta, err := diff.FingerprintTree(dir, nil, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintTree: %v (loadErrors=%v)", err, meta.LoadErrors)
	}

	if len(meta.LoadErrors) > 0 {
		t.Errorf("expected no load errors; got %v", meta.LoadErrors)
	}
	if !containsFunctionLike(results, "PublicEntry") || !containsFunctionLike(results, "helper") {
		t.Errorf("expected both PublicEntry and helper in results; got %v", funcNamesOf(results))
	}
}

func containsFunctionLike(results []diff.FingerprintResult, needle string) bool {
	for _, r := range results {
		if strings.Contains(r.FunctionName, needle) {
			return true
		}
	}
	return false
}

func funcNamesOf(results []diff.FingerprintResult) []string {
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.FunctionName)
	}
	return names
}

// A module of a workspace loads as the go command builds it: app imports
// lib, which only the go.work provides.
func TestFingerprintTree_Workspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for name, src := range map[string]string{
		"go.work":    "go 1.22\n\nuse (\n\t./app\n\t./lib\n)\n",
		"app/go.mod": "module example.com/app\n\ngo 1.22\n",
		"app/a.go":   "package app\n\nimport \"example.com/lib\"\n\nfunc Twice() int { return 2 * lib.One() }\n",
		"lib/go.mod": "module example.com/lib\n\ngo 1.22\n",
		"lib/l.go":   "package lib\n\nfunc One() int { return 1 }\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	results, _, err := diff.FingerprintTree(filepath.Join(root, "app"), nil, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range results {
		found = found || strings.HasSuffix(r.FunctionName, "app.Twice")
	}
	if !found {
		t.Errorf("app.Twice not fingerprinted: %d results", len(results))
	}
}
