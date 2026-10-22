package ir_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"golang.org/x/tools/go/packages"
)

// BuildProgram fails, naming the package's errors, when the first package
// is ill-typed: SSA would build nothing for it, and an empty program would
// read as a package without functions.
func TestBuildProgram_IllTypedFirstPackage(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"go.mod": "module m\n\ngo 1.22\n",
		"m.go":   "package m\n\nfunc F() int { return undefined }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkgs, err := packages.Load(&packages.Config{Dir: dir, Mode: packages.LoadAllSyntax, Env: diff.HardenedEnvFor(dir)}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.BuildProgram(pkgs); err == nil || !strings.Contains(err.Error(), "undefined") {
		t.Errorf("BuildProgram = %v; want an error naming the type error", err)
	}
	if _, _, err := ir.BuildSSAFromPackages(pkgs); err == nil {
		t.Error("BuildSSAFromPackages succeeded on an ill-typed package")
	}
}
