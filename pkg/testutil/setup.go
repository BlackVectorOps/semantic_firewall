package testutil

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// SetupTestEnv creates an isolated workspace with a valid go.mod.
// Returns the directory path and a cleanup function.
func SetupTestEnv(t *testing.T, prefix string) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	modPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modPath, []byte("module testmod\n\ngo 1.23\n"), 0644); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("failed to create go.mod: %v", err)
	}

	return dir, func() { os.RemoveAll(dir) }
}

// CompileAndGetFunction builds SSA from source and returns the requested function.
// This allows low-level analysis packages to be tested in isolation.
func CompileAndGetFunction(t *testing.T, src, funcName string) *ssa.Function {
	t.Helper()
	dir, cleanup := SetupTestEnv(t, "ssa-build-")
	defer cleanup()

	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	// Replicate the hardened environment used by the engine
	env := append(os.Environ(), "GO111MODULE=on", "GOPROXY=off", "CGO_ENABLED=0")

	cfg := &packages.Config{
		Dir:  dir,
		Mode: packages.LoadAllSyntax,
		Fset: token.NewFileSet(),
		Env:  env,
	}

	pkgs, err := packages.Load(cfg, "file="+path)
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("compilation errors in test source")
	}

	// Use the IR package builder to ensure consistent SSA construction
	prog, _, err := ir.BuildSSAFromPackages(pkgs)
	if err != nil {
		t.Fatalf("BuildSSA: %v", err)
	}

	for _, pkg := range pkgs {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				// Match simple name or package-qualified name
				if fn.Name() == funcName || strings.HasSuffix(fn.Name(), "."+funcName) {
					return fn
				}
			}
		}
	}

	t.Fatalf("function %q not found in SSA program", funcName)
	return nil
}
