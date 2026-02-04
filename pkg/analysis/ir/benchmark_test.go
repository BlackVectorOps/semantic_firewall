package ir_test

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

func compileForBenchmark(b *testing.B, src, funcName string) *ssa.Function {
	b.Helper()
	dir, err := os.MkdirTemp("", "ssa-bench-")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	modPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modPath, []byte("module testmod\n\ngo 1.23\n"), 0644); err != nil {
		b.Fatalf("failed to create go.mod: %v", err)
	}

	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		b.Fatalf("write source: %v", err)
	}

	env := append(os.Environ(), "GO111MODULE=on", "GOPROXY=off", "CGO_ENABLED=0")

	cfg := &packages.Config{
		Dir:  dir,
		Mode: packages.LoadAllSyntax,
		Fset: token.NewFileSet(),
		Env:  env,
	}

	pkgs, err := packages.Load(cfg, "file="+path)
	if err != nil {
		b.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		b.Fatal("compilation errors in test source")
	}

	prog, _, err := ir.BuildSSAFromPackages(pkgs)
	if err != nil {
		b.Fatalf("BuildSSA: %v", err)
	}

	for _, pkg := range pkgs {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if fn.Name() == funcName || strings.HasSuffix(fn.Name(), "."+funcName) {
					return fn
				}
			}
		}
	}

	b.Fatalf("function %q not found in SSA program", funcName)
	return nil
}

func BenchmarkCanonicalizeFunction(b *testing.B) {
	// Source code with various instruction types to exercise different paths
	src := `package main

	func everything(ch chan int, m map[string]interface{}) interface{} {
		// Defer
		defer func() { recover() }()

		res := 0

		// Select
		select {
		case x := <-ch:
			// Map Update & Interface
			m["val"] = x
			res = x
		default:
			// MakeSlice & Go
			go func() { _ = make([]int, 10, 20) }()
			res = 1
		}

		// Type Assert
		if val, ok := m["val"].(int); ok {
			return val * 2
		}

		return res
	}`

	fn := compileForBenchmark(b, src, "everything")
	// Use default policy
	policy := ir.DefaultLiteralPolicy

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Acquire/Release per iteration to simulate real usage
		c := ir.AcquireCanonicalizer(policy)
		c.CanonicalizeFunction(fn)
		ir.ReleaseCanonicalizer(c)
	}
}
