package diff

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff/internal/purge"
)

// loaderSnapshot renders what the analysis derives from a load: every root
// package's ID, IllTyped flag and errors, and for every function of the
// well-typed roots its name, position, fingerprint and complete topology.
// Two loads whose snapshots match give identical fingerprints and alerts.
func loaderSnapshot(t *testing.T, roots []*packages.Package) []string {
	t.Helper()
	sorted := append([]*packages.Package(nil), roots...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var lines, functions []string
	var wellTyped []*packages.Package
	for _, p := range sorted {
		lines = append(lines, fmt.Sprintf("package %s illTyped=%v", p.ID, p.IllTyped))
		for _, e := range p.Errors {
			lines = append(lines, fmt.Sprintf("  error %s", e))
		}
		if !p.IllTyped {
			wellTyped = append(wellTyped, p)
		}
	}
	if len(wellTyped) > 0 {
		results, err := FingerprintPackages(wellTyped, ir.DefaultLiteralPolicy, false)
		if err != nil {
			lines = append(lines, "fingerprint error "+err.Error())
		}
		for _, r := range results {
			topo, _ := json.Marshal(topology.ExtractTopology(r.GetSSAFunction()))
			functions = append(functions, fmt.Sprintf("func %s %s:%d %s %s", r.FunctionName, r.Filename, r.Line, r.Fingerprint, topo))
		}
	}
	sort.Strings(functions)
	return append(lines, functions...)
}

// assertLoadersAgree loads patterns with go/packages and three times with
// loadSource (the later runs reuse cached dependencies) and requires
// identical snapshots. It returns the snapshot.
func assertLoadersAgree(t *testing.T, mkcfg func() *packages.Config, patterns ...string) []string {
	t.Helper()
	t.Setenv(LoaderEnvVar, "")
	want, err := packages.Load(mkcfg(), patterns...)
	if err != nil {
		t.Fatalf("go/packages: %v", err)
	}
	wantSnap := loaderSnapshot(t, want)
	for run := 1; run <= 3; run++ {
		got, err := loadSource(mkcfg(), patterns...)
		if err != nil {
			t.Fatalf("loadSource run %d: %v", run, err)
		}
		if diff := firstDifference(wantSnap, loaderSnapshot(t, got)); diff != "" {
			t.Fatalf("loadSource run %d differs from go/packages: %s", run, diff)
		}
	}
	return wantSnap
}

func firstDifference(want, got []string) string {
	for i := 0; i < len(want) || i < len(got); i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			return fmt.Sprintf("line %d:\n  go/packages: %.400s\n  loadSource:  %.400s", i, w, g)
		}
	}
	return ""
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// goSumLines returns this repository's go.sum lines for a module version.
func goSumLines(t *testing.T, modVersion string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), modVersion+" ") || strings.HasPrefix(sc.Text(), modVersion+"/go.mod ") {
			out = append(out, sc.Text())
		}
	}
	if len(out) != 2 {
		t.Fatalf("go.sum has %d lines for %s; want 2", len(out), modVersion)
	}
	return strings.Join(out, "\n") + "\n"
}

func mustContain(t *testing.T, snap []string, wants ...string) {
	t.Helper()
	joined := strings.Join(snap, "\n")
	for _, w := range wants {
		if !strings.Contains(joined, w) {
			t.Errorf("snapshot lacks %q", w)
		}
	}
}

// A module with a local replacement, a pinned third-party module, build
// tags, GOOS files, cross-package generics and the standard library.
func TestLoadSource_ModuleParity(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.25.0\n\nrequire (\n\texample.com/dep v1.0.0\n\tgolang.org/x/sync v0.22.0\n)\n\nreplace example.com/dep => ./dep\n",
		"go.sum":     goSumLines(t, "golang.org/x/sync v0.22.0"),
		"dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"dep/list.go": "package dep\n\nimport \"sort\"\n\n// List is a generic list.\ntype List[T any] struct{ items []T }\n\nfunc (l *List[T]) Push(v T) { l.items = append(l.items, v) }\n\n" +
			"func Map[A, B any](xs []A, f func(A) B) []B {\n\tout := make([]B, 0, len(xs))\n\tfor _, x := range xs {\n\t\tout = append(out, f(x))\n\t}\n\treturn out\n}\n\n" +
			"func Sorted(xs []int) []int { sort.Ints(xs); return xs }\n\nvar Table = map[string]int{\"a\": 1, \"b\": 2}\n\nvar Handler = func(s string) int { return len(s) }\n",
		"dep/os_linux.go":   "package dep\n\nconst OS = \"linux\"\n",
		"dep/os_windows.go": "package dep\n\nconst OS = \"windows\"\n",
		"dep/os_other.go":   "//go:build !linux && !windows\n\npackage dep\n\nconst OS = \"other\"\n",
		"dep/tagged.go":     "//go:build sfwtag\n\npackage dep\n\nfunc Tagged() string { return \"tag\" }\n",
		"p/p.go": "package p\n\nimport (\n\t\"context\"\n\t\"crypto/hmac\"\n\t\"fmt\"\n\t\"net\"\n\t\"os\"\n\n\t\"example.com/dep\"\n\t\"golang.org/x/sync/errgroup\"\n)\n\n" +
			"type Pair[K comparable, V any] struct {\n\tK K\n\tV V\n}\n\n" +
			"func Keys[K comparable, V any](ps []Pair[K, V]) []K { return dep.Map(ps, func(p Pair[K, V]) K { return p.K }) }\n\n" +
			"func Run(ctx context.Context, addrs []string, key, mac []byte) error {\n\tif !hmac.Equal(key, mac) {\n\t\treturn fmt.Errorf(\"denied\")\n\t}\n\tg, ctx := errgroup.WithContext(ctx)\n\tvar l dep.List[string]\n\tfor _, a := range addrs {\n\t\tl.Push(a)\n\t\tg.Go(func() error {\n\t\t\tc, err := net.Dial(\"tcp\", a)\n\t\t\tif err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\treturn c.Close()\n\t\t})\n\t}\n\tif dep.OS == \"linux\" {\n\t\tos.RemoveAll(addrs[0])\n\t}\n\treturn g.Wait()\n}\n",
		"q/q.go": "package q\n\nimport \"example.com/m/p\"\n\nfunc Use() []string { return p.Keys([]p.Pair[string, int]{{K: \"a\", V: 1}}) }\n",
	})
	cfg := func() *packages.Config { return sourceLoaderConfig(root, nil) }
	snap := assertLoadersAgree(t, cfg, "./...")
	mustContain(t, snap, "package example.com/m/p illTyped=false", "package example.com/m/q illTyped=false", "func example.com/m/p.Run ", "\"net.Dial\":\"network\"")

	tagged := func() *packages.Config {
		c := sourceLoaderConfig(root, nil)
		c.BuildFlags = []string{"-tags=sfwtag"}
		return c
	}
	assertLoadersAgree(t, tagged, "./...")

	windows := func() *packages.Config {
		c := sourceLoaderConfig(root, nil)
		c.Env = append(c.Env, "GOOS=windows", "GOARCH=amd64")
		return c
	}
	assertLoadersAgree(t, windows, "./...")
}

// Test variants and an overlay that differs from the file on disk.
func TestLoadSource_TestsAndOverlayParity(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":        "module example.com/m\n\ngo 1.22\n",
		"p/p.go":        "package p\n\nfunc F() int { return 1 }\n",
		"p/p_test.go":   "package p\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { _ = F() }\n",
		"p/ext_test.go": "package p_test\n\nimport (\n\t\"os/exec\"\n\t\"testing\"\n\n\t\"example.com/m/p\"\n)\n\nfunc TestExt(t *testing.T) { _ = p.F(); exec.Command(\"x\") }\n",
	})
	withTests := func() *packages.Config {
		c := sourceLoaderConfig(root, nil)
		c.Tests = true
		return c
	}
	snap := assertLoadersAgree(t, withTests, "./...")
	mustContain(t, snap, "package example.com/m/p [example.com/m/p.test] illTyped=false", "package example.com/m/p_test [example.com/m/p.test] illTyped=false")

	file := filepath.Join(root, "p", "p.go")
	overlay := func() *packages.Config {
		return sourceLoaderConfig(root, map[string][]byte{file: []byte("package p\n\nimport \"os\"\n\nfunc F() int { os.Remove(\"x\"); return 2 }\n")})
	}
	snap = assertLoadersAgree(t, overlay, "file="+file)
	mustContain(t, snap, "\"os.Remove\":\"filesystem\"")
}

// Errors: a root with a type error and a syntax error, a dependency with an
// error in its declarations or a syntax error, and a vendored module the
// read-only module mode cannot resolve all fail identically.
func TestLoadSource_ErrorParity(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":         "module example.com/m\n\ngo 1.22\n",
		"typeerr/t.go":   "package typeerr\n\nfunc A() int { return undefinedThing }\n",
		"syntax/s.go":    "package syntax\n\nfunc C() int { return 2 \n",
		"baddecl/b.go":   "package baddecl\n\nvar X undefinedType\n",
		"usesbad/u.go":   "package usesbad\n\nimport \"example.com/m/baddecl\"\n\nfunc U() { _ = baddecl.X }\n",
		"missing/m.go":   "package missing\n\nimport \"example.com/notthere\"\n\nfunc M() { notthere.X() }\n",
		"badparse/b.go":  "package badparse\n\nvar Y = \n",
		"usesparse/u.go": "package usesparse\n\nimport \"example.com/m/badparse\"\n\nfunc U() { _ = badparse.Y }\n",
	})
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./typeerr", "./syntax", "./usesbad", "./missing", "./usesparse")
	mustContain(t, snap, "package example.com/m/typeerr illTyped=true", "package example.com/m/syntax illTyped=true",
		"package example.com/m/usesbad illTyped=true", "package example.com/m/missing illTyped=true", "package example.com/m/usesparse illTyped=true")

	vend := t.TempDir()
	writeFiles(t, vend, map[string]string{
		"go.mod":                          "module example.com/v\n\ngo 1.22\n\nrequire example.com/vend v1.0.0\n",
		"vendor/modules.txt":              "# example.com/vend v1.0.0\n## explicit\nexample.com/vend\n",
		"vendor/example.com/vend/vend.go": "package vend\n\nfunc V() int { return 1 }\n",
		"a/a.go":                          "package a\n\nimport \"example.com/vend\"\n\nfunc A() int { return vend.V() }\n",
	})
	snap = assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(vend, nil) }, "./a")
	mustContain(t, snap, "package example.com/v/a illTyped=true")
}

// A dependency's length-elided array whose element type spans lines keeps
// its length: a root that sizes an array by it or indexes it type-checks
// as with go/packages.
func TestLoadSource_ElidedArrayLengthParity(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n",
		"dep/d.go": "package dep\n\nvar Table = [...]struct {\n\tName string\n\tN    int\n}{{\"a\", 1}, {\"b\", 2}, {\"c\", 3}}\n\n" +
			"var Hooks = [...]interface{ Run(); Stop() }{nil, nil}\n",
		"root/r.go": "package root\n\nimport \"example.com/m/dep\"\n\nvar seen [len(dep.Table) + len(dep.Hooks)]bool\n\n" +
			"func Last() string { seen[4] = true; return dep.Table[2].Name }\n",
	})
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	mustContain(t, snap, "package example.com/m/root illTyped=false", "func example.com/m/root.Last ")
}

// The one intended difference: dependency function bodies are not
// type-checked, so an error confined to them no longer makes the root
// ill-typed. go/packages fails the root; loadSource analyzes it.
func TestLoadSource_DependencyBodyErrorIsNotChecked(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"dep/d.go":  "package dep\n\nfunc D() int { return undefinedThing }\n\nfunc OK() int { return 1 }\n",
		"root/r.go": "package root\n\nimport \"example.com/m/dep\"\n\nfunc R() int { return dep.OK() }\n",
	})
	t.Setenv(LoaderEnvVar, "")
	old, err := packages.Load(sourceLoaderConfig(root, nil), "./root")
	if err != nil || len(old) != 1 || !old[0].IllTyped {
		t.Fatalf("go/packages: %v, %+v; want the root ill-typed through its dependency", err, old)
	}
	got, err := loadSource(sourceLoaderConfig(root, nil), "./root")
	if err != nil || len(got) != 1 || got[0].IllTyped || len(got[0].Errors) != 0 {
		t.Fatalf("loadSource: %v; root illTyped=%v errors=%v; want a clean root", err, got[0].IllTyped, got[0].Errors)
	}
	mustContain(t, loaderSnapshot(t, got), "func example.com/m/root.R ")
}

// So are errors inside a dependency's package-level composite literals,
// whose contents are purged too, and errors of a package that only such a
// literal names, which is pruned: both loaders differ as documented.
func TestLoadSource_DependencyLiteralErrorIsNotChecked(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":        "module example.com/m\n\ngo 1.22\n",
		"table/t.go":    "package table\n\nvar Table = map[string]int{\"a\": undefinedThing}\n\nfunc Get() int { return 1 }\n",
		"broken/b.go":   "package broken\n\nvar X undefinedType\n\nfunc Use() {}\n",
		"handlers/h.go": "package handlers\n\nimport \"example.com/m/broken\"\n\nvar Handlers = map[string]func(){\"use\": broken.Use}\n\nfunc Get() int { return 1 }\n",
		"r1/r.go":       "package r1\n\nimport \"example.com/m/table\"\n\nfunc R() int { return table.Get() }\n",
		"r2/r.go":       "package r2\n\nimport \"example.com/m/handlers\"\n\nfunc R() int { return handlers.Get() }\n",
	})
	t.Setenv(LoaderEnvVar, "")
	for _, pkg := range []string{"./r1", "./r2"} {
		old, err := packages.Load(sourceLoaderConfig(root, nil), pkg)
		if err != nil || len(old) != 1 || !old[0].IllTyped {
			t.Fatalf("%s: go/packages: %v; want the root ill-typed through its dependency", pkg, err)
		}
		got, err := loadSource(sourceLoaderConfig(root, nil), pkg)
		if err != nil || len(got) != 1 || got[0].IllTyped || len(got[0].Errors) != 0 {
			t.Fatalf("%s: loadSource: %v; want a clean root", pkg, err)
		}
	}
}

// A dependency's error keeps its line: purged bodies keep their line
// breaks, so an ill-typed root's error names the line go/packages names.
func TestLoadSource_DependencyErrorPositions(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"dep/d.go":  "package dep\n\nfunc Helper() int {\n\tx := 1\n\tx++\n\tx++\n\treturn x\n}\n\nvar Broken undefinedType\n",
		"root/r.go": "package root\n\nimport \"example.com/m/dep\"\n\nfunc R() any { return dep.Broken }\n",
	})
	file := filepath.Join(root, "root", "r.go")
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := func(loader string) string {
		t.Setenv(LoaderEnvVar, loader)
		_, err := FingerprintSource(file, string(src), ir.DefaultLiteralPolicy)
		if err == nil {
			t.Fatalf("loader %q: no error for an ill-typed root", loader)
		}
		return err.Error()
	}
	want, got := fingerprint("packages"), fingerprint("")
	if want != got || !strings.Contains(got, "dep/d.go:10:12: undefined: undefinedType") {
		t.Errorf("errors:\n  go/packages: %s\n  loadSource:  %s\nwant both at dep/d.go:10:12", want, got)
	}
}

// A module missing from the module cache: go list's errors depend on the
// patterns of its run, so a batch is listed file by file, as go/packages
// lists it, and the roots get go/packages' errors.
func TestLoadMetadata_UnloadableModule(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, root, map[string]string{
		"go.mod":       "module example.com/m\n\ngo 1.22\n\nrequire example.com/sm v1.0.0\n",
		"go.sum":       "example.com/sm v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nexample.com/sm v1.0.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"r.go":         "package top\n\nimport (\n\t\"example.com/m/file\"\n\t\"example.com/sm\"\n)\n\nvar _ = file.F\nvar _ = sm.S\n\nfunc R() {}\n",
		"file/file.go": "package file\n\nimport \"example.com/sm\"\n\nvar F = sm.S\n",
		"ast/a.go":     "package ast\n\nimport \"example.com/m/file\"\n\nvar A = file.F\n",
	})
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) },
		"file="+filepath.Join(root, "ast", "a.go"), "file="+filepath.Join(root, "r.go"))
	mustContain(t, snap, "package example.com/m illTyped=true", "could not import example.com/sm")
}

// cgo is never run: CGO_ENABLED=0 excludes cgo files from the compiled
// file set, so neither loader invokes the C compiler, even for a cgo file
// whose preamble cannot compile.
func TestLoadSource_CgoIsNotRun(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "cc-was-run")
	trap := filepath.Join(root, "cc-trap.sh")
	if err := os.WriteFile(trap, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CC", trap)
	t.Setenv("CXX", trap)
	writeFiles(t, root, map[string]string{
		"go.mod":        "module example.com/m\n\ngo 1.22\n",
		"c/pure.go":     "package c\n\nfunc Pure() int { return 1 }\n",
		"c/cgo.go":      "package c\n\n/*\n#error this preamble must never be compiled\n*/\nimport \"C\"\n\nfunc Native() int { return int(C.int(1)) }\n",
		"root/r.go":     "package root\n\nimport \"example.com/m/c\"\n\nfunc R() int { return c.Pure() }\n",
		"root/r_cgo.go": "package root\n\n// #error nor this one\nimport \"C\"\n\nfunc N() {}\n",
	})
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root", "./c")
	mustContain(t, snap, "package example.com/m/root illTyped=false", "func example.com/m/c.Pure ")
	if strings.Contains(strings.Join(snap, "\n"), "Native") {
		t.Errorf("the cgo file was compiled into the package")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("the C compiler was invoked")
	}
}

// SFW_PARITY_CORPUS, a list of module roots separated by the OS path list
// separator, runs the parity check over every package of each module.
func TestLoadSource_CorpusParity(t *testing.T) {
	corpus := os.Getenv("SFW_PARITY_CORPUS")
	if corpus == "" {
		t.Skip("set SFW_PARITY_CORPUS to module roots to run")
	}
	for _, root := range filepath.SplitList(corpus) {
		root := root
		t.Run(filepath.Base(root), func(t *testing.T) {
			snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./...")
			n, pkgs, ill := 0, 0, 0
			for _, l := range snap {
				switch {
				case strings.HasPrefix(l, "func "):
					n++
				case strings.HasPrefix(l, "package "):
					pkgs++
					if strings.HasSuffix(l, "illTyped=true") {
						ill++
					}
				}
			}
			t.Logf("%s: %d packages (%d ill-typed), %d functions identical", root, pkgs, ill, n)
			if n == 0 {
				t.Errorf("no functions analyzed; the corpus entry proves nothing")
			}

			// Each package alone, as a diff loads it: one root, with the
			// module's other packages loaded as (purged) dependencies.
			list, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedFiles, Dir: root, Env: GetHardenedEnv()}, "./...")
			if err != nil {
				t.Fatal(err)
			}
			var files []string
			for _, p := range list {
				assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, p.PkgPath)
				for _, f := range p.GoFiles {
					files = append(files, "file="+f)
				}
			}
			t.Logf("%s: each of %d packages loaded alone identical", root, len(list))

			// Every file at once, as a batch loads them.
			assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, files...)
			t.Logf("%s: its %d files loaded together identical", root, len(files))
		})
	}
}

// pinnedModules serves the given module versions from a file:// proxy,
// downloads them into a new module cache (which the test's loads then use
// through GOMODCACHE), and writes go.sum for the module rooted at root. The
// loads themselves stay offline: GOPROXY=off reads only that cache.
func pinnedModules(t *testing.T, root string, modules map[string]map[string]string) {
	t.Helper()
	proxy := t.TempDir()
	for modVersion, files := range modules {
		mod, version, _ := strings.Cut(modVersion, "@")
		dir := filepath.Join(proxy, mod, "@v")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, src := range files {
			w, err := zw.Create(modVersion + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			w.Write([]byte(src))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		writeFiles(t, dir, map[string]string{
			version + ".zip":  buf.String(),
			version + ".mod":  files["go.mod"],
			version + ".info": fmt.Sprintf(`{"Version":%q}`, version),
		})
		f, err := os.OpenFile(filepath.Join(dir, "list"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(f, version)
		f.Close()
	}
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Cleanup(func() {
		// The module cache is read-only; make it removable.
		filepath.Walk(cache, func(p string, info os.FileInfo, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	cmd := exec.Command(goTool(), "mod", "tidy")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=file://"+filepath.ToSlash(proxy), "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
}

func goTool() string { return filepath.Join(runtime.GOROOT(), "bin", "go") }

// A dependency whose own files are the same under two build tags still
// changes when a package it imports does: api re-exports a constant from
// level, whose files depend on the tag. Both come from a pinned module, so
// both are cached; api's cache key must cover level's.
func TestLoadSource_CacheKeyCoversImports(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"root/r.go": "package root\n\nimport (\n\t\"os\"\n\n\t\"example.com/dep/api\"\n)\n\nfunc R(p string) {\n\tif api.Level > 1 {\n\t\tos.RemoveAll(p)\n\t}\n}\n",
	})
	pinnedModules(t, root, map[string]map[string]string{
		"example.com/dep@v1.0.0": {
			"go.mod":     "module example.com/dep\n\ngo 1.22\n",
			"level/a.go": "//go:build !strict\n\npackage level\n\nconst L = 1\n",
			"level/b.go": "//go:build strict\n\npackage level\n\nconst L = 2\n",
			"api/api.go": "package api\n\nimport \"example.com/dep/level\"\n\nconst Level = level.L\n",
		},
	})
	plain := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	strict := assertLoadersAgree(t, func() *packages.Config {
		c := sourceLoaderConfig(root, nil)
		c.BuildFlags = []string{"-tags=strict"}
		return c
	}, "./root")
	if strings.Join(plain, "\n") == strings.Join(strict, "\n") {
		t.Errorf("the two build configurations gave identical results")
	}
}

// Two versions of a pinned module in one process are cached separately.
func TestLoadSource_CacheKeyCoversVersions(t *testing.T) {
	var snaps [][]string
	for _, version := range []string{"v1.0.0", "v1.1.0"} {
		root := t.TempDir()
		writeFiles(t, root, map[string]string{
			"go.mod":    "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep " + version + "\n",
			"root/r.go": "package root\n\nimport (\n\t\"net\"\n\n\t\"example.com/dep/api\"\n)\n\nfunc R(a string) {\n\tif api.Remote {\n\t\tnet.Dial(\"tcp\", a)\n\t}\n}\n",
		})
		pinnedModules(t, root, map[string]map[string]string{
			"example.com/dep@" + version: {
				"go.mod":     "module example.com/dep\n\ngo 1.22\n",
				"api/api.go": "package api\n\nconst Remote = " + map[string]string{"v1.0.0": "false", "v1.1.0": "true"}[version] + "\n",
			},
		})
		snaps = append(snaps, assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root"))
	}
	if strings.Join(snaps[0], "\n") == strings.Join(snaps[1], "\n") {
		t.Errorf("v1.0.0 and v1.1.0 gave identical results")
	}
}

// An overlaid dependency file is never served from the cache. The go
// command refuses overlays beneath GOMODCACHE, so only the standard library
// can be overlaid among shareable packages, and only when GOROOT is not
// inside the module cache (as it is for a downloaded toolchain): the test
// moves GOMODCACHE aside. unicode/utf8 is loaded once and cached, then
// loaded with utf8.go overlaid.
func TestLoadSource_OverlaidDependencyIsNotCached(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"root/r.go": "package root\n\nimport (\n\t\"net\"\n\t\"unicode/utf8\"\n)\n\nfunc R(a string) {\n\tif utf8.UTFMax == 5 {\n\t\tnet.Dial(\"tcp\", a)\n\t}\n}\n",
	})
	utf8File := filepath.Join(runtime.GOROOT(), "src", "unicode", "utf8", "utf8.go")
	orig, err := os.ReadFile(utf8File)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(orig), "UTFMax    = 4", "UTFMax    = 5", 1)
	if changed == string(orig) {
		t.Fatal("utf8.go no longer declares UTFMax = 4")
	}
	plain := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	overlaid := assertLoadersAgree(t, func() *packages.Config {
		return sourceLoaderConfig(root, map[string][]byte{utf8File: []byte(changed)})
	}, "./root")
	if strings.Join(plain, "\n") == strings.Join(overlaid, "\n") {
		t.Errorf("the overlay did not change the result")
	}
}

// Type sizes are part of the key: a pure-Go dependency has the same files
// for amd64 and 386, but not the same unsafe.Sizeof.
func TestLoadSource_CacheKeyCoversSizes(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"root/r.go": "package root\n\nimport (\n\t\"os\"\n\n\t\"example.com/dep/w\"\n)\n\nfunc R(p string) {\n\tif w.Word == 8 {\n\t\tos.RemoveAll(p)\n\t}\n}\n",
	})
	pinnedModules(t, root, map[string]map[string]string{
		"example.com/dep@v1.0.0": {
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"w/w.go": "package w\n\nimport \"unsafe\"\n\nconst Word = unsafe.Sizeof(uintptr(0))\n",
		},
	})
	var snaps [][]string
	for _, arch := range []string{"amd64", "386"} {
		snaps = append(snaps, assertLoadersAgree(t, func() *packages.Config {
			c := sourceLoaderConfig(root, nil)
			c.Env = append(c.Env, "GOOS=linux", "GOARCH="+arch)
			return c
		}, "./root"))
	}
	if strings.Join(snaps[0], "\n") == strings.Join(snaps[1], "\n") {
		t.Errorf("amd64 and 386 gave identical results")
	}
}

// The module's Go version reaches the type checker: before Go 1.22 a loop
// variable is shared by all iterations, which changes the SSA of closures
// that capture it.
func TestLoadSource_GoVersionParity(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.21\n",
		"root/r.go": "package root\n\nfunc R(xs []int) []func() int {\n\tvar fs []func() int\n\tfor _, x := range xs {\n\t\tfs = append(fs, func() int { return x })\n\t}\n\treturn fs\n}\n",
	})
	old := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	writeFiles(t, root, map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n"})
	cur := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	if strings.Join(old, "\n") == strings.Join(cur, "\n") {
		t.Errorf("go 1.21 and go 1.22 loop-variable semantics gave identical results")
	}
}

// A cached dependency keeps its errors: a root importing a pinned module
// with a declaration error stays ill-typed on every load, the later ones
// served from the cache.
func TestLoadSource_CachedDependencyKeepsErrors(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n\nrequire example.com/broken v1.0.0\n",
		"root/r.go": "package root\n\nimport \"example.com/broken/b\"\n\nfunc R() int { return len(b.X) }\n",
	})
	pinnedModules(t, root, map[string]map[string]string{
		"example.com/broken@v1.0.0": {
			"go.mod": "module example.com/broken\n\ngo 1.22\n",
			"b/b.go": "package b\n\nvar X []undefinedType\n",
		},
	})
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	mustContain(t, snap, "package example.com/m/root illTyped=true")
}

// Only packages whose files cannot change are cached: a dependency in the
// main module edited on disk between two loads of one process (a library
// caller analyzing, editing, analyzing again) is read afresh.
func TestLoadSource_EditedWorkspaceFilesAreReloaded(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"dep/d.go":  "package dep\n\nconst On = false\n",
		"root/r.go": "package root\n\nimport (\n\t\"net\"\n\n\t\"example.com/m/dep\"\n)\n\nfunc R(a string) {\n\tif dep.On {\n\t\tnet.Dial(\"tcp\", a)\n\t}\n}\n",
	})
	before := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	writeFiles(t, root, map[string]string{"dep/d.go": "package dep\n\nconst On = true\n"})
	after := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	if strings.Join(before, "\n") == strings.Join(after, "\n") {
		t.Errorf("the edit to dep/d.go did not change the result")
	}
}

// The same holds for a module replaced by a local directory.
func TestLoadSource_EditedReplacementIsReloaded(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./dep\n",
		"dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"dep/d/d.go": "package d\n\nconst On = false\n",
		"root/r.go":  "package root\n\nimport (\n\t\"net\"\n\n\t\"example.com/dep/d\"\n)\n\nfunc R(a string) {\n\tif d.On {\n\t\tnet.Dial(\"tcp\", a)\n\t}\n}\n",
	})
	before := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	writeFiles(t, root, map[string]string{"dep/d/d.go": "package d\n\nconst On = true\n"})
	after := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(root, nil) }, "./root")
	if strings.Join(before, "\n") == strings.Join(after, "\n") {
		t.Errorf("the edit to the replacement did not change the result")
	}
}

// metadataSnapshot renders the root IDs in order and the metadata of every
// package they reach.
func metadataSnapshot(roots []*packages.Package) []string {
	var ids, all []string
	for _, r := range roots {
		ids = append(ids, r.ID)
	}
	packages.Visit(roots, nil, func(p *packages.Package) {
		var imports []string
		for path, imp := range p.Imports {
			imports = append(imports, path+"="+imp.ID)
		}
		sort.Strings(imports)
		var module string
		if p.Module != nil {
			module = p.Module.Path + "@" + p.Module.Version
		}
		all = append(all, fmt.Sprintf("%s name=%s path=%s dir=%s go=%v compiled=%v other=%v ignored=%v errors=%v imports=%v module=%s sizes=%v",
			p.ID, p.Name, p.PkgPath, p.Dir, p.GoFiles, p.CompiledGoFiles, p.OtherFiles, p.IgnoredFiles, p.Errors, imports, module, p.TypesSizes))
	})
	sort.Strings(all)
	return append([]string{"roots " + strings.Join(ids, " ")}, all...)
}

// Several file= queries take one go list run over their directories and
// get the roots go/packages gives, in its order: a package once however
// many of its files are queried, none for a test file or a file the build
// excludes, a test file's test variant when tests are loaded. A directory
// for which go/packages builds an ad-hoc package (one go list lists nothing
// for, or a package without Go files), a single query, a relative path and
// any other pattern take the per-file load.
func TestLoadMetadata_FileQueries(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"o.go": "package o\n"})
	writeFiles(t, root, map[string]string{
		"go.mod":             "module example.com/m\n\ngo 1.22\n",
		"a/a.go":             "package a\n\nimport \"os\"\n\nfunc A() { os.Exit(1) }\n",
		"a/b.go":             "package a\n\nfunc B() {}\n",
		"a/a_test.go":        "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n",
		"b/b.go":             "package b\n\nimport \"example.com/m/a\"\n\nfunc B() { a.B() }\n",
		"c/c.go":             "package c\n",
		"c/tagged.go":        "//go:build sfwnever\n\npackage c\n\nfunc T() {}\n",
		"onlytest/x_test.go": "package onlytest\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		"excluded/e.go":      "//go:build sfwnever\n\npackage excluded\n",
	})
	file := func(name string) string { return "file=" + filepath.Join(root, filepath.FromSlash(name)) }
	dir := func(name string) string { return "pattern=" + filepath.Join(root, name) }
	var calls []string
	listPackages = func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		calls = append(calls, strings.Join(patterns, " "))
		return packages.Load(cfg, patterns...)
	}
	t.Cleanup(func() { listPackages = packages.Load })
	overlay := map[string][]byte{filepath.Join(root, "a", "new.go"): []byte("package a\n\nfunc New() {}\n")}

	for _, tc := range []struct {
		name      string
		tests     bool
		patterns  []string
		wantRoots string
		wantCalls []string
	}{
		{
			name:      "many files",
			patterns:  []string{file("b/b.go"), file("a/a.go"), file("a/a_test.go"), file("a/b.go"), file("c/tagged.go"), file("a/new.go"), file("b/b.go")},
			wantRoots: "roots example.com/m/b example.com/m/a",
			wantCalls: []string{dir("b") + " " + dir("a") + " " + dir("c")},
		},
		{
			name:      "test variants",
			tests:     true,
			patterns:  []string{file("a/a_test.go"), file("b/b.go"), file("a/a.go")},
			wantRoots: "roots example.com/m/a [example.com/m/a.test] example.com/m/b example.com/m/a",
			wantCalls: []string{dir("a") + " " + dir("b")},
		},
		{
			name:      "only files nothing compiles",
			patterns:  []string{file("a/a_test.go"), file("c/tagged.go")},
			wantRoots: "roots ",
			wantCalls: []string{dir("a") + " " + dir("c")},
		},
		{
			name:      "a directory with only a test file",
			patterns:  []string{file("a/a.go"), file("onlytest/x_test.go")},
			wantRoots: "roots example.com/m/a",
			wantCalls: []string{dir("a") + " " + dir("onlytest"), file("a/a.go") + " " + file("onlytest/x_test.go")},
		},
		{
			name:      "a directory the build excludes",
			patterns:  []string{file("excluded/e.go"), file("a/a.go")},
			wantRoots: "roots command-line-arguments example.com/m/a",
			wantCalls: []string{dir("excluded") + " " + dir("a"), file("excluded/e.go") + " " + file("a/a.go")},
		},
		{
			name:      "a directory that does not exist",
			patterns:  []string{file("a/a.go"), file("gone/g.go")},
			wantRoots: "roots example.com/m/a",
			wantCalls: []string{dir("a") + " " + dir("gone"), file("a/a.go") + " " + file("gone/g.go")},
		},
		{
			name:      "a directory outside the module",
			patterns:  []string{file("a/a.go"), "file=" + filepath.Join(outside, "o.go")},
			wantCalls: []string{dir("a") + " pattern=" + outside, file("a/a.go") + " file=" + filepath.Join(outside, "o.go")},
		},
		{
			name:      "a relative path",
			patterns:  []string{file("a/a.go"), "file=b/b.go"},
			wantRoots: "roots example.com/m/a example.com/m/b",
			wantCalls: []string{file("a/a.go") + " file=b/b.go"},
		},
		{
			name:      "one file",
			patterns:  []string{file("a/a.go")},
			wantRoots: "roots example.com/m/a",
			wantCalls: []string{file("a/a.go")},
		},
		{
			name:      "another pattern",
			patterns:  []string{file("a/a.go"), "./b"},
			wantRoots: "roots example.com/m/b example.com/m/a",
			wantCalls: []string{file("a/a.go") + " ./b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sourceLoaderConfig(root, overlay)
			cfg.Tests = tc.tests
			cfg.Mode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
				packages.NeedImports | packages.NeedDeps | packages.NeedModule | packages.NeedTypesSizes
			cfg.Fset = nil
			want, err := packages.Load(cfg, tc.patterns...)
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			got, err := loadMetadata(cfg, tc.patterns)
			if err != nil {
				t.Fatal(err)
			}
			wantSnap, gotSnap := metadataSnapshot(want), metadataSnapshot(got)
			if diff := firstDifference(wantSnap, gotSnap); diff != "" {
				t.Errorf("loadMetadata differs from go/packages: %s", diff)
			}
			if tc.wantRoots != "" && gotSnap[0] != tc.wantRoots {
				t.Errorf("got %q, want %q", gotSnap[0], tc.wantRoots)
			}
			if strings.Join(calls, "\n") != strings.Join(tc.wantCalls, "\n") {
				t.Errorf("go/packages calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(tc.wantCalls, "\n"))
			}
		})
	}
}

// Two loads share a standard-library dependency's types, not a dependency
// in the main module, whose files may change between loads.
func TestLoadSource_SharesFixedDependencies(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"dep/d.go":  "package dep\n\nconst On = true\n",
		"root/r.go": "package root\n\nimport (\n\t\"strconv\"\n\n\t\"example.com/m/dep\"\n)\n\nfunc R() string { return strconv.FormatBool(dep.On) }\n",
	})
	var loads [2]*packages.Package
	for i := range loads {
		roots, err := loadSource(sourceLoaderConfig(root, nil), "./root")
		if err != nil || len(roots) != 1 || roots[0].IllTyped {
			t.Fatalf("load %d: %v %v", i, roots, err)
		}
		loads[i] = roots[0]
	}
	if loads[0].Imports["strconv"].Types != loads[1].Imports["strconv"].Types {
		t.Errorf("the two loads checked strconv separately")
	}
	if loads[0].Imports["example.com/m/dep"].Types == loads[1].Imports["example.com/m/dep"].Types {
		t.Errorf("the two loads shared a main-module dependency")
	}
}

// A dependency file that cannot be read is an error of its package, once,
// and makes the root that imports it ill-typed.
func TestLoadSource_UnreadableDependencyFile(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"dep/a.go":  "package dep\n\nconst A = 1\n",
		"dep/b.go":  "package dep\n\nconst B = 2\n",
		"root/r.go": "package root\n\nimport \"example.com/m/dep\"\n\nfunc R() int { return dep.A }\n",
	})
	unreadable := filepath.Join(root, "dep", "b.go")
	readSourceFile = func(name string) ([]byte, error) {
		if name == unreadable {
			return nil, fmt.Errorf("cannot read %s", name)
		}
		return os.ReadFile(name)
	}
	t.Cleanup(func() { readSourceFile = os.ReadFile })
	roots, err := loadSource(sourceLoaderConfig(root, nil), "./root")
	if err != nil || len(roots) != 1 {
		t.Fatalf("%v %v", roots, err)
	}
	dep := roots[0].Imports["example.com/m/dep"]
	if !roots[0].IllTyped || len(dep.Errors) != 1 || !strings.Contains(dep.Errors[0].Msg, "cannot read "+unreadable) {
		t.Errorf("root illTyped=%v, dep errors %v; want ill-typed, one read error", roots[0].IllTyped, dep.Errors)
	}
}

// A root is checked afresh by every load, so no shared dependency may be
// built on one: reflect, a dependency, imports strconv, here a root, and
// must use this load's strconv, though an earlier load shared a reflect
// built on a strconv that was a dependency there.
func TestLoadSource_SharedDependenciesNeverImportARoot(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n",
		"root/r.go": "package root\n\nimport \"encoding/json\"\n\nfunc R(v any) ([]byte, error) { return json.Marshal(v) }\n",
	})
	if _, err := loadSource(sourceLoaderConfig(root, nil), "./root"); err != nil {
		t.Fatal(err)
	}
	roots, err := loadSource(sourceLoaderConfig(root, nil), "strconv", "encoding/json")
	if err != nil || len(roots) != 2 {
		t.Fatalf("%v %v", roots, err)
	}
	strconvRoot, jsonRoot := roots[0], roots[1]
	if strconvRoot.PkgPath != "strconv" {
		strconvRoot, jsonRoot = jsonRoot, strconvRoot
	}
	reflect := jsonRoot.Imports["reflect"]
	if reflect == nil || reflect.Imports["strconv"] != strconvRoot {
		t.Fatalf("reflect does not import the strconv root")
	}
	for _, imp := range reflect.Types.Imports() {
		if imp.Path() == "strconv" && imp != strconvRoot.Types {
			t.Errorf("reflect was checked against another load's strconv")
		}
	}
}

// A dependency's check needs the imports its declarations name, with
// function bodies purged: a type, a constant, a signature, an embedded
// field, a constraint, a variable's initializer, a dot import, and an
// import whose package has no name. An import named only in a body, a
// function literal's body, or a blank import, is not needed.
func TestDeclaredImports(t *testing.T) {
	src := `package p

import (
	"bytes"
	"context"
	. "errors"
	"io"
	ospkg "os"
	"strings"
	"time"
	_ "embed"
	"example.com/noname"
	"example.com/unknown/alias"
	"sync"
	"unicode"
	"net"
)

type T struct {
	io.Reader
	d time.Duration
}

const Max = len("x") + int(unicode.MaxASCII)

var Upper = strings.ToUpper("a")

var Run = func() { _ = net.Dial }

func F(ctx context.Context) ospkg.FileMode { var b bytes.Buffer; _ = b; return 0 }

func G[S ~[]E, E comparable](s S) {}

type L struct{ mu sync.Mutex }

var e = New("x")
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", purge.PurgeFuncBodies([]byte(src)), parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	p := &packages.Package{Imports: map[string]*packages.Package{}}
	for _, path := range []string{"bytes", "context", "errors", "io", "os", "strings", "time", "embed", "sync", "unicode", "net"} {
		p.Imports[path] = &packages.Package{PkgPath: path, Name: filepath.Base(path)}
	}
	p.Imports["example.com/noname"] = &packages.Package{PkgPath: "example.com/noname"}
	got := strings.Join(declaredImports(p, []*ast.File{f}), " ")
	want := "context errors example.com/noname io os strings sync time unicode"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// A package a dependency imports only for its function bodies is never
// loaded: not parsed, not checked, not ill-typed for its importers. Here
// it has an error in its declarations, which go/packages reports through
// the dependency to the root; loadSource does not, as with any error that
// only a dependency's bodies would see. A single import declaration left
// empty is dropped, a grouped one keeps its needed import.
func TestLoadSource_BodyOnlyImportsAreNotLoaded(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":         "module example.com/m\n\ngo 1.22\n",
		"broken/b.go":    "package broken\n\nvar X undefinedType\n\nfunc Use() {}\n",
		"dep/single.go":  "package dep\n\nimport \"example.com/m/broken\"\n\nfunc Body() { broken.Use() }\n",
		"dep/grouped.go": "package dep\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nvar Up = strings.ToUpper(\"a\")\n\nfunc Run() { exec.Command(\"x\") }\n",
		"root/r.go":      "package root\n\nimport (\n\t\"net\"\n\n\t\"example.com/m/dep\"\n)\n\nfunc R(a string) {\n\tif dep.Up != \"\" {\n\t\tnet.Dial(\"tcp\", a)\n\t}\n}\n",
	})
	want, err := packages.Load(sourceLoaderConfig(root, nil), "./root")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, loaderSnapshot(t, want), "package example.com/m/root illTyped=true")

	roots, err := loadSource(sourceLoaderConfig(root, nil), "./root")
	if err != nil || len(roots) != 1 {
		t.Fatalf("%v %v", roots, err)
	}
	snap := loaderSnapshot(t, roots)
	mustContain(t, snap, "package example.com/m/root illTyped=false", "func example.com/m/root.R ", "\"net.Dial\":\"network\"")
	dep := roots[0].Imports["example.com/m/dep"]
	if dep.Types == nil || dep.IllTyped || dep.Types.Scope().Lookup("Up") == nil {
		t.Fatalf("dep: types %v, ill-typed %v, errors %v", dep.Types, dep.IllTyped, dep.Errors)
	}
	for _, path := range []string{"example.com/m/broken", "os/exec"} {
		if dep.Imports[path].Types != nil {
			t.Errorf("%s, imported only for dep's bodies, was loaded", path)
		}
	}
	if dep.Imports["strings"].Types == nil {
		t.Errorf("strings, which dep's declarations use, was not loaded")
	}
}

// The governing go.work is the first in the directory or a parent, up to
// the repository's root: a worktree checked out inside another tree (its
// .git a file) does not take the outer tree's workspace.
func TestWorkspaceFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, root, map[string]string{
		"repo/.git/HEAD":       "ref: refs/heads/main\n",
		"repo/go.work":         "go 1.22\n",
		"repo/app/go.mod":      "module example.com/app\n",
		"repo/app/sub/x.go":    "package sub\n",
		"repo/.wt/.git":        "gitdir: ../.git/worktrees/wt\n",
		"repo/.wt/app/go.mod":  "module example.com/app\n",
		"repo/.wt2/.git":       "gitdir: ../.git/worktrees/wt2\n",
		"repo/.wt2/go.work":    "go 1.22\n",
		"repo/.wt2/app/go.mod": "module example.com/app\n",
		"plain/go.work/keep":   "a directory, not a workspace\n",
		"plain/app/go.mod":     "module example.com/app\n",
	})
	for dir, want := range map[string]string{
		"repo":          "repo/go.work",
		"repo/app":      "repo/go.work",
		"repo/app/sub":  "repo/go.work",
		"repo/.wt/app":  "",
		"repo/.wt2/app": "repo/.wt2/go.work",
		"plain/app":     "",
	} {
		if want != "" {
			want = filepath.Join(root, filepath.FromSlash(want))
		}
		if got := WorkspaceFile(filepath.Join(root, filepath.FromSlash(dir))); got != want {
			t.Errorf("%s: got %q, want %q", dir, got, want)
		}
	}
	env := HardenedEnvFor(filepath.Join(root, "repo", "app"))
	if env[len(env)-1] != "GOWORK="+filepath.Join(root, "repo", "go.work") {
		t.Errorf("env ends %q; want the workspace", env[len(env)-1])
	}
	if env := HardenedEnvFor(filepath.Join(root, "plain", "app")); strings.Join(env, "\n") != strings.Join(GetHardenedEnv(), "\n") {
		t.Errorf("env without a workspace: %v", env[len(env)-3:])
	}
}

// A tree governed by a go.work loads as the go command builds it: a module
// of the workspace resolves to its directory, even one that takes the path
// of a required dependency. Here shadow/ replaces example.com/dep v1.0.0.
func TestLoadSource_WorkspaceParity(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, root, map[string]string{
		"go.work":       "go 1.22\n\nuse (\n\t./app\n\t./lib\n\t./shadow\n)\n",
		"app/go.mod":    "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"app/a.go":      "package app\n\nimport \"example.com/dep\"\n\nvar A = dep.D\n",
		"lib/go.mod":    "module example.com/lib\n\ngo 1.22\n",
		"lib/l.go":      "package lib\n\nconst L = 1\n",
		"shadow/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"shadow/d.go":   "package dep\n\nimport \"os/exec\"\n\nconst D = 666\n\nfunc Run() { exec.Command(\"sh\").Run() }\n",
	})
	pinnedModules(t, filepath.Join(root, "app"), map[string]map[string]string{
		"example.com/dep@v1.0.0": {"go.mod": "module example.com/dep\n\ngo 1.22\n", "d.go": "package dep\n\nconst D = 1\n\nfunc Run() {}\n"},
	})
	writeFiles(t, root, map[string]string{
		"app/a.go": "package app\n\nimport (\n\t\"example.com/dep\"\n\t\"example.com/lib\"\n)\n\nvar A = lib.L + dep.D\n\nfunc Go() { dep.Run() }\n",
	})
	app := filepath.Join(root, "app")
	snap := assertLoadersAgree(t, func() *packages.Config { return sourceLoaderConfig(app, nil) }, "./...")
	mustContain(t, snap, "package example.com/app illTyped=false", "func example.com/app.Go ")

	roots, err := loadSource(sourceLoaderConfig(app, nil), "./...")
	if err != nil || len(roots) != 1 {
		t.Fatalf("%v %v", roots, err)
	}
	dep := roots[0].Imports["example.com/dep"]
	if len(dep.GoFiles) != 1 || dep.GoFiles[0] != filepath.Join(root, "shadow", "d.go") {
		t.Errorf("example.com/dep loaded from %v; want the workspace's shadow/d.go", dep.GoFiles)
	}
	if c := dep.Types.Scope().Lookup("D").(*types.Const); c.Val().String() != "666" {
		t.Errorf("dep.D = %s; want the workspace copy's 666", c.Val())
	}
}
