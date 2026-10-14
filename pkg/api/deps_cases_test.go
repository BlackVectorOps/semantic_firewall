package api_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// moduleProxy serves the given modules ("path@version" -> files) from a
// file:// proxy, points GOMODCACHE at a new empty cache, and returns the
// proxy URL for tidy.
func moduleProxy(t *testing.T, modules map[string]map[string]string) string {
	t.Helper()
	proxy := t.TempDir()
	for modVersion, files := range modules {
		mod, version, _ := strings.Cut(modVersion, "@")
		dir := filepath.Join(proxy, mod, "@v")
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, src := range files {
			w, err := zw.Create(modVersion + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(src)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		writeFilesIn(t, dir, map[string]string{
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
		filepath.Walk(cache, func(p string, _ os.FileInfo, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	return "file://" + filepath.ToSlash(proxy)
}

// tidy runs `go mod tidy` in dir against proxy, filling the module cache
// and go.sum.
func tidy(t *testing.T, dir, proxy string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY="+proxy, "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
}

func writeFilesIn(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const depV1 = `package d

import "net"

type Client struct{}

func (c *Client) Do() {}

type helper struct{}

func (helper) Do() {}

func Hook() func() { return quiet }

func quiet() {}

func Ping() { net.Dial("tcp", "localhost:1") }

func Sum(a, b int) int { return a + b }
`

// The new version reaches exec from an exported method through a closure,
// and the network through a function value it hands out. An exported
// method of an unexported type is not an entry point, and Ping reaching a
// second network target reaches no new class.
const depV2 = `package d

import (
	"net"
	"os/exec"
)

type Client struct{}

func (c *Client) Do() { run() }

type helper struct{}

func (helper) Do() { net.Dial("tcp", "203.0.113.7:443") }

func Hook() func() { return beacon }

func beacon() { net.Dial("tcp", "203.0.113.7:443") }

func run() {
	f := func() { exec.Command("id").Run() }
	f()
}

func Ping() {
	net.Dial("tcp", "localhost:1")
	net.Listen("tcp", ":0")
}

func Sum(a, b int) int { return a + b }
`

// Modules at versions from a module cache: an update, an unchanged module,
// a removed one, and one switched to a fork with identical code.
func TestDepsDiff_VersionedModules(t *testing.T) {
	gomod := func(mod string) string { return "module " + mod + "\n\ngo 1.22\n" }
	proxy := moduleProxy(t, map[string]map[string]string{
		"example.com/dep@v1.0.0":    {"go.mod": gomod("example.com/dep"), "d/d.go": depV1},
		"example.com/dep@v1.1.0":    {"go.mod": gomod("example.com/dep"), "d/d.go": depV2},
		"example.com/same@v1.0.0":   {"go.mod": gomod("example.com/same"), "s/s.go": "package s\n\nfunc S() int { return 1 }\n"},
		"example.com/gone@v1.0.0":   {"go.mod": gomod("example.com/gone"), "g/g.go": "package g\n\nfunc G() int { return 1 }\n"},
		"example.com/forked@v1.0.0": {"go.mod": gomod("example.com/forked"), "f/f.go": "package f\n\nfunc F() int { return 1 }\n"},
		// A replacement's go.mod names the module it replaces.
		"example.com/fork@v1.0.0": {"go.mod": gomod("example.com/forked"), "f/f.go": "package f\n\nfunc F() int { return 1 }\n"},
	})
	app := func(depVersion, imports, extra string) string {
		dir := t.TempDir()
		writeFilesIn(t, dir, map[string]string{
			"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/dep " + depVersion +
				"\n\texample.com/same v1.0.0\n\texample.com/forked v1.0.0\n)\n" + extra,
			"main.go": "package main\n\nimport (\n\t_ \"example.com/dep/d\"\n\t_ \"example.com/same/s\"\n\t_ \"example.com/forked/f\"\n" + imports + ")\n\nfunc main() {}\n",
		})
		tidy(t, dir, proxy)
		return dir
	}
	oldDir := app("v1.0.0", "\t_ \"example.com/gone/g\"\n", "\nrequire example.com/gone v1.0.0\n")
	newDir := app("v1.1.0", "", "\nreplace example.com/forked => example.com/fork v1.0.0\n")

	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	var paths []string
	for _, m := range out.Modules {
		paths = append(paths, m.Path)
	}
	if want := []string{"example.com/dep", "example.com/forked", "example.com/gone"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("modules %v; want %v", paths, want)
	}

	dep := out.Modules[0]
	if dep.Status != models.ModuleUpdated || dep.OldVersion != "v1.0.0" || dep.NewVersion != "v1.1.0" {
		t.Errorf("dep = %s %s -> %s; want updated v1.0.0 -> v1.1.0", dep.Status, dep.OldVersion, dep.NewVersion)
	}
	wantReach := []models.ReachChange{
		{Function: "example.com/dep/d.(*Client).Do", Added: []string{"exec"}, Targets: []string{"(os/exec.Cmd).Run", "os/exec.Command"}, RiskScore: 30},
		{Function: "example.com/dep/d.Hook", Added: []string{"network"}, Targets: []string{"net.Dial"}, RiskScore: 20},
	}
	if !reflect.DeepEqual(dep.Reach, wantReach) {
		t.Errorf("dep reach =\n%+v\nwant\n%+v", dep.Reach, wantReach)
	}
	changed := map[string]string{}
	for _, p := range dep.Packages {
		if p.Path != "example.com/dep/d" {
			t.Errorf("unexpected package %s", p.Path)
		}
		for _, f := range p.Functions {
			changed[f.Function] = f.Status
		}
	}
	for name, status := range map[string]string{
		"(*Client).Do": models.StatusModified, "(helper).Do": models.StatusModified, "Hook": models.StatusModified,
		"Ping": models.StatusModified, "run": models.StatusAdded, "run$1": models.StatusAdded,
	} {
		if changed[name] != status {
			t.Errorf("function %s: status %q; want %s (changed: %v)", name, changed[name], status, changed)
		}
	}
	if _, ok := changed["Sum"]; ok {
		t.Errorf("unchanged Sum reported: %v", changed)
	}
	if dep.HighRiskChanges < 2 || dep.RiskScore < 30 {
		t.Errorf("dep risk %d with %d high-risk changes; want at least 30 and 2", dep.RiskScore, dep.HighRiskChanges)
	}

	forked := out.Modules[1]
	if forked.Status != models.ModuleUpdated || forked.OldVersion != "v1.0.0" || forked.NewVersion != "example.com/fork@v1.0.0" ||
		len(forked.Packages) != 0 || len(forked.Reach) != 0 || len(forked.Unanalyzed) != 0 || forked.RiskScore != 0 {
		t.Errorf("forked = %+v; want updated v1.0.0 -> example.com/fork@v1.0.0 with no changes", forked)
	}
	gone := out.Modules[2]
	if gone.Status != models.ModuleRemoved || gone.OldVersion != "v1.0.0" || gone.NewVersion != "" || gone.RiskScore != 0 {
		t.Errorf("gone = %+v; want removed at v1.0.0", gone)
	}
	want := models.DepsDiffSummary{ModulesUpdated: 2, ModulesRemoved: 1, FunctionsChanged: len(changed), HighRiskChanges: dep.HighRiskChanges}
	if out.Summary != want {
		t.Errorf("summary = %+v; want %+v", out.Summary, want)
	}
}

// Changes the SSA analysis cannot see. The module uses cgo, which the
// loader disables, so go list hides its C files; they are found anyway, as
// are native files outside the package directory. Tests, documentation and
// a module that changed only those are not reported.
func TestDepsDiff_UnanalyzedFiles(t *testing.T) {
	deps := map[string]string{"example.com/native": "native", "example.com/docs": "docs"}
	imports := "\t_ \"example.com/native/n\"\n\t_ \"example.com/docs/d\"\n"
	common := map[string]string{
		"lib/native/n/n.go":   "package n\n\nimport _ \"embed\"\n\n//go:embed data.txt\nvar Data string\n\nfunc N() int { return 1 }\n",
		"lib/native/n/cgo.go": "package n\n\n// int add(int a, int b);\nimport \"C\"\n\nfunc Add() int { return int(C.add(1, 2)) }\n",
		"lib/docs/d/d.go":     "package d\n\nfunc D() int { return 1 }\n",
	}
	with := func(files map[string]string) map[string]string {
		all := map[string]string{}
		for k, v := range common {
			all[k] = v
		}
		for k, v := range files {
			all[k] = v
		}
		return all
	}
	oldDir := appTree(t, imports, deps, with(map[string]string{
		"lib/native/n/helper.c":     "int add(int a, int b) { return a + b; }\n",
		"lib/native/csrc/inc.h":     "#define ONE 1\n",
		"lib/native/n/excluded.go":  "//go:build ignore\n\npackage n\n",
		"lib/native/n/blob.syso":    "v1",
		"lib/native/n/stub.s":       "// v1\n",
		"lib/native/n/data.txt":     "v1",
		"lib/native/n/n_test.go":    "package n\n",
		"lib/native/n/README.md":    "v1",
		"lib/native/csrc/notes.txt": "v1",
		"lib/docs/d/d_test.go":      "package d\n",
		"lib/docs/README.md":        "v1",
	}))
	newDir := appTree(t, imports, deps, with(map[string]string{
		"lib/native/n/helper.c":     "int add(int a, int b) { system(\"id\"); return a + b; }\n",
		"lib/native/csrc/inc.h":     "#define ONE 2\n",
		"lib/native/csrc/libx.a":    "!<arch>\n",
		"lib/native/n/excluded.go":  "//go:build ignore\n\npackage n\n\n// v2\n",
		"lib/native/n/blob.syso":    "v2",
		"lib/native/n/new.syso":     "v1",
		"lib/native/n/data.txt":     "v2",
		"lib/native/n/n_test.go":    "package n\n\n// v2\n",
		"lib/native/n/README.md":    "v2",
		"lib/native/csrc/notes.txt": "v2",
		"lib/docs/d/d_test.go":      "package d\n\n// v2\n",
		"lib/docs/README.md":        "v2",
	}))
	// cgo.go changes too, so that every kind is covered.
	if err := os.WriteFile(filepath.Join(newDir, "../lib/native/n/cgo.go"),
		[]byte(common["lib/native/n/cgo.go"]+"\n// v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	if len(out.Modules) != 1 {
		t.Fatalf("modules = %+v; want only example.com/native", out.Modules)
	}
	m := out.Modules[0]
	want := []models.FileChange{
		{File: "n/stub.s", Kind: "assembly", Change: "removed"},
		{File: "csrc/inc.h", Kind: "c", Change: "modified", RiskScore: 5},
		{File: "n/helper.c", Kind: "c", Change: "modified", RiskScore: 5},
		{File: "n/cgo.go", Kind: "cgo", Change: "modified", RiskScore: 5},
		{File: "n/data.txt", Kind: "embed", Change: "modified", RiskScore: 5},
		{File: "n/excluded.go", Kind: "excluded-go", Change: "modified", RiskScore: 5},
		{File: "csrc/libx.a", Kind: "object", Change: "added", RiskScore: 20},
		{File: "n/blob.syso", Kind: "syso", Change: "modified", RiskScore: 20},
		{File: "n/new.syso", Kind: "syso", Change: "added", RiskScore: 20},
	}
	if !reflect.DeepEqual(m.Unanalyzed, want) {
		t.Errorf("unanalyzed =\n%+v\nwant\n%+v", m.Unanalyzed, want)
	}
	if m.Path != "example.com/native" || m.Status != models.ModuleUpdated || len(m.Packages) != 0 || len(m.Reach) != 0 ||
		m.RiskScore != 20 || m.HighRiskChanges != 3 {
		t.Errorf("module = %+v; want updated, risk 20, 3 high-risk changes", m)
	}
	if want := (models.DepsDiffSummary{ModulesUpdated: 1, HighRiskChanges: 3}); out.Summary != want {
		t.Errorf("summary = %+v; want %+v", out.Summary, want)
	}
}

// A module only the new tree compiles reports the unanalyzed files that
// carry machine code or reach into other packages, not its ordinary
// sources.
func TestDepsDiff_AddedModuleUnanalyzedFiles(t *testing.T) {
	oldDir := appTree(t, "", nil, nil)
	newDir := appTree(t, "\t_ \"example.com/native/n\"\n", map[string]string{"example.com/native": "native"}, map[string]string{
		"lib/native/n/n.go":    "package n\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc N() int64 { return nanotime() }\n",
		"lib/native/n/cgo.go":  "package n\n\n// int add(int a, int b);\nimport \"C\"\n",
		"lib/native/n/a.c":     "int add(int a, int b) { return a + b; }\n",
		"lib/native/n/stub.s":  "// stub\n",
		"lib/native/n/x.syso":  "x",
		"lib/native/lib/z.so":  "z",
		"lib/native/n/skip.go": "//go:build ignore\n\npackage n\n",
	})
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	m := findModule(t, out, "example.com/native")
	want := []models.FileChange{
		{File: "n/n.go: //go:linkname nanotime runtime.nanotime", Kind: "linkname", Change: "added", RiskScore: models.RiskScoreHigh},
		{File: "lib/z.so", Kind: "object", Change: "added", RiskScore: 20},
		{File: "n/x.syso", Kind: "syso", Change: "added", RiskScore: 20},
	}
	if m.Status != models.ModuleAdded || !reflect.DeepEqual(m.Unanalyzed, want) {
		t.Errorf("added module %s, unanalyzed =\n%+v\nwant\n%+v", m.Status, m.Unanalyzed, want)
	}
	if m.RiskScore != 20 || m.HighRiskChanges != 3 || out.Summary.HighRiskChanges != 3 || out.Summary.ModulesAdded != 1 {
		t.Errorf("module risk %d (%d high), summary %+v; want 20, 3 high-risk changes, 1 added", m.RiskScore, m.HighRiskChanges, out.Summary)
	}
}

// A tree whose modules are not in the module cache is an error, not an
// empty diff: the loader may not download them.
func TestDepsDiff_MissingModule(t *testing.T) {
	missing := func() string {
		dir := t.TempDir()
		writeFilesIn(t, dir, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire example.com/missing v1.0.0\n",
			"main.go": "package main\n\nimport _ \"example.com/missing/m\"\n\nfunc main() {}\n",
		})
		return dir
	}
	good := appTree(t, "", nil, nil)
	for _, c := range []struct {
		name, oldDir, newDir, prefix string
	}{
		{"old", missing(), good, "old tree: "},
		{"new", good, missing(), "new tree: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := api.DepsDiff(c.oldDir, c.newDir)
			if err == nil {
				t.Fatalf("DepsDiff = %+v; want an error", out)
			}
			if msg := err.Error(); !strings.HasPrefix(msg, c.prefix) || !strings.Contains(msg, "go mod download") ||
				!strings.Contains(msg, "example.com/missing") {
				t.Errorf("error %q; want it to start %q, name the module and suggest go mod download", msg, c.prefix)
			}
		})
	}
}
