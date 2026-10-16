package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/token"
	"go/types"
	"go/version"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type FingerprintResult struct {
	FunctionName string
	Fingerprint  string
	CanonicalIR  string
	Pos          token.Pos
	Line         int
	Filename     string
	fn           *ssa.Function
}

func (r FingerprintResult) GetSSAFunction() *ssa.Function {
	return r.fn
}

type virtualControlFlowState struct {
	swappedBlocks map[*ssa.BasicBlock]bool
	virtualBinOps map[*ssa.BinOp]token.Token
}

func newVirtualControlFlowState() *virtualControlFlowState {
	return &virtualControlFlowState{
		swappedBlocks: make(map[*ssa.BasicBlock]bool),
		virtualBinOps: make(map[*ssa.BinOp]token.Token),
	}
}

func computeVirtualControlFlow(fn *ssa.Function) *virtualControlFlowState {
	state := newVirtualControlFlowState()

	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		if ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			if binOp, ok := ifInstr.Cond.(*ssa.BinOp); ok {
				isSafeToSwap := func(t types.Type) bool {
					if basic, ok := t.Underlying().(*types.Basic); ok {
						return (basic.Info() & (types.IsInteger | types.IsString)) != 0
					}
					return false
				}

				if !isSafeToSwap(binOp.X.Type()) || !isSafeToSwap(binOp.Y.Type()) {
					continue
				}

				// FIX: Re-enabled Referrers check.
				// We can only swap the operator (e.g. GEQ -> LSS) if we compensate by swapping the branches
				// of the If instruction. If the BinOp result is used by ANY other instruction (e.g. Return, Store, or another If),
				// the value they receive would be inverted, causing logic corruption.
				// We filter out DebugRef, as it doesn't impact program semantics.
				if refs := binOp.Referrers(); refs != nil {
					isSafe := true
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.DebugRef); ok {
							continue
						}
						// If the user is not THIS specific If instruction, it is unsafe to swap.
						if ref != ifInstr {
							isSafe = false
							break
						}
					}
					if !isSafe {
						continue
					}
				}

				var newOp token.Token
				swap := false
				switch binOp.Op {
				case token.GEQ:
					newOp = token.LSS
					swap = true
				case token.GTR:
					newOp = token.LEQ
					swap = true
				}

				if swap {
					if len(block.Succs) != 2 {
						continue
					}
					state.virtualBinOps[binOp] = newOp
					state.swappedBlocks[block] = true
				}
			}
		}
	}
	return state
}

const MaxFunctionBlocks = 5000

// rangeFuncYield is the Synthetic tag x/tools gives the closure holding the
// body of a range-over-func loop. Unlike other synthetic functions, it is
// user code.
const rangeFuncYield = "range-over-func yield"

// oversizedFingerprint hashes the raw SSA of a function too large to
// canonicalize. It is deterministic but not canonical: a rename can change it.
// A constant placeholder would instead make every change to such a function
// invisible -- padding a function past MaxFunctionBlocks would hide anything.
func oversizedFingerprint(fn *ssa.Function) string {
	h := sha256.New()
	fmt.Fprintf(h, "oversized\n%s\n", fn.Signature)
	for _, b := range fn.Blocks {
		fmt.Fprintf(h, "b%d:\n", b.Index)
		for _, instr := range b.Instrs {
			if v, ok := instr.(ssa.Value); ok && v.Name() != "" {
				fmt.Fprintf(h, "%s = ", v.Name())
			}
			fmt.Fprintf(h, "%s\n", instr)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// functionPosition returns the file and line of fn's position, as
// FingerprintResult reports them: where fn is written, whatever a //line
// directive says. A diff keeps a file's functions by this file, and a
// directive must not move a function out of the file it is in, nor into
// another.
func functionPosition(fn *ssa.Function) (filename string, line int) {
	if fn.Prog == nil || fn.Prog.Fset == nil {
		return "", 0
	}
	p := fn.Prog.Fset.PositionFor(fn.Pos(), false)
	return p.Filename, p.Line
}

func GenerateFingerprint(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool) FingerprintResult {
	filename, line := functionPosition(fn)

	if len(fn.Blocks) > MaxFunctionBlocks {
		return FingerprintResult{
			FunctionName: fn.RelString(nil),
			Fingerprint:  oversizedFingerprint(fn),
			CanonicalIR:  fmt.Sprintf("; Not canonicalized: function too large (%d blocks > %d); fingerprint is over raw SSA", len(fn.Blocks), MaxFunctionBlocks),
			Pos:          fn.Pos(),
			Line:         line,
			Filename:     filename,
			fn:           fn,
		}
	}

	virtualCF := computeVirtualControlFlow(fn)
	canonicalizer := ir.AcquireCanonicalizer(policy)
	defer ir.ReleaseCanonicalizer(canonicalizer)

	canonicalizer.StrictMode = strictMode
	canonicalizer.ApplyVirtualControlFlowFromState(virtualCF.swappedBlocks, virtualCF.virtualBinOps)
	canonicalIR := canonicalizer.CanonicalizeFunction(fn)

	hash := sha256.Sum256([]byte(canonicalIR))
	fingerprint := hex.EncodeToString(hash[:])

	return FingerprintResult{
		FunctionName: fn.RelString(nil),
		Fingerprint:  fingerprint,
		CanonicalIR:  canonicalIR,
		Pos:          fn.Pos(),
		Line:         line,
		Filename:     filename,
		fn:           fn,
	}
}

func FingerprintSource(filename string, src string, policy ir.LiteralPolicy) ([]FingerprintResult, error) {
	return FingerprintSourceAdvanced(filename, src, policy, false)
}

func FingerprintSourceAdvanced(filename string, src string, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	return FingerprintSourceWhere(filename, src, policy, strictMode, nil)
}

// FingerprintSourceWhere is FingerprintSourceAdvanced restricted as
// FingerprintPackagesWhere restricts FingerprintPackages.
func FingerprintSourceWhere(filename string, src string, policy ir.LiteralPolicy, strictMode bool, keep func(filename string) bool) ([]FingerprintResult, error) {
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	return FingerprintPackagesWhere(initialPkgs, policy, strictMode, keep)
}

// WorkspaceFile returns the go.work file that governs builds in dir as the
// go command finds it, the first in dir or a parent, or "" when there is
// none. The search stops at the repository's root, the first directory
// holding a .git entry: a tree checked out inside another must not take
// the outer tree's workspace.
func WorkspaceFile(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.work")); err == nil && !info.IsDir() {
			return filepath.Join(dir, "go.work")
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// HardenedEnvFor is GetHardenedEnv for loading packages in dir: it uses the
// workspace that governs dir (see WorkspaceFile), as the go command builds
// it, and none when there is none, and the vendor directory the go command
// builds dir from (see VendorDir), if any.
func HardenedEnvFor(dir string) []string {
	return withBuildDefaults(GetHardenedEnv(), dir)
}

// withBuildDefaults sets env's GOWORK to the workspace that governs dir and,
// when the go command would build dir from a vendor directory, GOFLAGS to
// -mod=vendor. GetHardenedEnv's GOFLAGS=-mod=readonly would otherwise
// override that default and demand the module cache for vendored modules.
func withBuildDefaults(env []string, dir string) []string {
	// The last value of a variable wins.
	if work := WorkspaceFile(dir); work != "" {
		env = append(env, "GOWORK="+work)
	}
	if VendorDir(dir) != "" {
		env = append(env, "GOFLAGS=-mod=vendor")
	}
	return env
}

// VendorDir returns the vendor directory the go command builds dir from,
// or "" when it builds from the module cache. As in the go command, that
// is the workspace's vendor directory when a go.work governs dir (see
// WorkspaceFile) and the go.work's go line is 1.22 or later, and otherwise
// the vendor directory of the module whose go.mod is nearest above dir when
// the go.mod's go line is 1.14 or later (a missing go line counts as 1.16,
// as the go command counts it). The directory must exist; whether it is
// consistent with the go.mod is the go command's to report.
func VendorDir(dir string) string {
	root, modFile, minVersion := "", "", "go1.14"
	if work := WorkspaceFile(dir); work != "" {
		root, modFile, minVersion = filepath.Dir(work), work, "go1.22"
	} else if root = moduleRootAbove(dir); root != "" {
		modFile = filepath.Join(root, "go.mod")
	} else {
		return ""
	}
	data, err := os.ReadFile(modFile)
	if err != nil {
		return ""
	}
	v := goDirective(data)
	if v == "" {
		// The go command's default for a go.mod without a go line; below
		// go1.22, so a go.work without one never vendors either.
		v = "1.16"
	}
	if version.Compare("go"+v, minVersion) < 0 {
		return ""
	}
	vendor := filepath.Join(root, "vendor")
	if info, err := os.Stat(vendor); err != nil || !info.IsDir() {
		return ""
	}
	return vendor
}

// moduleRootAbove returns the directory of the go.mod nearest at or above
// dir, as the go command finds a module, or "" when there is none.
func moduleRootAbove(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// goDirective returns the version of the `go <version>` line of a go.mod or
// go.work, or "" when there is none.
func goDirective(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			return fields[1]
		}
	}
	return ""
}

// GetHardenedEnv returns the environment for loading untrusted source: no
// cgo, no network (GOPROXY=off), a read-only module graph, no workspace
// (see HardenedEnvFor) and the local toolchain.
func GetHardenedEnv() []string {
	// FIX: Ensure return is OUTSIDE the loop so we don't truncate the environment.
	env := make([]string, 0, len(os.Environ())+7)
	for _, e := range os.Environ() {
		upperE := strings.ToUpper(e)
		switch {
		case strings.HasPrefix(upperE, "CGO_ENABLED="),
			strings.HasPrefix(upperE, "GOPROXY="),
			strings.HasPrefix(upperE, "GOFLAGS="),
			strings.HasPrefix(upperE, "GONOSUMDB="),
			strings.HasPrefix(upperE, "GOWORK="),
			strings.HasPrefix(upperE, "GO111MODULE="),
			strings.HasPrefix(upperE, "GOTOOLCHAIN="):
			continue
		}
		env = append(env, e)
	}
	env = append(env, "CGO_ENABLED=0", "GOPROXY=off", "GOFLAGS=-mod=readonly", "GONOSUMDB=*", "GOWORK=off", "GO111MODULE=on", "GOTOOLCHAIN=local")
	return env
}

func loadPackagesFromSource(filename string, src string) ([]*packages.Package, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("input source code is empty")
	}

	sourceDir := filepath.Dir(filename)
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", filename, err)
	}

	cfg := sourceLoaderConfig(sourceDir, map[string][]byte{absFilename: []byte(src)})

	// A file the host build leaves out (a GOOS/GOARCH name suffix, or a
	// //go:build line that does not hold for this host) is loaded under a
	// configuration that includes it, chosen before the first load. A load
	// under the host's would not always report it missing: when it is the
	// only Go file of its directory, or outside any module, go list builds
	// an ad-hoc package of the one file under the host's GOOS and GOARCH,
	// with its build constraints ignored, where its platform's API is
	// undefined and its sizes are the host's. A file no known configuration
	// includes is loaded that way.
	if goos, goarch, tags, ok := buildConfigFor(absFilename, src); ok && (goos != build.Default.GOOS || goarch != build.Default.GOARCH || len(tags) > 0) {
		cfg.Env = append(cfg.Env, "GOOS="+goos, "GOARCH="+goarch)
		if len(tags) > 0 {
			cfg.BuildFlags = []string{"-tags=" + strings.Join(tags, ",")}
		}
	}

	initialPkgs, err := loadSource(cfg, "file="+absFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}

	// A _test.go file is in none of the loaded packages. Reload with the
	// package's tests.
	if !packagesContain(initialPkgs, absFilename) && strings.HasSuffix(absFilename, "_test.go") {
		cfg.Tests = true
		if initialPkgs, err = loadSource(cfg, "file="+absFilename); err != nil {
			return nil, fmt.Errorf("failed to execute loader: %w", err)
		}
	}
	// A file its directory's package leaves out under every configuration
	// (a //go:build ignore script beside the package's files) is in none of
	// the loaded packages either. Load it alone, as `go build file.go`
	// builds it: an ad-hoc package of the one file, its constraints ignored.
	if !packagesContain(initialPkgs, absFilename) {
		if initialPkgs, err = loadSource(cfg, absFilename); err != nil {
			return nil, fmt.Errorf("failed to execute loader: %w", err)
		}
	}
	if cfg.Tests {
		// Keep only the test variant that compiles this file, not the
		// package itself or the synthesized test main.
		var withFile []*packages.Package
		for _, p := range initialPkgs {
			if packagesContain([]*packages.Package{p}, absFilename) {
				withFile = append(withFile, p)
			}
		}
		initialPkgs = withFile
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	if len(initialPkgs) == 0 && errorMessages.Len() > 0 {
		return nil, fmt.Errorf("packages contain errors and no packages were loaded: \n%s", errorMessages.String())
	}

	return initialPkgs, nil
}

// sourceLoaderConfig is the go/packages configuration every source load
// uses: full syntax and types for the whole import graph, the hardened
// environment (CGO_ENABLED=0, GOPROXY=off, GOFLAGS=-mod=readonly,
// GOTOOLCHAIN=local) with the workspace that governs dir, no test
// variants, and the given file contents as overlays.
func sourceLoaderConfig(dir string, overlay map[string][]byte) *packages.Config {
	return &packages.Config{
		Dir:     dir,
		Mode:    packages.LoadAllSyntax,
		Fset:    token.NewFileSet(),
		Overlay: overlay,
		Tests:   false,
		Env:     HardenedEnvFor(dir),
	}
}

// LoadFiles loads, with one go/packages call run from dir, the packages
// that compile the given files: absolute paths mapped to their contents,
// which are used as overlays. It uses the same configuration as the
// single-file loader behind FingerprintSource, so a package loads the same
// way either way. Unlike FingerprintSource it does not retry a file the
// default build leaves out (a _test.go file, a GOOS suffix, a //go:build
// line): such a file is in none of the returned packages, and
// PackagesContain reports it.
func LoadFiles(dir string, files map[string][]byte) ([]*packages.Package, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files to load")
	}
	patterns := make([]string, 0, len(files))
	for f := range files {
		patterns = append(patterns, "file="+f)
	}
	sort.Strings(patterns)
	pkgs, err := loadSource(sourceLoaderConfig(dir, files), patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}
	return pkgs, nil
}

// PackagesContain reports whether any of pkgs compiles the file at absPath.
func PackagesContain(pkgs []*packages.Package, absPath string) bool {
	return packagesContain(pkgs, filepath.Clean(absPath))
}

// packagesContain reports whether any of pkgs compiles the file at absPath.
func packagesContain(pkgs []*packages.Package, absPath string) bool {
	for _, p := range pkgs {
		for _, files := range [][]string{p.GoFiles, p.CompiledGoFiles} {
			for _, f := range files {
				if filepath.Clean(f) == absPath {
					return true
				}
			}
		}
	}
	return false
}

// knownPlatforms are GOOS/GOARCH pairs tried, after the host's own, when a
// file's build constraints exclude it from the host build. All are valid
// `go tool dist list` targets.
var knownPlatforms = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "386"}, {"linux", "arm"},
	{"linux", "ppc64le"}, {"linux", "s390x"}, {"linux", "riscv64"}, {"linux", "loong64"},
	{"linux", "mips64le"}, {"darwin", "arm64"}, {"darwin", "amd64"},
	{"windows", "amd64"}, {"windows", "arm64"}, {"windows", "386"},
	{"freebsd", "amd64"}, {"freebsd", "arm64"}, {"netbsd", "amd64"}, {"openbsd", "amd64"},
	{"dragonfly", "amd64"}, {"solaris", "amd64"}, {"illumos", "amd64"}, {"aix", "ppc64"},
	{"android", "arm64"}, {"ios", "arm64"}, {"js", "wasm"}, {"wasip1", "wasm"}, {"plan9", "amd64"},
}

// maxCustomTags bounds the tag subsets buildConfigFor tries (2^n).
const maxCustomTags = 4

// buildConfigFor finds a GOOS, GOARCH and set of custom build tags under
// which the file's name suffix and //go:build line include it, using
// go/build's own constraint matching on src. Cgo is assumed disabled, as
// the loader runs with CGO_ENABLED=0.
func buildConfigFor(absFilename, src string) (goos, goarch string, tags []string, ok bool) {
	ctxt := build.Default
	ctxt.CgoEnabled = false
	ctxt.OpenFile = func(path string) (io.ReadCloser, error) {
		if filepath.Clean(path) == absFilename {
			return io.NopCloser(strings.NewReader(src)), nil
		}
		return os.Open(path)
	}
	custom := customBuildTags(src)
	if len(custom) > maxCustomTags {
		custom = custom[:maxCustomTags]
	}
	platforms := append([][2]string{{build.Default.GOOS, build.Default.GOARCH}}, knownPlatforms...)
	dir, name := filepath.Dir(absFilename), filepath.Base(absFilename)
	for _, p := range platforms {
		for mask := 0; mask < 1<<len(custom); mask++ {
			var set []string
			for i, t := range custom {
				if mask&(1<<i) != 0 {
					set = append(set, t)
				}
			}
			ctxt.GOOS, ctxt.GOARCH, ctxt.BuildTags = p[0], p[1], set
			if match, err := ctxt.MatchFile(dir, name); err == nil && match {
				return p[0], p[1], set, true
			}
		}
	}
	return "", "", nil, false
}

// customBuildTags returns, sorted, the tags in src's //go:build lines that
// are not platform, toolchain or release tags and so must be supplied with
// -tags. The ignore tag is never supplied: it marks files no build is meant
// to include (generators in the standard library among them), and a build
// with it set fails everywhere.
func customBuildTags(src string) []string {
	platform := map[string]bool{"unix": true, "cgo": true, "gc": true, "gccgo": true, "ignore": true}
	for _, p := range knownPlatforms {
		platform[p[0]], platform[p[1]] = true, true
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			continue
		}
		var walk func(constraint.Expr)
		walk = func(e constraint.Expr) {
			switch e := e.(type) {
			case *constraint.TagExpr:
				if !platform[e.Tag] && !strings.HasPrefix(e.Tag, "go1.") && !strings.HasPrefix(e.Tag, "goexperiment.") {
					seen[e.Tag] = true
				}
			case *constraint.NotExpr:
				walk(e.X)
			case *constraint.AndExpr:
				walk(e.X)
				walk(e.Y)
			case *constraint.OrExpr:
				walk(e.X)
				walk(e.Y)
			}
		}
		walk(expr)
	}
	tags := make([]string, 0, len(seen))
	for t := range seen {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func FingerprintPackages(initialPkgs []*packages.Package, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	return FingerprintPackagesWhere(initialPkgs, policy, strictMode, nil)
}

// FingerprintPackagesWhere is FingerprintPackages for the functions whose
// file, as FingerprintResult.Filename names it, keep accepts, and those
// without a file; a nil keep accepts every file. The other functions are
// not canonicalized: a diff of a few files of a large package reads only
// their functions.
func FingerprintPackagesWhere(initialPkgs []*packages.Package, policy ir.LiteralPolicy, strictMode bool, keep func(filename string) bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	prog, _, err := ir.BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	var results []FingerprintResult
	visited := make(map[*ssa.Function]bool)
	accept := func(fn *ssa.Function) bool {
		file, _ := functionPosition(fn)
		return keep == nil || file == "" || keep(file)
	}

	for _, pkg := range initialPkgs {
		if pkg.Types == nil {
			continue
		}

		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		for _, member := range ssaPkg.Members {
			switch mem := member.(type) {
			case *ssa.Function:
				processFunctionAndAnons(mem, policy, strictMode, &results, visited, accept)
			case *ssa.Type:
				if named, ok := mem.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						m := named.Method(i)
						if fn := prog.FuncValue(m); fn != nil {
							processFunctionAndAnons(fn, policy, strictMode, &results, visited, accept)
						}
					}
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].FunctionName < results[j].FunctionName
	})

	return results, nil
}

// processFunctionAndAnons fingerprints fn, when accept accepts it, and its
// anonymous functions, which accept judges on their own: a //line
// directive can place a closure in another file than its parent.
func processFunctionAndAnons(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool, results *[]FingerprintResult, visited map[*ssa.Function]bool, accept func(*ssa.Function) bool) {
	if visited[fn] {
		return
	}
	visited[fn] = true

	if fn.Synthetic != "" && fn.Name() != "init" && fn.Synthetic != rangeFuncYield {
		return
	}

	if len(fn.Blocks) > 0 && accept(fn) {
		result := GenerateFingerprint(fn, policy, strictMode)
		*results = append(*results, result)
	}

	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results, visited, accept)
	}
}
