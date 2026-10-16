// -- internal/cli/scan.go --
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/storage/pebbledb"
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// -- Public API --

func RunScan(target string, opts models.ScanOptions, noSandbox bool) error {
	fsys := RealFileSystem{}
	sb := RealSandboxer{}
	pkgLoader := RealPackageLoader{}

	cleanTarget := filepath.Clean(target)

	// Resolve database path BEFORE entering the sandbox.
	if opts.DBPath == "" {
		opts.DBPath = ResolveDBPath("")
	}
	if opts.DBPath != "" {
		if abs, err := filepath.Abs(opts.DBPath); err == nil {
			opts.DBPath = abs
		}
	}

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{"--target", cleanTarget}
		args = append(args, "--threshold", fmt.Sprintf("%f", opts.Threshold))
		args = append(args, "--deps-depth", opts.DepsDepth)

		if opts.ExactOnly {
			args = append(args, "--exact")
		}
		if opts.ScanDeps {
			args = append(args, "--deps")
		}

		var inputs []string
		inputs = append(inputs, cleanTarget)

		if opts.DBPath != "" {
			args = append(args, "--db", opts.DBPath)
			inputs = append(inputs, opts.DBPath)
		}

		return SandboxExec(sb, os.Stdout, os.Stderr, "scan", args, inputs...)
	}

	return RunScanLogic(fsys, pkgLoader, cleanTarget, opts)
}

// -- Core Logic --

func RunScanLogic(fsys FileSystem, pkgLoader PackageLoader, target string, opts models.ScanOptions) error {
	files, err := CollectFiles(fsys, target)
	if err != nil {
		return fmt.Errorf("collect files failed: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	var (
		allAlerts      []detection.ScanResult
		totalFunctions int
		depsScanned    int
		scannedDeps    []string
		backend        string
		scanner        SignatureScanner
	)

	// DB Initialization
	if !IsJSON(opts.DBPath) {
		backend = models.BackendPebbleDB

		// Use shared helper logic to handle sandbox environments robustly
		safeDBPath, cleanup, err := PrepareSandboxDB(opts.DBPath)
		if err != nil {
			return fmt.Errorf("failed to prepare pebbledb: %w", err)
		}
		defer cleanup()

		scanOpts := pebbledb.DefaultPebbleScannerOptions()
		scanOpts.MatchThreshold = opts.Threshold
		scanOpts.ReadOnly = true

		ps, err := pebbledb.NewPebbleScanner(safeDBPath, scanOpts)
		if err != nil {
			return fmt.Errorf("failed to open pebbledb: %w", err)
		}
		defer ps.Close()
		scanner = ps
	} else {
		backend = models.BackendJSON
		js := jsondb.NewScanner()
		if err := js.LoadDatabase(opts.DBPath); err != nil {
			return fmt.Errorf("failed to load json db: %w", err)
		}
		if opts.ExactOnly {
			js.SetThreshold(1.0)
		} else {
			js.SetThreshold(opts.Threshold)
		}
		scanner = js
	}

	allAlerts, totalFunctions, err = RunScanParallel(fsys, files, scanner, opts.ExactOnly)
	if err != nil {
		return err
	}

	if opts.ScanDeps {
		depAlerts, depFuncs, deps, depErr := RunScanDeps(pkgLoader, target, opts, scanner)
		if depErr != nil {
			return fmt.Errorf("dependency scan failed: %w", depErr)
		}
		allAlerts = append(allAlerts, depAlerts...)
		depsScanned = depFuncs
		scannedDeps = deps
	}

	// Deterministic Sort
	sort.Slice(allAlerts, func(i, j int) bool {
		if allAlerts[i].MatchedFunction != allAlerts[j].MatchedFunction {
			return allAlerts[i].MatchedFunction < allAlerts[j].MatchedFunction
		}
		return allAlerts[i].SignatureName < allAlerts[j].SignatureName
	})

	summary := models.ScanSummary{TotalAlerts: len(allAlerts)}
	for _, alert := range allAlerts {
		switch alert.Severity {
		case models.SeverityCritical:
			summary.CriticalAlerts++
		case models.SeverityHigh:
			summary.HighAlerts++
		case models.SeverityMedium:
			summary.MediumAlerts++
		case models.SeverityLow:
			summary.LowAlerts++
		}
	}

	output := models.ScanOutput{
		Target:       target,
		Database:     opts.DBPath,
		Backend:      backend,
		Threshold:    opts.Threshold,
		TotalScanned: totalFunctions + depsScanned,
		DepsScanned:  depsScanned,
		Alerts:       allAlerts,
		Summary:      summary,
		ScannedDeps:  scannedDeps,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// -- Helpers --

func RunScanParallel(fsys FileSystem, files []string, scanner SignatureScanner, exactOnly bool) ([]detection.ScanResult, int, error) {
	var (
		allAlerts      []detection.ScanResult
		totalFunctions int
		mu             sync.Mutex
	)

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(runtime.GOMAXPROCS(0))

	for _, file := range files {
		f := file
		g.Go(func() error {
			// Panic recovery for robust scanning
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "warning: panic recovered analyzing %s: %v\n", f, r)
				}
			}()

			results, err := LoadAndFingerprint(fsys, f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", f, err)
				return nil
			}

			localAlerts := []detection.ScanResult{}
			localCount := 0

			for _, result := range results {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				fn := result.GetSSAFunction()
				if fn == nil {
					continue
				}
				topo := topology.ExtractTopology(fn)
				if topo == nil {
					continue
				}

				localCount++
				funcName := resultName(result)

				if exactOnly {
					if alert, err := scanner.ScanTopologyExact(topo, funcName); err == nil && alert != nil {
						localAlerts = append(localAlerts, *alert)
					}
				} else {
					if alerts, err := scanner.ScanTopology(topo, funcName); err == nil {
						localAlerts = append(localAlerts, alerts...)
					}
				}
			}

			mu.Lock()
			allAlerts = append(allAlerts, localAlerts...)
			totalFunctions += localCount
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, 0, err
	}

	return allAlerts, totalFunctions, nil
}

func RunScanDeps(pkgLoader PackageLoader, target string, opts models.ScanOptions, scanner SignatureScanner) ([]detection.ScanResult, int, []string, error) {
	roots, err := loadPackagesWithDeps(pkgLoader, target)
	if err != nil {
		return nil, 0, nil, err
	}

	deps := selectDependencies(roots, opts.DepsDepth == "transitive")
	if len(deps) == 0 {
		return nil, 0, []string{}, nil
	}

	// One SSA program spans the whole import graph so cross-package calls
	// resolve; only the dependencies being scanned have their bodies built.
	var prog *ssa.Program
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "warning: panic during SSA construction: %v\n", r)
			}
		}()
		prog, _ = ssautil.AllPackages(roots, ssa.InstantiateGenerics)
	}()
	if prog == nil {
		return nil, 0, nil, fmt.Errorf("failed to construct SSA for dependencies of %s", target)
	}

	var (
		allAlerts      []detection.ScanResult
		totalFunctions int
		scannedDeps    = []string{}
	)
	for _, pkg := range deps {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			fmt.Fprintf(os.Stderr, "warning: skipping dependency %s: package did not type-check\n", pkg.PkgPath)
			continue
		}
		if !buildPackage(ssaPkg) {
			continue
		}
		scannedDeps = append(scannedDeps, pkg.PkgPath)

		for _, fn := range diff.PackageFunctions(prog, ssaPkg) {
			totalFunctions++
			allAlerts = append(allAlerts, scanFunction(fn, ssaFunctionName(fn), scanner, opts.ExactOnly)...)
		}
	}

	return allAlerts, totalFunctions, scannedDeps, nil
}

func buildPackage(pkg *ssa.Package) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping dependency %s: panic during SSA build: %v\n", pkg.Pkg.Path(), r)
			ok = false
		}
	}()
	pkg.Build()
	return true
}

func scanFunction(fn *ssa.Function, funcName string, scanner SignatureScanner, exactOnly bool) []detection.ScanResult {
	topo := topology.ExtractTopology(fn)
	if topo == nil {
		return nil
	}
	if exactOnly {
		alert, err := scanner.ScanTopologyExact(topo, funcName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: scanning %s: %v\n", funcName, err)
			return nil
		}
		if alert != nil {
			return []detection.ScanResult{*alert}
		}
		return nil
	}
	alerts, err := scanner.ScanTopology(topo, funcName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: scanning %s: %v\n", funcName, err)
	}
	return alerts
}

// loadPackagesWithDeps loads the target with its full import graph. Without
// NeedDeps, imported packages are placeholders with no types or syntax and
// nothing in them can be scanned -- even for a "direct" scan.
func loadPackagesWithDeps(pkgLoader PackageLoader, target string) ([]*packages.Package, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps |
		packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule

	var dir string
	var pattern string
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		dir = target
		pattern = "./..."
	} else {
		dir = filepath.Dir(target)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		pattern = "file=" + absTarget
	}

	cfg := &packages.Config{
		Mode:  mode,
		Dir:   dir,
		Tests: false,
		Env:   diff.HardenedEnvFor(dir),
	}
	return pkgLoader.Load(cfg, pattern)
}

// selectDependencies returns the third-party packages to scan, sorted by
// import path. Packages of the target's own module(s) are traversed but never
// reported as dependencies, so an external package counts as a direct
// dependency when any of the project's packages imports it -- not only the
// root package. Transitive mode additionally follows dependencies' imports.
// Standard library packages are skipped.
func selectDependencies(roots []*packages.Package, transitive bool) []*packages.Package {
	ownModules := make(map[string]bool)
	for _, p := range roots {
		if p.Module != nil {
			ownModules[p.Module.Path] = true
		}
	}

	deps := make(map[string]*packages.Package)
	visited := make(map[*packages.Package]bool)
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if visited[p] {
			return
		}
		visited[p] = true
		for _, imp := range p.Imports {
			if isStdlibPackage(imp) {
				continue
			}
			if imp.Module != nil && ownModules[imp.Module.Path] {
				visit(imp)
				continue
			}
			deps[imp.PkgPath] = imp
			if transitive {
				visit(imp)
			}
		}
	}
	for _, r := range roots {
		visit(r)
	}

	paths := make([]string, 0, len(deps))
	for path := range deps {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := make([]*packages.Package, 0, len(paths))
	for _, path := range paths {
		out = append(out, deps[path])
	}
	return out
}

// isStdlibPackage reports whether p belongs to the standard library: it has
// no module and its first path element has no dot (third-party import paths
// start with a domain). Std-vendored packages ("vendor/golang.org/x/...")
// therefore count as standard library too.
func isStdlibPackage(p *packages.Package) bool {
	if p.Module != nil {
		return false
	}
	first, _, _ := strings.Cut(p.PkgPath, "/")
	return !strings.Contains(first, ".")
}
