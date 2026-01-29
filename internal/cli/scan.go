// -- internal/cli/scan.go --
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
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
		if opts.DBPath != "" {
			args = append(args, "--db", opts.DBPath)
		}

		return SandboxExec(sb, os.Stdout, os.Stderr, "scan", args, cleanTarget, opts.DBPath)
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
		backend = "pebbledb"
		scanOpts := pebbledb.DefaultPebbleScannerOptions()
		scanOpts.MatchThreshold = opts.Threshold
		scanOpts.ReadOnly = true

		ps, err := pebbledb.NewPebbleScanner(opts.DBPath, scanOpts)
		if err != nil {
			return fmt.Errorf("failed to open pebbledb: %w", err)
		}
		defer ps.Close()
		scanner = ps
	} else {
		backend = "json"
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
		case "CRITICAL":
			summary.CriticalAlerts++
		case "HIGH":
			summary.HighAlerts++
		case "MEDIUM":
			summary.MediumAlerts++
		case "LOW":
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
				funcName := ShortFunctionName(result.FunctionName)

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
	pkgs, err := loadPackagesWithDeps(pkgLoader, target, opts.DepsDepth == "transitive")
	if err != nil {
		return nil, 0, nil, err
	}

	depPkgs := make(map[string]*packages.Package)
	visited := make(map[string]bool)
	for _, pkg := range pkgs {
		collectDependencies(pkg, depPkgs, opts.DepsDepth == "transitive", visited)
	}

	if len(depPkgs) == 0 {
		return nil, 0, []string{}, nil
	}

	var pkgKeys []string
	for k := range depPkgs {
		pkgKeys = append(pkgKeys, k)
	}
	sort.Strings(pkgKeys)

	var depSlice []*packages.Package
	for _, k := range pkgKeys {
		depSlice = append(depSlice, depPkgs[k])
	}

	var (
		allAlerts      []detection.ScanResult
		totalFunctions int
		scannedDeps    []string
		mu             sync.Mutex
	)

	const batchSize = 50
	for batchStart := 0; batchStart < len(depSlice); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(depSlice) {
			batchEnd = len(depSlice)
		}
		batch := depSlice[batchStart:batchEnd]

		prog, err := ssautil.AllPackages(batch, ssa.InstantiateGenerics)
		if err != nil || prog == nil {
			fmt.Fprintf(os.Stderr, "warning: failed to build SSA for batch: %v\n", err)
			continue
		}
		prog.Build()

		for _, pkg := range batch {
			pkgPath := pkg.PkgPath
			mu.Lock()
			scannedDeps = append(scannedDeps, pkgPath)
			mu.Unlock()

			ssaPkg := prog.Package(pkg.Types)
			if ssaPkg == nil {
				continue
			}

			for _, member := range ssaPkg.Members {
				switch m := member.(type) {
				case *ssa.Function:
					if m == nil || len(m.Blocks) == 0 {
						continue
					}
					funcName := ShortFunctionName(m.String())
					alerts := scanFunction(m, funcName, scanner, opts.ExactOnly)
					mu.Lock()
					allAlerts = append(allAlerts, alerts...)
					totalFunctions++
					mu.Unlock()
				case *ssa.Type:
					if named, ok := m.Type().(*types.Named); ok {
						for i := 0; i < named.NumMethods(); i++ {
							method := named.Method(i)
							fn := prog.FuncValue(method)
							if fn == nil || len(fn.Blocks) == 0 {
								continue
							}
							funcName := ShortFunctionName(fn.String())
							alerts := scanFunction(fn, funcName, scanner, opts.ExactOnly)
							mu.Lock()
							allAlerts = append(allAlerts, alerts...)
							totalFunctions++
							mu.Unlock()
						}
					}
				}
			}
		}

		prog = nil
		runtime.GC()
	}

	sort.Strings(scannedDeps)
	return allAlerts, totalFunctions, scannedDeps, nil
}

func scanFunction(fn *ssa.Function, funcName string, scanner SignatureScanner, exactOnly bool) []detection.ScanResult {
	topo := topology.ExtractTopology(fn)
	if topo == nil {
		return nil
	}
	if exactOnly {
		if alert, err := scanner.ScanTopologyExact(topo, funcName); err == nil && alert != nil {
			return []detection.ScanResult{*alert}
		}
		return nil
	}
	alerts, _ := scanner.ScanTopology(topo, funcName)
	return alerts
}

func loadPackagesWithDeps(pkgLoader PackageLoader, target string, transitive bool) ([]*packages.Package, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	if transitive {
		mode |= packages.NeedDeps
	}

	var dir string
	var pattern string
	info, err := os.Stat(target) // We still use OS stat for the target path resolution initially
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
		Env:   diff.GetHardenedEnv(),
	}
	return pkgLoader.Load(cfg, pattern)
}

func collectDependencies(pkg *packages.Package, deps map[string]*packages.Package, transitive bool, visited map[string]bool) {
	if pkg == nil || visited[pkg.PkgPath] {
		return
	}
	visited[pkg.PkgPath] = true
	for importPath, importPkg := range pkg.Imports {
		if !strings.Contains(importPath, ".") && !strings.Contains(importPath, "/") {
			continue
		}
		if _, ok := deps[importPath]; ok {
			continue
		}
		deps[importPath] = importPkg
		if transitive {
			collectDependencies(importPkg, deps, transitive, visited)
		}
	}
}
