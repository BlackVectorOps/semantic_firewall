// -- builder.go --
package semanticfw

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Constructs Static Single Assignment form from loaded Go packages.
// Returns the complete program and the target package for analysis.
func BuildSSAFromPackages(initialPkgs []*packages.Package) (*ssa.Program, *ssa.Package, error) {
	if len(initialPkgs) == 0 {
		return nil, nil, fmt.Errorf("input packages list is empty")
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	// SECURITY IMPROVEMENT: Relaxed error handling.
	// Previously, we returned an error if *any* package had errors.
	// This prevented analyzing malware that imports missing packages.
	// Now we log them (optional) but proceed, as SSA construction
	// is often resilient enough to handle partial programs.
	if errorMessages.Len() > 0 {
		// In a real logging system, we'd log this. For now, we proceed.
	}

	// Initializes the SSA program builder for all packages and dependencies.
	// Enable InstantiateGenerics so generic function bodies are built in Go 1.18+.
	mode := ssa.InstantiateGenerics
	prog, pkgs := ssautil.AllPackages(initialPkgs, mode)
	if prog == nil {
		return nil, nil, fmt.Errorf("failed to initialize SSA program builder")
	}

	// CRITICAL BUG FIX: Performance / DoS Prevention
	// Previously, prog.Build() was called here. That method transitively builds SSA
	// for the ENTIRE dependency graph, including the Go standard library (runtime, net, etc.).
	// This caused massive memory usage and latency for simple files.
	// FIX: Iterate and build only the target packages we explicitly loaded.
	for _, p := range initialPkgs {
		if ssaPkg := prog.Package(p.Types); ssaPkg != nil {
			ssaPkg.Build()
		}
	}

	mainPkg := initialPkgs[0]
	var ssaPkg *ssa.Package

	// Robustly find the SSA package. ssautil.AllPackages preserves order,
	// so pkgs[0] corresponds to initialPkgs[0].
	if len(pkgs) > 0 && pkgs[0] != nil {
		ssaPkg = pkgs[0]
	}

	// Fallback lookup if index mapping failed
	if ssaPkg == nil && mainPkg.Types != nil {
		ssaPkg = prog.Package(mainPkg.Types)
	}

	if ssaPkg == nil {
		// Include package errors in the error message for better diagnostics
		if errorMessages.Len() > 0 {
			return nil, nil, fmt.Errorf("could not find main SSA package for %s (packages contain errors: %s)", mainPkg.ID, strings.TrimSpace(errorMessages.String()))
		}
		return nil, nil, fmt.Errorf("could not find main SSA package for %s", mainPkg.ID)
	}

	return prog, ssaPkg, nil
}
