package ir

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// BuildSSAFromPackages constructs Static Single Assignment form from loaded Go packages.
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

	// Log errors but proceed if possible
	if errorMessages.Len() > 0 {
		// In a real system, log these errors
	}

	mode := ssa.InstantiateGenerics
	prog, pkgs := ssautil.AllPackages(initialPkgs, mode)
	if prog == nil {
		return nil, nil, fmt.Errorf("failed to initialize SSA program builder")
	}

	// Performance optimization: Only build the packages we explicitly loaded.
	for _, p := range initialPkgs {
		if ssaPkg := prog.Package(p.Types); ssaPkg != nil {
			ssaPkg.Build()
		}
	}

	mainPkg := initialPkgs[0]
	var ssaPkg *ssa.Package

	if len(pkgs) > 0 && pkgs[0] != nil {
		ssaPkg = pkgs[0]
	}

	if ssaPkg == nil && mainPkg.Types != nil {
		ssaPkg = prog.Package(mainPkg.Types)
	}

	if ssaPkg == nil {
		if errorMessages.Len() > 0 {
			return nil, nil, fmt.Errorf("could not find main SSA package for %s (packages contain errors: %s)", mainPkg.ID, strings.TrimSpace(errorMessages.String()))
		}
		return nil, nil, fmt.Errorf("could not find main SSA package for %s", mainPkg.ID)
	}

	return prog, ssaPkg, nil
}
