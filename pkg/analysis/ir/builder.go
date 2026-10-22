package ir

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// BuildProgram builds the SSA program of the loaded packages: their bodies,
// and their dependencies' members without bodies. Package errors don't stop
// it, since SSA skips ill-typed packages, but it fails when the first
// package could not be built, with the packages' errors in the message.
func BuildProgram(initialPkgs []*packages.Package) (*ssa.Program, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	// pkgs[i] is nil when initialPkgs[i] has no types or is ill-typed: SSA
	// creates no package for it.
	prog, pkgs := ssautil.AllPackages(initialPkgs, ssa.InstantiateGenerics)
	for _, p := range pkgs {
		if p != nil {
			p.Build()
		}
	}

	if pkgs[0] == nil {
		mainPkg := initialPkgs[0]
		if errorMessages.Len() > 0 {
			return nil, fmt.Errorf("could not find main SSA package for %s (packages contain errors: %s)", mainPkg.ID, strings.TrimSpace(errorMessages.String()))
		}
		return nil, fmt.Errorf("could not find main SSA package for %s", mainPkg.ID)
	}
	return prog, nil
}

// BuildSSAFromPackages is BuildProgram that also returns the first
// package's SSA package.
//
// Deprecated: Use BuildProgram, and prog.Package(initialPkgs[0].Types) for
// the package.
func BuildSSAFromPackages(initialPkgs []*packages.Package) (*ssa.Program, *ssa.Package, error) {
	prog, err := BuildProgram(initialPkgs)
	if err != nil {
		return nil, nil, err
	}
	return prog, prog.Package(initialPkgs[0].Types), nil
}
