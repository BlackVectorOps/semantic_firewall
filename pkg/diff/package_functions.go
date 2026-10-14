package diff

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// PackageFunctions lists every function with a body that a package
// contributes: package-level functions, methods of its named types, and,
// recursively, the closures they contain -- including the synthetic bodies of
// range-over-func loops. Ordered by name for deterministic output.
func PackageFunctions(prog *ssa.Program, pkg *ssa.Package) []*ssa.Function {
	names := make([]string, 0, len(pkg.Members))
	for name := range pkg.Members {
		names = append(names, name)
	}
	sort.Strings(names)

	var fns []*ssa.Function
	seen := make(map[*ssa.Function]bool)
	var add func(fn *ssa.Function)
	add = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		if len(fn.Blocks) > 0 {
			fns = append(fns, fn)
		}
		for _, anon := range fn.AnonFuncs {
			add(anon)
		}
	}

	for _, name := range names {
		switch m := pkg.Members[name].(type) {
		case *ssa.Function:
			add(m)
		case *ssa.Type:
			if named, ok := m.Type().(*types.Named); ok {
				for i := 0; i < named.NumMethods(); i++ {
					add(prog.FuncValue(named.Method(i)))
				}
			}
		}
	}
	return fns
}
