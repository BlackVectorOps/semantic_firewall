package api

import (
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
)

// movedCapabilities finds the capability targets of added functions that a
// refactor moved rather than added: an existing function's direct call
// extracted into a new helper. added holds the topology of each added
// function. The result maps an added function to its moved targets, each
// with the callers it moved out of.
//
// A target of added function A moved only when all of these hold, so a move
// cannot bring a new capability, a new caller or a dropped guard with it:
//   - A is a package-level, unexported, non-generic function (see
//     movableHelper);
//   - every reference to A in its package is a direct call;
//   - every caller is the new version of a matched function whose old
//     version called the target directly and whose new version does not;
//   - when the old call ran under a condition, the call to A or the call
//     inside A still does.
func movedCapabilities(matched []diff.TopologyMatch, added map[*ssa.Function]*topology.FunctionTopology) map[*ssa.Function]map[string][]string {
	candidates := make(map[*ssa.Function]*topology.FunctionTopology)
	pkgs := make(map[*ssa.Package]bool)
	for fn, t := range added {
		if movableHelper(fn) && t != nil && len(t.Capabilities) > 0 && t.CapabilityGuards != nil {
			candidates[fn] = t
			pkgs[fn.Pkg] = true
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	pairs := make(map[*ssa.Function]diff.TopologyMatch, len(matched))
	for _, m := range matched {
		if fn := m.NewResult.GetSSAFunction(); fn != nil && m.OldTopology != nil && m.NewTopology != nil {
			pairs[fn] = m
		}
	}

	// A candidate referenced other than as the callee of a direct call can
	// run from anywhere its value goes, so it is dropped.
	callers := make(map[*ssa.Function][]*ssa.Function)
	for pkg := range pkgs {
		for _, fn := range diff.PackageFunctions(pkg.Prog, pkg) {
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					var common *ssa.CallCommon
					if call, ok := instr.(ssa.CallInstruction); ok && !call.Common().IsInvoke() {
						common = call.Common()
					}
					for _, op := range instr.Operands(nil) {
						f, ok := (*op).(*ssa.Function)
						if !ok || candidates[f] == nil {
							continue
						}
						if common == nil || op != &common.Value {
							delete(candidates, f)
						} else if cs := callers[f]; len(cs) == 0 || cs[len(cs)-1] != fn {
							callers[f] = append(cs, fn)
						}
					}
				}
			}
		}
	}

	var moved map[*ssa.Function]map[string][]string
	for fn, t := range candidates {
		// A helper nobody calls leaves from empty, and keeps its full score.
		cs := callers[fn]
		for target := range t.Capabilities {
			var from []string
			for _, caller := range cs {
				m, ok := pairs[caller]
				if !ok || !movedFrom(m, fn, t, target) {
					from = nil
					break
				}
				from = append(from, ResultName(m.NewResult))
			}
			if len(from) == 0 {
				continue
			}
			sort.Strings(from)
			if moved == nil {
				moved = make(map[*ssa.Function]map[string][]string)
			}
			if moved[fn] == nil {
				moved[fn] = make(map[string][]string)
			}
			moved[fn][target] = from
		}
	}
	return moved
}

// movableHelper reports whether fn can receive a moved capability. A method
// can be called through an interface and a closure through a func value,
// calls that no reference to them shows; an exported function can be called
// from other packages; a generic function is called through its instances;
// an init function runs without a caller.
func movableHelper(fn *ssa.Function) bool {
	return fn != nil && fn.Pkg != nil && fn.Object() != nil && fn.Parent() == nil &&
		fn.Signature.Recv() == nil && fn.TypeParams().Len() == 0 &&
		!token.IsExported(fn.Name()) && fn.Name() != "init" && !strings.HasPrefix(fn.Name(), "init#")
}

// movedFrom reports whether target moved out of the matched function m into
// helper, whose topology is ht: m's old version called target directly and
// its new version does not, and if the old call ran under a condition, the
// new version's calls to helper or helper's own call still do.
func movedFrom(m diff.TopologyMatch, helper *ssa.Function, ht *topology.FunctionTopology, target string) bool {
	if _, had := callTargetsOf(m.OldTopology)[target]; !had || m.OldTopology.Capabilities[target] == "" {
		return false
	}
	if _, has := callTargetsOf(m.NewTopology)[target]; has {
		return false
	}
	old, ok := m.OldTopology.CapabilityGuards[target]
	if !ok {
		return false
	}
	if old == 0 {
		return true
	}
	call, ok := topology.CallGuards(m.NewResult.GetSSAFunction(), helper)
	return ok && call+ht.CapabilityGuards[target] > 0
}
