package topology

import (
	"go/types"
	"strings"
	"unicode"

	"golang.org/x/tools/go/ssa"
)

// maxCheckHelperDepth bounds how far collectCheckHelpers follows static
// calls when deciding whether a helper performs a verification.
const maxCheckHelperDepth = 3

// collectCheckHelpers adds to t.Checks the calls that act as verifications
// without being one of the primitives IsVerificationCall lists:
//   - a static call to a function whose body, following static calls up to
//     maxCheckHelperDepth deep, calls a verification primitive;
//   - a call, static or through an interface, whose name contains a
//     verification word (authorize, verify, validate, ...; see
//     isVerificationName) and whose result decides a branch or is returned.
//
// Static calls are keyed like CallTargets; interface calls are keyed by the
// interface type and method, "(example.com/p.Verifier).Verify".
func collectCheckHelpers(fn *ssa.Function, t *FunctionTopology) {
	memo := make(map[*ssa.Function]bool)
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			if call.Call.IsInvoke() {
				m := call.Call.Method
				if isVerificationName(m.Name()) && resultDecides(call) {
					t.Checks["("+types.TypeString(call.Call.Value.Type(), nil)+")."+m.Name()] = true
				}
				continue
			}
			callee := call.Call.StaticCallee()
			if callee == nil || callee.Parent() != nil {
				continue
			}
			pkgPath, recv, name, ok := calleeIdentity(callee)
			if !ok || IsVerificationCall(pkgPath, recv, name) {
				continue
			}
			if (isVerificationName(name) && resultDecides(call)) || reachesVerification(callee, maxCheckHelperDepth, memo) {
				t.Checks[callTargetKey(pkgPath, recv, name)] = true
			}
		}
	}
}

// reachesVerification reports whether fn's body calls a verification
// primitive, directly or through static calls to functions with bodies, at
// most depth calls deep. Functions of packages that were loaded but not
// built have no body and end the search.
func reachesVerification(fn *ssa.Function, depth int, memo map[*ssa.Function]bool) bool {
	if depth <= 0 || len(fn.Blocks) == 0 {
		return false
	}
	if found, ok := memo[fn]; ok {
		return found
	}
	memo[fn] = false // cycle guard
	found := false
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				callee, ok := (*op).(*ssa.Function)
				if !ok {
					continue
				}
				if pkgPath, recv, name, ok := calleeIdentity(callee); ok && IsVerificationCall(pkgPath, recv, name) {
					found = true
				} else if reachesVerification(callee, depth-1, memo) {
					found = true
				}
				if found {
					memo[fn] = true
					return true
				}
			}
		}
	}
	return false
}

// resultDecides reports whether a call's result, possibly after negation, a
// comparison, a tuple extract or a phi, is the condition of a branch or is
// returned to the caller (which then decides on it).
func resultDecides(call *ssa.Call) bool {
	seen := make(map[ssa.Value]bool)
	var decides func(v ssa.Value, depth int) bool
	decides = func(v ssa.Value, depth int) bool {
		if depth > 4 || seen[v] || v.Referrers() == nil {
			return false
		}
		seen[v] = true
		for _, ref := range *v.Referrers() {
			switch r := ref.(type) {
			case *ssa.If, *ssa.Return:
				return true
			case *ssa.UnOp:
				if r.Op.String() == "!" && decides(r, depth+1) {
					return true
				}
			case *ssa.BinOp, *ssa.Extract, *ssa.Phi, *ssa.ChangeType:
				if decides(r.(ssa.Value), depth+1) {
					return true
				}
			}
		}
		return false
	}
	return decides(call, 0)
}

// verificationWords are word prefixes that mark a function name as a
// verification: authorize, authenticate, verify, validate, permission,
// allowed, isAdmin, hasRole, csrf ...
var verificationWords = []string{
	"auth", "verif", "valid", "permi", "allow", "admin", "acl", "csrf", "xsrf",
	"signature", "privilege", "owner", "role", "access",
}

// isVerificationName reports whether a camelCase or snake_case function
// name contains a word starting with one of verificationWords.
func isVerificationName(name string) bool {
	for _, w := range splitWords(name) {
		for _, p := range verificationWords {
			if strings.HasPrefix(w, p) {
				return true
			}
		}
	}
	return false
}

// splitWords splits an identifier into lower-cased words at underscores,
// lower-to-upper transitions and the end of an upper-case run:
// "isCSRFTokenValid" -> is, csrf, token, valid.
func splitWords(name string) []string {
	rs := []rune(name)
	var words []string
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(string(rs[start:end])))
		}
		start = end
	}
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '_' || unicode.IsDigit(rs[i]):
			flush(i)
			start = i + 1
		case i > start && unicode.IsUpper(rs[i]) &&
			(unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]))):
			flush(i)
		}
	}
	flush(len(rs))
	return words
}
