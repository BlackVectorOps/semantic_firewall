package topology

import (
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/tools/go/ssa"
)

// maxCheckHelperDepth bounds how far collectCheckHelpers follows static
// calls when deciding whether a helper performs a verification.
const maxCheckHelperDepth = 3

// collectCheckHelpers records in t.Checks the calls that verify something:
//   - a call of a primitive IsVerificationCall lists, when its result
//     decides a branch or is returned;
//   - a static call to a function of the same package whose body, following
//     static calls within that package up to maxCheckHelperDepth deep, makes
//     such a call, when the call's result decides a branch or is returned,
//     or the helper has no result (it panics or exits on failure). The
//     primitives it reaches are recorded too, so moving a check into a
//     helper does not read as removing it;
//   - a call, static or through an interface, whose name contains a
//     verification word (authorize, verify, validate, ...; see
//     isVerificationName) and whose result decides a branch or is returned.
//
// A static call that is not a name-based check but passes checks (see
// passesChecks) to a function of the same package, processFlight say, puts
// the name-based checks processFlight makes, and those of the functions it
// calls as a name-based check or in a way that passes checks, up to
// maxCheckHelperDepth deep, in t.HelperMovedChecks, not Checks: they
// explain a check that left this function for processFlight, without
// making every caller of processFlight lose it when processFlight changes.
//
// A check whose result nothing decides on has no effect, and is not one.
// Static calls are keyed like CallTargets; interface calls are keyed by the
// interface type and method, "(example.com/p.Verifier).Verify".
func collectCheckHelpers(fn *ssa.Function, t *FunctionTopology) {
	memo := newReachMemo()
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			if call.Call.IsInvoke() {
				if k, ok := decidedNameCheck(call); ok {
					t.Checks[k] = true
				}
			}
			// An interface call has no static callee.
			callee := call.Call.StaticCallee()
			if callee == nil || callee.Parent() != nil {
				continue
			}
			pkgPath, recv, name, _ := calleeIdentity(callee)
			key := callTargetKey(pkgPath, recv, name)
			if IsVerificationCall(pkgPath, recv, name) {
				if resultDecides(call, true) {
					t.Checks[key] = true
				}
				continue
			}
			if k, ok := decidedNameCheck(call); ok {
				t.Checks[k] = true
				// The checks a check helper of this package makes are the
				// caller's too: moving them into validateHeaders removes none.
				for _, c := range checksReached(callee, pkgOf(fn), maxCheckHelperDepth, true, memo) {
					t.Checks[c] = true
				}
			} else if passesChecks(call) {
				for _, c := range memo.helperChecks(callee, pkgOf(fn)) {
					addHelperMovedCheck(t, c, key)
				}
			}
			if call.Call.Signature().Results().Len() == 0 || resultDecides(call, true) {
				if reached := checksReached(callee, pkgOf(fn), maxCheckHelperDepth, false, memo); len(reached) > 0 {
					t.Checks[key] = true
					for _, k := range reached {
						t.Checks[k] = true
					}
				}
			}
		}
	}
	for _, lit := range fn.AnonFuncs {
		collectLiteralChecks(lit, t)
	}
}

// collectLiteralChecks records the checks of the function literal lit in
// t, the topology of its parent, when the parent's one use of it is a call.
// Invoked on the spot, lit runs there: its checks are the parent's when it
// has no result or its result decides, as for a helper. Passed to a call,
// it runs when the callee chooses, which a cache may skip: its checks go to
// MovedChecks, when the call's error result decides. A literal stored or
// converted to an interface can run from anywhere and counts for nothing.
func collectLiteralChecks(lit *ssa.Function, t *FunctionTopology) {
	var v ssa.Value = lit
	use := soleReferrer(v)
	if mc, ok := use.(*ssa.MakeClosure); ok {
		v, use = mc, soleReferrer(mc)
	}
	// A literal passed as a named func type is converted first.
	for {
		ct, ok := use.(*ssa.ChangeType)
		if !ok {
			break
		}
		v, use = ct, soleReferrer(ct)
	}
	call, ok := use.(*ssa.Call)
	if !ok {
		return
	}
	inner := &FunctionTopology{Checks: make(map[string]bool)}
	collectCheckHelpers(lit, inner)
	if call.Call.Value == v {
		if call.Call.Signature().Results().Len() > 0 && !resultDecides(call, true) {
			return
		}
		maps.Copy(t.Checks, inner.Checks)
	} else {
		if !typedResultDecides(call, func(_ int, t types.Type) bool { return isErrorType(t) }) {
			return
		}
		via := calleeKey(&call.Call)
		for k := range inner.Checks {
			addMovedCheck(t, k, via)
		}
	}
	for k, innerVia := range inner.MovedChecks {
		addMovedCheck(t, k, innerVia)
	}
	for k, vias := range inner.HelperMovedChecks {
		for _, via := range vias {
			addHelperMovedCheck(t, k, via)
		}
	}
}

func addHelperMovedCheck(t *FunctionTopology, k, via string) {
	if t.HelperMovedChecks == nil {
		t.HelperMovedChecks = make(map[string][]string)
	}
	vias := t.HelperMovedChecks[k]
	if i, found := slices.BinarySearch(vias, via); !found {
		t.HelperMovedChecks[k] = slices.Insert(vias, i, via)
	}
}

func addMovedCheck(t *FunctionTopology, k, via string) {
	if t.MovedChecks == nil {
		t.MovedChecks = make(map[string]string)
	}
	t.MovedChecks[k] = via
}

func soleReferrer(v ssa.Value) ssa.Instruction {
	if refs := v.Referrers(); len(*refs) == 1 {
		return (*refs)[0]
	}
	return nil
}

// typedResultDecides reports whether a result of call decides (see
// resultDecides), directly or once boxed in an interface (var err error =
// validate()), counting only the results it accepts by index and type. A
// branch on another, singleflight's shared flag or a returned *Alert,
// says nothing about whether a check passed.
func typedResultDecides(call *ssa.Call, is func(i int, t types.Type) bool) bool {
	decides := func(v ssa.Value) bool {
		if resultDecides(v, true) {
			return true
		}
		for _, ref := range *v.Referrers() {
			if mi, ok := ref.(*ssa.MakeInterface); ok && resultDecides(mi, false) {
				return true
			}
		}
		return false
	}
	if call.Call.Signature().Results().Len() == 1 {
		return is(0, call.Type()) && decides(call)
	}
	for _, ref := range *call.Referrers() {
		if ex, ok := ref.(*ssa.Extract); ok && is(ex.Index, ex.Type()) && decides(ex) {
			return true
		}
	}
	return false
}

// passesChecks reports whether the name-based checks the static callee of
// call makes count for the caller, when call is not a name-based check
// itself: a bool or error result of it decides, or its last result, of a
// type that implements error (*ValidationError), does, or it has no result
// and the callee's name says it checks (mustVerify panics or exits on
// failure). A generic helper with no result, a logger say, can branch on a
// check without enforcing it.
func passesChecks(call *ssa.Call) bool {
	if n := call.Call.Signature().Results().Len(); n > 0 {
		return typedResultDecides(call, func(i int, t types.Type) bool {
			return isBoolOrError(t) || i == n-1 && types.Implements(t, errorInterface)
		})
	}
	_, _, name, _ := calleeIdentity(call.Call.StaticCallee())
	return isVerificationName(name)
}

var errorInterface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

// calleeKey returns the key of the function c calls, like CallTargets, or
// "(iface).Method" for an interface call, or "func value".
func calleeKey(c *ssa.CallCommon) string {
	if c.IsInvoke() {
		return "(" + types.TypeString(c.Value.Type(), nil) + ")." + c.Method.Name()
	}
	if f := c.StaticCallee(); f != nil {
		pkgPath, recv, name, _ := calleeIdentity(f)
		return callTargetKey(pkgPath, recv, name)
	}
	return "func value"
}

// notChecks are callees whose names contain a verification word but which
// classify or inspect a value rather than check a permission:
// os.IsPermission reads an error, and its documented replacement,
// errors.Is(err, fs.ErrPermission), contains no such word.
var notChecks = map[string]bool{
	"os.IsPermission":         true,
	"(reflect.Value).IsValid": true,
}

// pkgOf returns the package of fn, or of the generic function fn
// instantiates.
func pkgOf(fn *ssa.Function) *ssa.Package {
	if fn.Pkg == nil && fn.Origin() != nil {
		return fn.Origin().Pkg
	}
	return fn.Pkg
}

// reachKey memoizes checksReached: the answer depends on the depth left,
// as a helper reached at the end of a long chain may be within reach when
// called directly, and on whether name-based checks count.
type reachKey struct {
	fn    *ssa.Function
	depth int
	named bool
}

// reachMemo holds what one function's search has learned: the answers
// checksReached gave, and what each body it read references.
type reachMemo struct {
	reached map[reachKey][]string
	bodies  map[*ssa.Function]*bodyRefs
	helpers map[*ssa.Function][]string
}

func newReachMemo() *reachMemo {
	return &reachMemo{
		reached: make(map[reachKey][]string),
		bodies:  make(map[*ssa.Function]*bodyRefs),
		helpers: make(map[*ssa.Function][]string),
	}
}

// helperChecks returns the name-based checks fn, a function of package
// pkg, makes and decides on, directly or through name-based checks and
// calls that pass checks (see passesChecks) to other functions of pkg, at
// most maxCheckHelperDepth functions deep counting fn. Each function is
// read once, at the shallowest depth it is reached.
func (m *reachMemo) helperChecks(fn *ssa.Function, pkg *ssa.Package) []string {
	if found, ok := m.helpers[fn]; ok {
		return found
	}
	var found []string
	seen := make(map[*ssa.Function]bool)
	level := []*ssa.Function{fn}
	for depth := 0; depth < maxCheckHelperDepth && len(level) > 0; depth++ {
		var next []*ssa.Function
		for _, f := range level {
			if seen[f] || pkg == nil || pkgOf(f) != pkg || len(f.Blocks) == 0 {
				continue
			}
			seen[f] = true
			r := m.refs(f)
			for _, k := range r.named {
				if !slices.Contains(found, k) {
					found = append(found, k)
				}
			}
			next = append(next, r.passing...)
		}
		level = next
	}
	m.helpers[fn] = found
	return found
}

// bodyRefs is what a function body references, once each: the
// verification primitives and the name-based checks it calls and decides
// on, the other functions, and those of them it calls as a name-based
// check or in a way that passes checks (see passesChecks).
type bodyRefs struct {
	primitives []string
	named      []string
	callees    []*ssa.Function
	passing    []*ssa.Function
}

func (m *reachMemo) refs(fn *ssa.Function) *bodyRefs {
	if r, ok := m.bodies[fn]; ok {
		return r
	}
	r := &bodyRefs{}
	var ops []*ssa.Value
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			ops = instr.Operands(ops[:0])
			for _, op := range ops {
				callee, ok := (*op).(*ssa.Function)
				if !ok {
					continue
				}
				pkgPath, recv, name, _ := calleeIdentity(callee)
				if !IsVerificationCall(pkgPath, recv, name) && !slices.Contains(r.callees, callee) {
					r.callees = append(r.callees, callee)
				}
			}
			if k, ok := decidedPrimitive(instr); ok && !slices.Contains(r.primitives, k) {
				r.primitives = append(r.primitives, k)
			}
			if call, ok := instr.(*ssa.Call); ok {
				k, named := decidedNameCheck(call)
				if named && !slices.Contains(r.named, k) {
					r.named = append(r.named, k)
				}
				if callee := call.Call.StaticCallee(); callee != nil && slices.Contains(r.callees, callee) &&
					!slices.Contains(r.passing, callee) && (named || passesChecks(call)) {
					r.passing = append(r.passing, callee)
				}
			}
		}
	}
	m.bodies[fn] = r
	return r
}

// checksReached returns the keys of the verification primitives fn, a
// function of package pkg, calls and decides on, and with named the keys
// of its name-based checks too, directly or through static calls to other
// functions of pkg, at most depth calls deep. The search never leaves pkg:
// whether another package's functions have SSA bodies depends on which
// packages happened to be built, and the result must not. Every recursive
// call has less depth, so recursion in the code ends the search.
func checksReached(fn *ssa.Function, pkg *ssa.Package, depth int, named bool, m *reachMemo) []string {
	if depth <= 0 || pkg == nil || pkgOf(fn) != pkg || len(fn.Blocks) == 0 {
		return nil
	}
	key := reachKey{fn, depth, named}
	if reached, ok := m.reached[key]; ok {
		return reached
	}
	r := m.refs(fn)
	reached := slices.Clone(r.primitives)
	if named {
		reached = append(reached, r.named...)
	}
	for _, callee := range r.callees {
		for _, k := range checksReached(callee, pkg, depth-1, named, m) {
			if !slices.Contains(reached, k) {
				reached = append(reached, k)
			}
		}
	}
	m.reached[key] = reached
	return reached
}

// decidedNameCheck returns the key of the name-based check call makes: a
// call, static or through an interface, whose name contains a verification
// word (see isVerificationName) and whose result decides (see
// resultDecides). A primitive is not one: decidedPrimitive covers it.
func decidedNameCheck(call *ssa.Call) (string, bool) {
	var key, name string
	if call.Call.IsInvoke() {
		name = call.Call.Method.Name()
		key = "(" + types.TypeString(call.Call.Value.Type(), nil) + ")." + name
	} else {
		callee := call.Call.StaticCallee()
		if callee == nil || callee.Parent() != nil {
			return "", false
		}
		var pkgPath, recv string
		pkgPath, recv, name, _ = calleeIdentity(callee)
		if IsVerificationCall(pkgPath, recv, name) {
			return "", false
		}
		key = callTargetKey(pkgPath, recv, name)
	}
	if notChecks[key] || !isVerificationName(name) || !resultDecides(call, false) {
		return "", false
	}
	return key, true
}

// decidedPrimitive returns the key of the verification primitive instr
// calls, when the call's result decides (see resultDecides).
func decidedPrimitive(instr ssa.Instruction) (string, bool) {
	call, ok := instr.(*ssa.Call)
	if !ok {
		return "", false
	}
	callee := call.Call.StaticCallee()
	if callee == nil {
		return "", false
	}
	pkgPath, recv, name, _ := calleeIdentity(callee)
	if !IsVerificationCall(pkgPath, recv, name) || !resultDecides(call, true) {
		return "", false
	}
	return callTargetKey(pkgPath, recv, name), true
}

// resultDecides reports whether v, a call's result, possibly through up to
// four unary or binary operations, conversions, tuple extracts, phis,
// locals and errors.Is or errors.As calls testing it, is the condition of
// a branch or is returned (its caller then decides on it). Unless
// anyReturn is set, only a returned boolean or error counts: a getter
// returning another value decides nothing.
func resultDecides(v ssa.Value, anyReturn bool) bool {
	// The phis of a large switch reach one another many times over. A value
	// already walked with as much depth left found nothing then either.
	walked := make(map[ssa.Value]int)
	var decides func(v ssa.Value, depth int) bool
	decides = func(v ssa.Value, depth int) bool {
		if d, ok := walked[v]; depth > 4 || ok && d <= depth {
			return false
		}
		walked[v] = depth
		for _, ref := range *v.Referrers() {
			switch r := ref.(type) {
			case *ssa.If:
				return true
			case *ssa.Return:
				if anyReturn || isBoolOrError(v.Type()) {
					return true
				}
			case *ssa.UnOp, *ssa.BinOp, *ssa.ChangeType, *ssa.Convert, *ssa.Extract, *ssa.Phi:
				if decides(r.(ssa.Value), depth+1) {
					return true
				}
			case *ssa.Call:
				if f := r.Call.StaticCallee(); f != nil && r.Call.Args[0] == v {
					if p, _, name, _ := calleeIdentity(f); p == "errors" && (name == "Is" || name == "As") && decides(r, depth+1) {
						return true
					}
				}
			case *ssa.Store:
				// A local the value is stored in, such as the result a
				// function with a defer returns: follow its loads.
				if local, ok := r.Addr.(*ssa.Alloc); ok {
					for _, use := range *local.Referrers() {
						if load, ok := use.(*ssa.UnOp); ok && load.Op == token.MUL && decides(load, depth+1) {
							return true
						}
					}
				}
			}
		}
		return false
	}
	return decides(v, 0)
}

func isBoolOrError(t types.Type) bool {
	if basic, ok := t.Underlying().(*types.Basic); ok {
		return basic.Info()&types.IsBoolean != 0
	}
	return isErrorType(t)
}

// verificationWords are word prefixes that mark a function name as a
// verification: authorize, authenticate, verify, validate, permission,
// allowed, isAdmin, hasRole, csrf ...
var verificationWords = []string{
	"auth", "verif", "valid", "permi", "allow", "admin", "acl", "csrf", "xsrf",
	"signature", "privilege", "owner", "role", "access",
}

// isVerificationName reports whether a camelCase or snake_case function
// name contains a word starting with one of verificationWords, and none of
// actionWords: GetRoles, BuildRoleLinks and DeleteExternalAuths fetch,
// build or change something about roles or auth; they check nothing.
func isVerificationName(name string) bool {
	verification := false
	for _, w := range splitWords(name) {
		if actionWords[w] {
			return false
		}
		for _, p := range verificationWords {
			verification = verification || strings.HasPrefix(w, p)
		}
	}
	return verification
}

// actionWords are verbs of names that fetch, build or change state.
var actionWords = map[string]bool{
	"get": true, "set": true, "unset": true, "build": true, "rebuild": true, "load": true, "reload": true,
	"list": true, "find": true, "new": true, "create": true, "make": true, "add": true, "append": true,
	"insert": true, "put": true, "delete": true, "remove": true, "update": true, "save": true,
	"store": true, "fetch": true, "read": true, "write": true, "init": true, "register": true,
	"clear": true, "reset": true, "sync": true, "copy": true, "clone": true,
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
