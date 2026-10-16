package api

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// capabilityRisk is the escalation charged the first time a function reaches
// a capability class. Every weight is at least models.RiskScoreHigh, so a
// single newly reached capability flags the change on its own -- regardless of
// how many calls were added or removed alongside it.
var capabilityRisk = map[string]int{
	topology.CapExec:       30,
	topology.CapSyscall:    25,
	topology.CapPlugin:     25,
	topology.CapNetwork:    20,
	topology.CapReflection: 15,
	topology.CapFilesystem: 10,
}

const (
	// riskAdditionalCapability is charged for each new sensitive target in a
	// class the function already reached (e.g. net.Listen next to net.Dial).
	riskAdditionalCapability = 5

	// Structural churn weights. Their sum (plus BaseRiskAddedFunc) is capped
	// at maxStructuralRisk, so churn alone never reaches RiskScoreHigh.
	riskPerNewCallTarget = 2
	riskPerNewLoop       = 5
	riskPerNewBranch     = 1
	riskNewDefer         = 2
	riskNewPanic         = 3

	maxStructuralRisk = models.RiskScoreHigh - 1
)

// riskAssessment itemizes how a function's topology changed between versions.
// Structural churn is reported but capped below the high-risk threshold;
// escalations (newly reached capabilities, new concurrency, obfuscation) are
// uncapped and each can reach the threshold on its own.
type riskAssessment struct {
	labels          []string
	structural      int
	escalation      int
	newCapabilities []string
}

func (r riskAssessment) score(base int) int {
	s := base + r.structural
	if s > maxStructuralRisk {
		s = maxStructuralRisk
	}
	return s + r.escalation
}

func (r riskAssessment) delta() string {
	if len(r.labels) == 0 {
		return models.TopoDeltaNone
	}
	return strings.Join(r.labels, ", ")
}

// CalculateTopologyDelta diffs two function topologies and returns the
// topology_delta and risk_score Diff reports for the change. A nil oldT
// means the function was added, a nil newT that it was removed. Newly
// reached capabilities (process execution, raw syscalls, plugins, network,
// reflective invocation, filesystem mutation), new goroutines, obfuscation
// and the deletion signals each reach models.RiskScoreHigh on their own;
// ordinary call, loop and branch churn is capped below it. Removing
// structure is neutral, except a check.
func CalculateTopologyDelta(oldT, newT *topology.FunctionTopology) (string, int) {
	switch {
	case newT == nil && oldT == nil:
		return models.TopoDeltaUnknown, 0
	case newT == nil:
		return removedDelta(oldT)
	case oldT == nil:
		return addedDelta(newT, riskProfile{})
	}
	r := assessTopologyDeltaFor(oldT, newT, riskProfile{})
	return r.delta(), r.score(0)
}

// addedDelta scores an added function with topology t.
func addedDelta(t *topology.FunctionTopology, profile riskProfile) (string, int) {
	r := assessTopologyDeltaFor(nil, t, profile)
	if len(r.labels) == 0 {
		return models.TopoDeltaNew, r.score(models.BaseRiskAddedFunc)
	}
	return r.delta(), r.score(models.BaseRiskAddedFunc)
}

// removedDelta scores a removed function with topology t. Deleting a
// function is usually neutral, but deleting one that performed a
// verification (a validator, a signature check) removes that check from
// every caller.
func removedDelta(t *topology.FunctionTopology) (string, int) {
	if len(t.Checks) == 0 {
		return "", 0
	}
	checks := slices.Sorted(maps.Keys(t.Checks))
	return fmt.Sprintf("RemovedCheck(%s)", strings.Join(checks, ",")), models.RiskScoreHigh
}

// riskProfile adjusts scoring to where the diffed code comes from. The zero
// value scores a project's own code.
type riskProfile struct {
	// ownModule, when set, is the module the diffed functions belong to. Its
	// own call targets are not capabilities of its functions: a syscall
	// wrapper module calling its own Syscall6 is doing its job, not
	// escalating.
	ownModule string
	// labelGoroutines reports a new goroutine without charging for it. In a
	// dependency, what a goroutine can reach is scored by the reach analysis.
	labelGoroutines bool
}

func assessTopologyDeltaFor(oldT, newT *topology.FunctionTopology, profile riskProfile) riskAssessment {
	var r riskAssessment
	if oldT == nil {
		oldT = &topology.FunctionTopology{}
	}
	if profile.ownModule != "" {
		oldT, newT = withoutModuleTargets(oldT, profile.ownModule), withoutModuleTargets(newT, profile.ownModule)
	}

	oldTargets, newTargets := callTargetsOf(oldT), callTargetsOf(newT)

	oldClasses := make(map[string]bool)
	for _, class := range oldT.Capabilities {
		oldClasses[class] = true
	}

	// Group newly reached sensitive targets by class.
	newByClass := make(map[string][]string)
	newPlain := 0
	for target := range newTargets {
		if _, seen := oldTargets[target]; seen {
			continue
		}
		if class := newT.Capabilities[target]; class != "" {
			newByClass[class] = append(newByClass[class], target)
		} else {
			newPlain++
		}
	}
	removed := 0
	for target := range oldTargets {
		if _, kept := newTargets[target]; !kept {
			removed++
		}
	}

	classes := make([]string, 0, len(newByClass))
	for class := range newByClass {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	for _, class := range classes {
		targets := newByClass[class]
		sort.Strings(targets)
		r.labels = append(r.labels, fmt.Sprintf("Capability+%s(%s)", class, strings.Join(targets, ",")))
		r.newCapabilities = append(r.newCapabilities, targets...)
		extra := len(targets)
		if !oldClasses[class] {
			r.escalation += capabilityRisk[class]
			extra--
		}
		r.escalation += extra * riskAdditionalCapability
	}

	// A capability call that every old reference made under a condition now
	// has a reference that runs unconditionally: its guard was deleted, or
	// the call was moved out of it. A target the old version did not call
	// counts when every old call of its class was guarded: swapping a
	// guarded exec.Command for an unguarded os.StartProcess deletes the same
	// guard. A new version too large for the guard analysis records no
	// guards; growing a function must not hide a deleted guard, so a call
	// the old version guarded is then GuardsUnknown, charged the same.
	guardedClass := guardedClasses(oldT)
	var unguarded []string
	for target, class := range newT.Capabilities {
		wasGuarded := guardedClass[class]
		if g, ok := oldT.CapabilityGuards[target]; ok {
			wasGuarded = g > 0
		}
		if g, ok := newT.CapabilityGuards[target]; wasGuarded && (newT.CapabilityGuards == nil || ok && g == 0) {
			unguarded = append(unguarded, target)
		}
	}
	if len(unguarded) > 0 {
		label := "Unguarded"
		if newT.CapabilityGuards == nil {
			label = "GuardsUnknown"
		}
		sort.Strings(unguarded)
		r.labels = append(r.labels, fmt.Sprintf("%s(%s)", label, strings.Join(unguarded, ",")))
		r.escalation += models.RiskScoreHigh
	}

	// A security setting that weakens on its own appears, or one whose
	// removal weakens disappears ("-" prefix).
	var weakened []string
	for s := range newT.WeakSettings {
		if !oldT.WeakSettings[s] && !raisesTLSVersion(s, oldT.WeakSettings, newT.WeakSettings) {
			weakened = append(weakened, s)
		}
	}
	for s := range oldT.SecureSettings {
		if !newT.SecureSettings[s] {
			weakened = append(weakened, "-"+s)
		}
	}
	if len(weakened) > 0 {
		sort.Strings(weakened)
		r.labels = append(r.labels, fmt.Sprintf("WeakenedSecurity(%s)", strings.Join(weakened, ",")))
		r.escalation += models.RiskScoreHigh
	}

	// A removed verification call is how a guard gets deleted: a MAC or
	// signature check, certificate verification, a password comparison.
	// A check that reappears under the same name with only its first
	// letter's case changed (an exported rename) is the same check, and so
	// is subtle.ConstantTimeCompare in place of hmac.Equal or back. One
	// that reappears under the same name in a package of the same name at
	// another path (a module's new major version, a fork, a library that
	// moved) is labelled ReplacedCheck without points: the code still
	// checks, through an implementation a reviewer should see.
	var addedChecks []string
	for target := range newT.Checks {
		if !oldT.Checks[target] {
			addedChecks = append(addedChecks, target)
		}
	}
	sort.Strings(addedChecks)
	var removedChecks, replacedChecks []string
	for target := range oldT.Checks {
		if newT.Checks[target] {
			continue
		}
		switch match, same := matchingCheck(target, addedChecks); {
		case match == "":
			removedChecks = append(removedChecks, target)
		case !same:
			replacedChecks = append(replacedChecks, target+"->"+match)
		}
	}
	if len(removedChecks) > 0 {
		sort.Strings(removedChecks)
		r.labels = append(r.labels, fmt.Sprintf("RemovedCheck(%s)", strings.Join(removedChecks, ",")))
		r.escalation += models.RiskScoreHigh
	}
	if len(replacedChecks) > 0 {
		sort.Strings(replacedChecks)
		r.labels = append(r.labels, fmt.Sprintf("ReplacedCheck(%s)", strings.Join(replacedChecks, ",")))
	}

	if newPlain > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Calls+%d", newPlain))
		r.structural += newPlain * riskPerNewCallTarget
	}
	if removed > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Calls-%d", removed))
	}

	// Fewer branches that stop the function on a failed condition: an
	// error check, an authorization test, a validation. Labelled only.
	if d := newT.ErrorExits - oldT.ErrorExits; d < 0 {
		r.labels = append(r.labels, fmt.Sprintf("ErrorExits%d", d))
	}

	if d := newT.LoopCount - oldT.LoopCount; d > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Loops+%d", d))
		r.structural += d * riskPerNewLoop
	} else if d < 0 {
		r.labels = append(r.labels, fmt.Sprintf("Loops%d", d))
	}

	if d := newT.BranchCount - oldT.BranchCount; d > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Branches+%d", d))
		r.structural += d * riskPerNewBranch
	} else if d < 0 {
		r.labels = append(r.labels, fmt.Sprintf("Branches%d", d))
	}

	if newT.HasGo && !oldT.HasGo {
		r.labels = append(r.labels, models.TopoDeltaGoroutine)
		if !profile.labelGoroutines {
			r.escalation += models.RiskScoreHigh
		}
	}
	if newT.HasDefer && !oldT.HasDefer {
		r.labels = append(r.labels, models.TopoDeltaDefer)
		r.structural += riskNewDefer
	}
	if newT.HasPanic && !oldT.HasPanic {
		r.labels = append(r.labels, models.TopoDeltaPanic)
		r.structural += riskNewPanic
	}

	if !slices.Equal(oldT.StringLiterals, newT.StringLiterals) {
		r.labels = append(r.labels, "StringLiterals~")
	}

	// Entropy drift from ordinary string literals (log and error messages) is
	// reported but not scored; only crossing into the HIGH/PACKED bands is an
	// escalation.
	if d := newT.EntropyScore - oldT.EntropyScore; d > 1.0 {
		r.labels = append(r.labels, fmt.Sprintf("Entropy+%.1f", d))
	}
	newClass := topology.ClassifyEntropy(newT.EntropyScore)
	if newClass >= topology.EntropyHigh && newClass > topology.ClassifyEntropy(oldT.EntropyScore) {
		r.labels = append(r.labels, "EntropyClass:"+newClass.String())
		r.escalation += models.RiskScoreHigh
	}

	if newT.Obfuscation.Class >= topology.ObfuscationModerate && newT.Obfuscation.Class > oldT.Obfuscation.Class {
		r.labels = append(r.labels, "Obfuscation:"+newT.Obfuscation.Class.String())
		r.escalation += models.RiskScoreHigh
	}

	return r
}

// raisesTLSVersion reports whether s, a weak TLS version bound
// ("crypto/tls.Config.MinVersion=TLS1.1"), replaces an old weak bound on
// the same field that was no higher: raising a legacy minimum from TLS 1.0
// to 1.1 leaves it weak, but weakens nothing. An old bound the new version
// still sets was not replaced: s is then another config's bound, lowered
// from a secure version.
func raisesTLSVersion(s string, old, current map[string]bool) bool {
	field, version, ok := strings.Cut(s, "=")
	if !ok || (field != "crypto/tls.Config.MinVersion" && field != "crypto/tls.Config.MaxVersion") {
		return false
	}
	v, ok := tlsVersionNumber(version)
	if !ok {
		return false
	}
	for o := range old {
		if oField, oVersion, _ := strings.Cut(o, "="); oField == field && !current[o] {
			if ov, ok := tlsVersionNumber(oVersion); ok && ov <= v {
				return true
			}
		}
	}
	return false
}

// tlsVersionNumber reads a version as collectSecuritySettings writes it:
// a name ("TLS1.0") or the constant's value.
func tlsVersionNumber(s string) (int64, bool) {
	switch s {
	case "SSL3.0":
		return 0x0300, true
	case "TLS1.0":
		return 0x0301, true
	case "TLS1.1":
		return 0x0302, true
	}
	v, err := strconv.ParseInt(s, 0, 64)
	return v, err == nil
}

// matchingCheck returns the first of candidates that is check key old
// under another spelling, and whether it is the same check rather than a
// replacement: the same receiver and name but for the case of their first
// letters, in the same package (the same check) or in a package whose path
// ends in the same name, ignoring major version suffixes ("/v3", ".v2"). A
// verification primitive matches only itself and its equivalent, the same
// check: a function of another package named Equal is no hmac.Equal, but
// subtle.ConstantTimeCompare is.
func matchingCheck(old string, candidates []string) (match string, same bool) {
	pkg, recv, name := splitCheckKey(old)
	if topology.IsVerificationCall(pkg, recv, name) {
		if eq := equivalentPrimitive[old]; slices.Contains(candidates, eq) {
			return eq, true
		}
		return "", false
	}
	for _, c := range candidates {
		cPkg, cRecv, cName := splitCheckKey(c)
		if topology.IsVerificationCall(cPkg, cRecv, cName) || !equalButFirstCase(cRecv, recv) || !equalButFirstCase(cName, name) {
			continue
		}
		if cPkg == pkg {
			return c, true
		}
		if packageBase(cPkg) == packageBase(pkg) {
			return c, false
		}
	}
	return "", false
}

// equivalentPrimitive pairs verification primitives that decide the same
// thing: hmac.Equal is subtle.ConstantTimeCompare's result on equal-length
// inputs, and ConstantTimeCompare returns 0 for unequal lengths.
var equivalentPrimitive = map[string]string{
	"crypto/hmac.Equal":                 "crypto/subtle.ConstantTimeCompare",
	"crypto/subtle.ConstantTimeCompare": "crypto/hmac.Equal",
}

// splitCheckKey splits a Checks key, "pkg.Name" or "(pkg.Recv).Name". An
// interface's type arguments stay with its name: "(pkg.Recv[other.T]).Name"
// has receiver "Recv[other.T]".
func splitCheckKey(key string) (pkg, recv, name string) {
	if rest, ok := strings.CutPrefix(key, "("); ok {
		if typ, method, found := strings.Cut(rest, ")."); found {
			pkg, recv := splitQualified(typ)
			return pkg, recv, method
		}
	}
	pkg, name = splitQualified(key)
	return pkg, "", name
}

// splitQualified splits "pkg.Name" at the last dot before any type
// arguments.
func splitQualified(s string) (pkg, name string) {
	head, _, _ := strings.Cut(s, "[")
	i := strings.LastIndexByte(head, '.')
	return s[:max(i, 0)], s[i+1:]
}

// packageBase is the last element of an import path without a major
// version: "casbin" for github.com/casbin/casbin/v2, "go-jose" for
// gopkg.in/square/go-jose.v2.
func packageBase(path string) string {
	elems := strings.Split(path, "/")
	last := elems[len(elems)-1]
	if len(elems) > 1 && majorVersion.MatchString(last) {
		last = elems[len(elems)-2]
	}
	if i := strings.LastIndex(last, ".v"); i > 0 && majorVersion.MatchString(last[i+1:]) {
		last = last[:i]
	}
	return last
}

var majorVersion = regexp.MustCompile(`^v[0-9]+$`)

// equalButFirstCase reports whether a and b are the same name but for the
// case of their first letters.
func equalButFirstCase(a, b string) bool {
	ra, na := utf8.DecodeRuneInString(a)
	rb, nb := utf8.DecodeRuneInString(b)
	return unicode.ToLower(ra) == unicode.ToLower(rb) && a[na:] == b[nb:]
}

// guardedClasses reports, for each capability class t reaches, whether all
// of its targets have a guard count of at least 1.
func guardedClasses(t *topology.FunctionTopology) map[string]bool {
	guarded := make(map[string]bool)
	for target, class := range t.Capabilities {
		g, ok := t.CapabilityGuards[target]
		all, seen := guarded[class]
		guarded[class] = (all || !seen) && ok && g > 0
	}
	return guarded
}

// callTargetsOf prefers the import-path-qualified targets and falls back to
// the package-name call profile for topologies built without them.
func callTargetsOf(t *topology.FunctionTopology) map[string]int {
	if t.CallTargets != nil {
		return t.CallTargets
	}
	return t.CallSignatures
}

// withoutModuleTargets returns t with the capability targets declared in
// module mod removed from Capabilities. Guards are looked up by the
// targets of Capabilities, so CapabilityGuards is kept as it is.
func withoutModuleTargets(t *topology.FunctionTopology, mod string) *topology.FunctionTopology {
	c := *t
	c.Capabilities = make(map[string]string, len(t.Capabilities))
	for k, v := range t.Capabilities {
		if pkg, _, _ := splitCheckKey(k); !inModule(pkg, mod) {
			c.Capabilities[k] = v
		}
	}
	return &c
}

func inModule(pkgPath, mod string) bool {
	return pkgPath == mod || strings.HasPrefix(pkgPath, mod+"/")
}
