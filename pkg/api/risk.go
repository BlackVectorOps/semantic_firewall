package api

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
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

// CalculateTopologyDelta diffs two function topologies and returns a short
// human label plus a heuristic risk score. A nil oldT means the function is
// new. Newly reached capabilities (process execution, raw syscalls, plugins,
// network, reflective invocation, filesystem mutation), new goroutines and
// obfuscation each reach models.RiskScoreHigh on their own; ordinary call,
// loop and branch churn is capped below it. Removing structure is neutral.
func CalculateTopologyDelta(oldT, newT *topology.FunctionTopology) (string, int) {
	if newT == nil {
		return models.TopoDeltaUnknown, 0
	}
	r := assessTopologyDelta(oldT, newT)
	return r.delta(), r.score(0)
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

func assessTopologyDelta(oldT, newT *topology.FunctionTopology) riskAssessment {
	return assessTopologyDeltaFor(oldT, newT, riskProfile{})
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
	// the call was moved out of it.
	var unguarded []string
	for target, newGuards := range newT.CapabilityGuards {
		if oldGuards, ok := oldT.CapabilityGuards[target]; ok && oldGuards > 0 && newGuards == 0 {
			unguarded = append(unguarded, target)
		}
	}
	if len(unguarded) > 0 {
		sort.Strings(unguarded)
		r.labels = append(r.labels, fmt.Sprintf("Unguarded(%s)", strings.Join(unguarded, ",")))
		r.escalation += models.RiskScoreHigh
	}

	// A security setting that weakens on its own appears, or one whose
	// removal weakens disappears ("-" prefix).
	var weakened []string
	for s := range newT.WeakSettings {
		if !oldT.WeakSettings[s] && !raisesTLSVersion(s, oldT.WeakSettings) {
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
	// letter's case changed (an exported rename) is the same check. One
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
		switch match, samePackage := matchingCheck(target, addedChecks); {
		case match == "":
			removedChecks = append(removedChecks, target)
		case !samePackage:
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

// callTargetsOf prefers the import-path-qualified targets and falls back to
// the package-name call profile for topologies built without them.
// raisesTLSVersion reports whether s, a weak TLS version bound
// ("crypto/tls.Config.MinVersion=TLS1.1"), replaces an old weak bound on
// the same field that was no higher: raising a legacy minimum from TLS 1.0
// to 1.1 leaves it weak, but weakens nothing.
func raisesTLSVersion(s string, old map[string]bool) bool {
	field, version, ok := strings.Cut(s, "=")
	if !ok || (field != "crypto/tls.Config.MinVersion" && field != "crypto/tls.Config.MaxVersion") {
		return false
	}
	v, ok := tlsVersionNumber(version)
	if !ok {
		return false
	}
	for o := range old {
		if oField, oVersion, _ := strings.Cut(o, "="); oField == field {
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
// under another spelling, and whether it is in the same package: the same
// receiver and name but for the case of their first letters, in the same
// package or in a package whose path ends in the same name, ignoring major
// version suffixes ("/v3", ".v2"). A verification primitive matches only
// itself: a function of another package named Equal is no hmac.Equal.
func matchingCheck(old string, candidates []string) (match string, samePackage bool) {
	pkg, recv, name := splitCheckKey(old)
	if topology.IsVerificationCall(pkg, recv, name) {
		return "", false
	}
	for _, c := range candidates {
		cPkg, cRecv, cName := splitCheckKey(c)
		if topology.IsVerificationCall(cPkg, cRecv, cName) || lowerFirst(cRecv) != lowerFirst(recv) || lowerFirst(cName) != lowerFirst(name) {
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

// splitCheckKey splits a Checks key, "pkg.Name" or "(pkg.Recv).Name".
func splitCheckKey(key string) (pkg, recv, name string) {
	if rest, ok := strings.CutPrefix(key, "("); ok {
		if typ, method, found := strings.Cut(rest, ")."); found {
			i := strings.LastIndexByte(typ, '.')
			return typ[:max(i, 0)], typ[i+1:], method
		}
	}
	i := strings.LastIndexByte(key, '.')
	return key[:max(i, 0)], "", key[i+1:]
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

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func callTargetsOf(t *topology.FunctionTopology) map[string]int {
	if t.CallTargets != nil {
		return t.CallTargets
	}
	return t.CallSignatures
}

// withoutModuleTargets returns t with the capability targets declared in
// module mod removed from Capabilities and CapabilityGuards.
func withoutModuleTargets(t *topology.FunctionTopology, mod string) *topology.FunctionTopology {
	c := *t
	c.Capabilities = make(map[string]string, len(t.Capabilities))
	for k, v := range t.Capabilities {
		if !inModule(targetPackage(k), mod) {
			c.Capabilities[k] = v
		}
	}
	if t.CapabilityGuards != nil {
		c.CapabilityGuards = make(map[string]int, len(t.CapabilityGuards))
		for k, v := range t.CapabilityGuards {
			if _, kept := c.Capabilities[k]; kept {
				c.CapabilityGuards[k] = v
			}
		}
	}
	return &c
}

// targetPackage returns the import path of a CallTargets key:
// "golang.org/x/sys/unix" for "golang.org/x/sys/unix.Syscall6" and for
// "(golang.org/x/sys/unix.Timespec).Unix".
func targetPackage(key string) string {
	if rest, ok := strings.CutPrefix(key, "("); ok {
		if recv, _, found := strings.Cut(rest, ")."); found {
			key = recv
		}
	}
	if i := strings.LastIndexByte(key, '.'); i > 0 {
		return key[:i]
	}
	return key
}

func inModule(pkgPath, mod string) bool {
	return pkgPath == mod || strings.HasPrefix(pkgPath, mod+"/")
}
