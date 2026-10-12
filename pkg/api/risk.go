package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
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

func assessTopologyDelta(oldT, newT *topology.FunctionTopology) riskAssessment {
	var r riskAssessment
	if oldT == nil {
		oldT = &topology.FunctionTopology{}
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

	if newPlain > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Calls+%d", newPlain))
		r.structural += newPlain * riskPerNewCallTarget
	}
	if removed > 0 {
		r.labels = append(r.labels, fmt.Sprintf("Calls-%d", removed))
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
		r.escalation += models.RiskScoreHigh
	}
	if newT.HasDefer && !oldT.HasDefer {
		r.labels = append(r.labels, models.TopoDeltaDefer)
		r.structural += riskNewDefer
	}
	if newT.HasPanic && !oldT.HasPanic {
		r.labels = append(r.labels, models.TopoDeltaPanic)
		r.structural += riskNewPanic
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
func callTargetsOf(t *topology.FunctionTopology) map[string]int {
	if t.CallTargets != nil {
		return t.CallTargets
	}
	return t.CallSignatures
}
