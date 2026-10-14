package models

// DepsDiffOutput is the result of `sfw deps diff`: how the third-party code
// compiled into a module changed between two trees of it.
type DepsDiffOutput struct {
	OldDir  string          `json:"old_dir"`
	NewDir  string          `json:"new_dir"`
	Summary DepsDiffSummary `json:"summary"`
	Modules []ModuleDiff    `json:"modules"`
}

type DepsDiffSummary struct {
	ModulesUpdated   int `json:"modules_updated"`
	ModulesAdded     int `json:"modules_added"`
	ModulesRemoved   int `json:"modules_removed"`
	FunctionsChanged int `json:"functions_changed"`
	HighRiskChanges  int `json:"high_risk_changes"`
}

// Module statuses in a deps diff.
const (
	ModuleUpdated = "updated"
	ModuleAdded   = "added"
	ModuleRemoved = "removed"
)

// ModuleDiff is one third-party module whose compiled code differs between
// the two trees.
type ModuleDiff struct {
	Path       string `json:"path"`
	Status     string `json:"status"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`

	// Packages holds the changed functions of each of the module's packages
	// in the build (updated modules only).
	Packages []PackageDiff `json:"packages,omitempty"`

	// Reach lists exported functions and package initializers that can
	// newly reach a capability class.
	Reach []ReachChange `json:"reach,omitempty"`

	// Unanalyzed lists added, modified and removed files the SSA analysis
	// cannot see: assembly, C and other non-Go sources, .syso objects, cgo
	// and build-constraint-excluded Go files, embedded files, and
	// //go:linkname directives.
	Unanalyzed []FileChange `json:"unanalyzed,omitempty"`

	// Capabilities, for an added module, lists the capability classes its
	// exported functions and package initializers can reach.
	Capabilities []string `json:"capabilities,omitempty"`

	RiskScore       int `json:"risk_score"`
	HighRiskChanges int `json:"high_risk_changes,omitempty"`
}

// PackageDiff is the function-level diff of one package of a module.
type PackageDiff struct {
	Path      string         `json:"path"`
	Summary   DiffSummary    `json:"summary"`
	Functions []FunctionDiff `json:"functions"`
}

// ReachChange is an entry point that can reach capability classes it could
// not reach before, through static calls and function values.
type ReachChange struct {
	Function  string   `json:"function"`
	Added     []string `json:"added"`
	Targets   []string `json:"targets"`
	RiskScore int      `json:"risk_score"`
}

// FileChange is a change to a file the SSA analysis does not cover.
type FileChange struct {
	File      string `json:"file"`
	Kind      string `json:"kind"`
	Change    string `json:"change"`
	RiskScore int    `json:"risk_score,omitempty"`
}
