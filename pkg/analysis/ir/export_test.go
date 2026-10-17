package ir

import (
	"golang.org/x/tools/go/ssa"
)

// ExportTest_RenamerFunc exposes the internal renamer closure for testing recursion safety.
func (c *Canonicalizer) ExportTest_RenamerFunc() func(ssa.Value) string {
	return c.renamerFunc()
}

// ExportTest_SetSubstitution allows injecting mock substitutions for cycle testing.
func (c *Canonicalizer) ExportTest_SetSubstitution(k ssa.Value, v ssa.Value) {
	c.virtualSubstitutions[k] = v
}
