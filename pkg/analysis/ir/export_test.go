package ir

import (
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/loop"
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

// ExportTest_MarkSunk forces an instruction to be treated as "sunk", moving it to the HEAD list.
func (c *Canonicalizer) ExportTest_MarkSunk(instr ssa.Instruction) {
	c.sunkInstrs[instr] = true
}

// ExportTest_MarkHoisted forces an instruction to be treated as "hoisted", moving it to the TAIL list.
func (c *Canonicalizer) ExportTest_MarkHoisted(instr ssa.Instruction) {
	c.hoistedInstrs[instr] = true
}

// ExportTest_InjectLoopInfo allows injecting a mock loop info structure.
func (c *Canonicalizer) ExportTest_InjectLoopInfo(info *loop.LoopInfo) {
	c.loopInfo = info
}
