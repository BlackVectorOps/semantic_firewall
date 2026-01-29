package ir

import (
	"go/constant"
	"go/token"
	"math"

	"golang.org/x/tools/go/ssa"
)

// -- Implementation Details --

// LiteralPolicy defines the configurable strategy for determining which literal values should
// be abstracted into placeholders during canonicalization.
type LiteralPolicy struct {
	AbstractControlFlowComparisons bool
	KeepSmallIntegerIndices        bool
	KeepReturnStatusValues         bool
	KeepStringLiterals             bool
	SmallIntMin                    int64
	SmallIntMax                    int64
	AbstractOtherTypes             bool
}

// DefaultLiteralPolicy preserves small integers used for indexing
// and status codes while masking magic numbers and large constants.
var DefaultLiteralPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: true,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	KeepStringLiterals:             false,
	SmallIntMin:                    -16,
	SmallIntMax:                    16,
	AbstractOtherTypes:             true,
}

// KeepAllLiteralsPolicy is designed for testing or exact matching.
var KeepAllLiteralsPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: false,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	KeepStringLiterals:             true,
	SmallIntMin:                    math.MinInt64,
	SmallIntMax:                    math.MaxInt64,
	AbstractOtherTypes:             false,
}

// IsConst verifies if an ssa.Value is a constant equal to a given target.
func IsConst(v ssa.Value, target constant.Value) bool {
	if v == nil || target == nil {
		return false
	}
	if c, ok := v.(*ssa.Const); ok {
		if c.Value == nil {
			return false
		}
		if c.Value.Kind() != target.Kind() {
			return false
		}
		return constant.Compare(c.Value, token.EQL, target)
	}
	return false
}

// ShouldAbstract decides whether a given constant should be replaced by a placeholder.
func (p *LiteralPolicy) ShouldAbstract(c *ssa.Const, usageContext ssa.Instruction) bool {
	if c == nil || c.Value == nil {
		return false
	}

	if c.Value.Kind() == constant.String {
		if p.KeepStringLiterals {
			return false
		}
		return true
	}

	isInteger := c.Value.Kind() == constant.Int
	isSmall := false
	if isInteger {
		isSmall = p.IsSmallInt(c.Value)
	}

	if usageContext != nil {
		switch instr := usageContext.(type) {
		case *ssa.Return:
			if isInteger {
				if p.KeepReturnStatusValues && isSmall {
					return false
				}
				return true
			}

		case *ssa.BinOp:
			if IsComparisonOp(instr.Op) {
				isControlFlow := false
				if refs := instr.Referrers(); refs != nil {
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.If); ok {
							isControlFlow = true
							break
						}
					}
				}

				if isControlFlow {
					if p.AbstractControlFlowComparisons {
						if isInteger && p.KeepSmallIntegerIndices && isSmall {
							return false
						}
						return true
					}
				}
			}

		case *ssa.IndexAddr:
			if instr.Index != nil && IsConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Index:
			if instr.Index != nil && IsConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Lookup:
			if instr.Index != nil && IsConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Slice:
			isBound := (instr.Low != nil && IsConst(instr.Low, c.Value)) ||
				(instr.High != nil && IsConst(instr.High, c.Value)) ||
				(instr.Max != nil && IsConst(instr.Max, c.Value))

			if isBound {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.MakeSlice:
			isDim := (instr.Len != nil && IsConst(instr.Len, c.Value)) ||
				(instr.Cap != nil && IsConst(instr.Cap, c.Value))

			if isDim && isInteger {
				if p.KeepSmallIntegerIndices && isSmall {
					return false
				}
				return true
			}

		case *ssa.MakeChan:
			if instr.Size != nil && IsConst(instr.Size, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.MakeMap:
			if instr.Reserve != nil && IsConst(instr.Reserve, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Alloc:
			if isInteger {
				if p.KeepSmallIntegerIndices && isSmall {
					return false
				}
				return true
			}
		}
	}

	if isInteger {
		return !isSmall
	}

	return p.AbstractOtherTypes
}

// IsSmallInt checks if the constant fits within the configured small integer range.
func (p *LiteralPolicy) IsSmallInt(c constant.Value) bool {
	if c.Kind() != constant.Int {
		return false
	}
	val, exact := constant.Int64Val(c)
	if !exact {
		return false
	}
	return val >= p.SmallIntMin && val <= p.SmallIntMax
}

// IsComparisonOp identifies strict comparison operators.
func IsComparisonOp(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	default:
		return false
	}
}
