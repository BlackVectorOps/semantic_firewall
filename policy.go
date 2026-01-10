{
Filename: policy.go
Full Content:
package semanticfw

import (
	"go/constant"
	"go/token"
	"math"

	"golang.org/x/tools/go/ssa"
)

// -- Implementation Details --

// LiteralPolicy defines the configurable strategy for determining which literal
// values should be abstracted into placeholders during canonicalization.
// It allows fine grained control over integer abstraction in different contexts.
type LiteralPolicy struct {
	AbstractControlFlowComparisons bool
	KeepSmallIntegerIndices        bool
	KeepReturnStatusValues         bool
	SmallIntMin                    int64
	SmallIntMax                    int64
	AbstractOtherTypes             bool
}

// DefaultLiteralPolicy represents the standard policy for fingerprinting;
// it preserves small integers used for indexing and status codes while masking
// magic numbers and large constants.
var DefaultLiteralPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: true,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    -16,
	SmallIntMax:                    16,
	AbstractOtherTypes:             true,
}

// KeepAllLiteralsPolicy is designed for testing or exact matching by disabling
// most abstractions and expanding the "small" integer range to the full int64 spectrum.
var KeepAllLiteralsPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: false,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    math.MinInt64,
	SmallIntMax:                    math.MaxInt64,
	AbstractOtherTypes:             false,
}

// verifies if an ssa.Value is a constant equal to a given target.
// It rigorously checks types to prevent panic during comparison.
func isConst(v ssa.Value, target constant.Value) bool {
	if v == nil || target == nil {
		return false
	}
	if c, ok := v.(*ssa.Const); ok {
		// handle nil constants defensively
		if c.Value == nil {
			return false
		}
		// ensure values are comparable; mixing types in constant.Compare can panic
		if c.Value.Kind() != target.Kind() {
			return false
		}
		// perform precise comparison using the compiler constant package
		return constant.Compare(c.Value, token.EQL, target)
	}
	return false
}

// decides whether a given constant should be replaced by a generic placeholder.
// It analyzes the constant's type, value, and immediate usage context in the SSA graph.
func (p *LiteralPolicy) ShouldAbstract(c *ssa.Const, usageContext ssa.Instruction) bool {
	// defensive check: nil constants cannot be abstracted or analyzed
	if c == nil || c.Value == nil {
		return false
	}

	isInteger := c.Value.Kind() == constant.Int
	isSmall := false
	if isInteger {
		isSmall = p.isSmallInt(c.Value)
	}

	// analyze the instruction consuming this constant
	if usageContext != nil {
		switch instr := usageContext.(type) {
		case *ssa.Return:
			if isInteger {
				// if configured, preserve small integers as likely status codes
				if p.KeepReturnStatusValues && isSmall {
					return false
				}
				return true
			}

		case *ssa.BinOp:
			// check if this binary operation feeds into a control flow decision
			if isComparisonOp(instr.Op) {
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
						// allow small loop bounds if configured
						if isInteger && p.KeepSmallIntegerIndices && isSmall {
							return false
						}
						return true
					}
				}
			}

		case *ssa.IndexAddr:
			// accessing array/slice: index context
			if instr.Index != nil && isConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Index:
			// accessing map/string (legacy or specific types): index context
			if instr.Index != nil && isConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Lookup:
			// map[key] or string[i]: check if c is the key/index
			if instr.Index != nil && isConst(instr.Index, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
				// for non integer map keys (e.g. strings), fall through to default
			}

		case *ssa.Slice:
			// slicing operations: low, high, max are index like bounds
			isBound := (instr.Low != nil && isConst(instr.Low, c.Value)) ||
				(instr.High != nil && isConst(instr.High, c.Value)) ||
				(instr.Max != nil && isConst(instr.Max, c.Value))

			if isBound {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.MakeSlice:
			// slice creation: len and cap are dimension specifiers
			isDim := (instr.Len != nil && isConst(instr.Len, c.Value)) ||
				(instr.Cap != nil && isConst(instr.Cap, c.Value))

			if isDim && isInteger {
				if p.KeepSmallIntegerIndices && isSmall {
					return false
				}
				return true
			}

		case *ssa.MakeChan:
			// channel creation: buffer size is a dimension specifier
			if instr.Size != nil && isConst(instr.Size, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.MakeMap:
			// map creation: reserve size is a dimension specifier
			if instr.Reserve != nil && isConst(instr.Reserve, c.Value) {
				if isInteger {
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					return true
				}
			}

		case *ssa.Alloc:
			// the canonicalizer generates synthetic constants for static array lengths
			// and passes the Alloc instruction as context; we treat these like dimensions
			if isInteger {
				if p.KeepSmallIntegerIndices && isSmall {
					return false
				}
				return true
			}
		}
	}

	// fallback: default behavior for integers and other types
	if isInteger {
		return !isSmall
	}

	return p.AbstractOtherTypes
}

// checks if the constant is an integer fitting within the configured small integer range.
func (p *LiteralPolicy) isSmallInt(c constant.Value) bool {
	if c.Kind() != constant.Int {
		return false
	}
	// Int64Val returns exact=false if the value doesn't fit in int64; which inherently means it is not small
	val, exact := constant.Int64Val(c)
	if !exact {
		return false
	}
	return val >= p.SmallIntMin && val <= p.SmallIntMax
}

// identifies strict comparison operators.
func isComparisonOp(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	default:
		return false
	}
}
}
