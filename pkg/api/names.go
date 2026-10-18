package api

import (
	"fmt"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"golang.org/x/tools/go/ssa"
)

// SSAFunctionName returns fn's name relative to its own package: "F",
// "(*T).M", "F$1". Unlike ShortFunctionName it does not have to guess where
// the package path ends, so a package whose last path element contains a dot
// ("gopkg.in/yaml.v3", "example.com/lib.v2") is stripped completely.
func SSAFunctionName(fn *ssa.Function) string {
	if fn.Pkg != nil {
		return fn.RelString(fn.Pkg.Pkg)
	}
	return ShortFunctionName(fn.RelString(nil))
}

// ResultName is the name reported for a fingerprinted function: its
// SSAFunctionName, or ShortFunctionName of its full name when the result
// carries no SSA function.
func ResultName(r diff.FingerprintResult) string {
	if fn := r.GetSSAFunction(); fn != nil {
		return SSAFunctionName(fn)
	}
	return ShortFunctionName(r.FunctionName)
}

// ShortFunctionName strips package paths and qualifying identifiers
// from a Go SSA function name so it is readable in diffs and reports.
// Given only the string, it takes the text up to the first dot after the
// last slash as the package name; prefer SSAFunctionName when the function
// is at hand.
//
// It handles three shapes:
//   - "fmt.Println"                              -> "Println"
//   - "pkg.(*Type).Method" / "(*pkg.Type).Method" -> "(*Type).Method"
//   - Generics like "pkg.Func[a/b.T]"            -> "Func[a/b.T]"
//
// Brackets and parens are tracked so qualified types inside generic
// parameters or receiver positions are preserved verbatim.
func ShortFunctionName(fullName string) string {
	// Receiver form: "(*pkg.Type).Method" or "(pkg.Type).Method".
	// Recurse into the receiver type so its package qualifier is
	// stripped while the pointer marker and method tail survive.
	if strings.HasPrefix(fullName, "(") {
		depth := 0
		closeIndex := -1
		for i, c := range fullName {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					closeIndex = i
					break
				}
			}
		}

		if closeIndex > 1 {
			receiver := fullName[1:closeIndex] // e.g. "*pkg.Type"
			rest := fullName[closeIndex+1:]    // e.g. ".Method"

			prefix := ""
			if strings.HasPrefix(receiver, "*") {
				prefix = "*"
				receiver = receiver[1:]
			}

			cleanReceiver := ShortFunctionName(receiver)
			return fmt.Sprintf("(%s%s)%s", prefix, cleanReceiver, rest)
		}
	}

	// Backward scan to strip "github.com/...../pkg." style import paths.
	// Brackets and parens prevent splitting inside generics like
	// "Func[a/b.T]" where the slash is part of a type argument.
	end := len(fullName) - 1
	depthBrackets := 0
	depthParens := 0
	splitIndex := -1

	for i := end; i >= 0; i-- {
		b := fullName[i]
		switch b {
		case ']':
			depthBrackets++
		case '[':
			depthBrackets--
		case ')':
			depthParens++
		case '(':
			depthParens--
		case '/':
			if depthBrackets == 0 && depthParens == 0 {
				splitIndex = i
				goto FoundSplit
			}
		}
	}
FoundSplit:
	name := fullName
	if splitIndex >= 0 {
		name = fullName[splitIndex+1:]
	}

	// Forward scan for the first top-level dot. If the prefix carries
	// brackets/parens it is part of the type signature (e.g.
	// "Type[T].Method") and must be preserved; otherwise it is a bare
	// package name that can be stripped.
	depth := 0
	for i, ch := range name {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '[':
			depth++
		case ']':
			depth--
		case '.':
			if depth == 0 {
				prefix := name[:i]
				if !containsSpecial(prefix) {
					return name[i+1:]
				}
				return name
			}
		}
	}
	return name
}

func containsSpecial(s string) bool {
	return strings.ContainsAny(s, "[]()")
}
