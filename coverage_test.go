package semanticfw

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestInstructionCoverage ensures that various SSA instructions are correctly canonicalized.
func TestInstructionCoverage(t *testing.T) {
	// Use the KeepAllLiteralsPolicy for easier verification of the output structure.
	policy := KeepAllLiteralsPolicy

	testCases := []struct {
		name       string
		src        string
		funcName   string
		expected   []string // Patterns expected in the canonical IR
		unexpected []string // Patterns that should NOT be in the IR
	}{
		{
			name: "Slices and Arrays (Alloca, IndexAddr, Store, Slice variations)",
			src: `
		package main
		func slices(input int) []int {
			// Optimized by compiler: MakeSlice -> Alloca + Slice
			s := make([]int, 10, 20)
			s[5] = 42 // IndexAddr + Store
			arr := [5]int{1,2,3,4,5}
			// Optimized by compiler: Index -> IndexAddr + UnOp* (Load)
			_ = arr[input]
			s1 := s[1:3:5] // Full slice expression
			return append(s1, arr[0])
		}
		`,
			funcName: "slices",
			expected: []string{
				`Alloca [20]int`,
				`Alloca [5]int`,
				`IndexAddr <vN>, const(5)`,
				`Store <vN>, const(42)`,
				`UnOp *, <vN>`,
				`Slice <vN>, Low:const(1), High:const(3), Max:const(5)`,
				`Call <builtin:append>`,
			},
			unexpected: []string{
				"MakeSlice", // Ensure it was optimized away
			},
		},
		{
			name: "Maps (MakeMap, MapUpdate, Lookup, CommaOk, Extract)",
			src: `
		package main
		func maps(k string) int {
			m := make(map[string]int, 10)
			m["hello"] = 1
			v, ok := m[k]
			if ok { return v }
			return 0
		}
		`,
			funcName: "maps",
			expected: []string{
				`MakeMap map[string]int, Reserve:const(10)`,
				`MapUpdate <vN>, Key:const("hello"), Val:const(1)`,
				`Lookup <vN>, Key:p0, CommaOk`,
				`Extract <vN>, 0`,
				`Extract <vN>, 1`,
			},
		},
		{
			name: "Structs (FieldAddr, UnOp*)",
			src: `
		package main
		type Point struct { X, Y int }
		func structs(p *Point) int {
			x := p.X // ssa.FieldAddr + UnOp*
			p.Y = 5  // ssa.FieldAddr + Store
			return x
		}
		`,
			funcName: "structs",
			expected: []string{
				`FieldAddr p0, field(0)`,
				`FieldAddr p0, field(1)`,
				`UnOp *, <vN>`,
				`Store <vN>, const(5)`,
			},
			unexpected: []string{"Field "},
		},
		{
			name: "Type Conversions (ChangeType, Convert, MakeInterface, TypeAssert)",
			src: `
		package main
		type MyInt int
		type IntPtr *int
		func conversions(a int) interface{} {
			pA := &a
			b := uint(a) // Convert
			var i interface{} = MyInt(b) // Convert, MakeInterface
			val, ok := i.(MyInt) // TypeAssert CommaOk
			p := IntPtr(pA) // ChangeType
			if ok { return val }
			return p
		}
		`,
			funcName: "conversions",
			expected: []string{
				`Convert uint, <vN>`,
				// Types are sanitized to use package name instead of full path
				`Convert main.MyInt, <vN>`,
				`MakeInterface interface{}, <vN>`,
				`TypeAssert <vN>, AssertedType:main.MyInt, CommaOk`,
				`ChangeType main.IntPtr, <vN>`,
			},
		},
		{
			name: "Concurrency (MakeChan, Send, Recv, Go, MakeClosure, Select)",
			src: `
		package main
		func concurrency(data int, chBool chan bool) int {
			ch := make(chan int, 1) // MakeChan
			// Explicitly define closure to ensure MakeClosure is generated robustly
			fn := func(d int) {
				ch <- d // Send
			}
			go fn(data)

			// Select statement (non-blocking due to default)
			select {
			case res := <-ch: // Recv (via Select)
				return res
			case chBool <- true: // Send (via Select)
				return 1
			default:
				return -1
			}
		}
		`,
			funcName: "concurrency",
			expected: []string{
				`MakeChan chan int, Size:const(1)`,
				// Bindings capture the environment (ch in this case).
				// func_ref format is <func_ref:NAME:SIGNATURE>
				`MakeClosure <func_ref:<ANY>:func(int)> [<vN>]`,
				`Go <vN>(p0)`,
				// Select statement expectations (deterministic order).
				// FIX: Updated expectation based on deterministic sorting (Default first, then sorted channels alphabetically: p1 before vN).
				`Select [non-blocking] (<- <default>) (-> p1 <- const(true)) (<- <vN>)`,
			},
		},
		{
			name: "Defer and Panic (Defer, RunDefers, Panic, MakeInterface)",
			src: `
		package main
		func panicDefer(x int) (r int) {
			defer func() { r = 1 }() // Defer, MakeClosure
			if x == 0 {
				panic("zero") // Panic, implicit MakeInterface
			}
			return 2
		}
		`,
			funcName: "panicDefer",
			expected: []string{
				// Bindings capture the environment (r in this case)
				`MakeClosure <func_ref:<ANY>:func()> [<vN>]`,
				`Defer <vN>()`,
				`MakeInterface interface{}, const("zero")`,
				`Panic <vN>`,
				`RunDefers`,
			},
		},
		{
			name: "Closures (FreeVars usage and normalization)",
			src: `
		package main
		func closure(x int) func(int) int {
			return func(y int) int {
				return x + y
			}
		}
		`,
			funcName: "closure$1",
			expected: []string{
				`UnOp *, fv0`,
				// The order depends on normalization (commutative +)
				`BinOp +, p0, <vN>`,
			},
		},
		{
			name: "User Init Function (init#1)",
			src: `
		package main
		var GlobalVarB = 10
		func Use(i int){} // Use the variable so SSA includes the store robustly
		func init() {
			GlobalVarB = 20
			Use(GlobalVarB)
		}
		`,
			funcName: "init#1",
			expected: []string{
				`Store <global:*int>, const(20)`,
			},
		},
		{
			// Added test case for Invoke (Coverage Increase)
			name: "Interface Methods (Invoke)",
			src: `
		package main
		type Runner interface {
			Run(int) int
		}
		func callInterface(r Runner, v int) int {
			// This generates an ssa.Call instruction with IsInvoke() == true.
			return r.Run(v)
		}
		`,
			funcName: "callInterface",
			expected: []string{
				// Expecting: Call Invoke p0.Run(p1)
				`Call Invoke p0.Run(p1)`,
			},
		},
	}

	// Create an isolated environment for the test (Uses helper from canonicalizer_test.go)
	tempDir, cleanup := setupTestEnv(t, "coverage-test-")
	defer cleanup()

	// Use a regex to sanitize filenames
	reg := regexp.MustCompile("[^a-zA-Z0-9_]+")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a unique, safe file name for each test case.
			safeFileName := reg.ReplaceAllString(tc.name, "_")
			tempFile := filepath.Join(tempDir, safeFileName+".go")

			if err := os.WriteFile(tempFile, []byte(tc.src), 0644); err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}

			// Use FingerprintSourceAdvanced with strictMode=true
			results, err := FingerprintSourceAdvanced(tempFile, tc.src, policy, true)
			if err != nil {
				t.Fatalf("Failed to fingerprint source: %v\nSource:\n%s", err, tc.src)
			}

			res := findResult(results, tc.funcName)

			if res == nil {
				t.Fatalf("Could not find result for function %s. Found functions: %v", tc.funcName, getFunctionNames(results))
			}

			ir := res.CanonicalIR

			for _, expectedPattern := range tc.expected {
				checkIRPattern(t, ir, expectedPattern)
			}

			for _, unexpectedPattern := range tc.unexpected {
				if strings.Contains(ir, unexpectedPattern) {
					t.Errorf("Found unexpected snippet in IR.\nUnexpected: %s\nActual IR:\n%s", unexpectedPattern, ir)
				}
			}
		})
	}
}
