package topology

import (
	"math"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestNormCut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		v, lo, hi, want float64
	}{
		{"below lo", 3, 5, 8, 0},
		{"at lo", 5, 5, 8, 0},
		{"midpoint", 6.5, 5, 8, 0.5},
		{"at hi", 8, 5, 8, 1},
		{"above hi", 9, 5, 8, 1},
		{"degenerate equal", 5, 8, 8, 0},
		{"degenerate inverted", 5, 8, 5, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normCut(tc.v, tc.lo, tc.hi); math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("normCut(%v,%v,%v)=%v want %v", tc.v, tc.lo, tc.hi, got, tc.want)
			}
		})
	}
}

func TestClamp01(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want float64 }{
		{math.NaN(), 0},
		{-1, 0},
		{0, 0},
		{0.5, 0.5},
		{1, 1},
		{2, 1},
		{math.Inf(1), 1},
	}
	for _, tc := range tests {
		if got := clamp01(tc.in); got != tc.want {
			t.Errorf("clamp01(%v)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestTotalStringLen(t *testing.T) {
	t.Parallel()
	if got := totalStringLen(nil); got != 0 {
		t.Errorf("nil: got %d want 0", got)
	}
	if got := totalStringLen([]string{"ab", "c", ""}); got != 3 {
		t.Errorf("got %d want 3", got)
	}
}

func TestHasPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s, prefix string
		want      bool
	}{
		{"dynamic:x", "dynamic:", true},
		{"foo", "dynamic:", false},
		{"", "x", false},
		{"x", "", true},
		{"ab", "abc", false},
		{"abc", "abc", true},
	}
	for _, tc := range tests {
		if got := hasPrefix(tc.s, tc.prefix); got != tc.want {
			t.Errorf("hasPrefix(%q,%q)=%v want %v", tc.s, tc.prefix, got, tc.want)
		}
	}
}

func TestIsIndirectCallSig(t *testing.T) {
	t.Parallel()
	indirect := []string{
		"dynamic:func()",
		"invoke:T.M",
		"go:dynamic:x",
		"defer:dynamic:x",
		// Reflection invocation: the DOT-form is what ExtractTopology actually
		// emits under InstantiateGenerics (verified against real SSA). Matching
		// only the colon-form previously let all reflection dispatch escape the
		// IndirectCallRatio, under-counting obfuscation for reflection-hidden
		// capabilities. Both forms must match.
		"reflect.Call",
		"reflect.CallSlice",
		"reflect.MethodByName",
		"reflect:Call", // colon-form: unreachable under this loader, matched defensively
	}
	for _, s := range indirect {
		if !isIndirectCallSig(s) {
			t.Errorf("isIndirectCallSig(%q)=false, want true", s)
		}
	}
	direct := []string{
		"net.Dial",
		"builtin:println",
		"closure:func()",
		"",
		"call:unknown",
		// reflect introspection helpers emit "reflect.<Func>" too but are
		// ordinary direct calls, NOT dynamic dispatch -- they must NOT count.
		"reflect.TypeOf",
		"reflect.ValueOf",
		"reflect.DeepEqual",
	}
	for _, s := range direct {
		if isIndirectCallSig(s) {
			t.Errorf("isIndirectCallSig(%q)=true, want false", s)
		}
	}
	// Known gap (documented): go:/defer: wrapping an interface invoke is not
	// matched, only go:dynamic:/defer:dynamic: are. Pin current behavior so a
	// future change to close the gap updates this deliberately.
	for _, s := range []string{"go:invoke:T.M", "defer:invoke:T.M"} {
		if isIndirectCallSig(s) {
			t.Errorf("KNOWN GAP changed: isIndirectCallSig(%q) now true — update gap handling", s)
		}
	}
}

func TestClassifyObfuscation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		score float64
		want  ObfuscationClass
	}{
		{0, ObfuscationNone},
		{0.24, ObfuscationNone},
		{0.25, ObfuscationLow},
		{0.49, ObfuscationLow},
		{0.50, ObfuscationModerate},
		{0.74, ObfuscationModerate},
		{0.75, ObfuscationHigh},
		{1.0, ObfuscationHigh},
	}
	for _, tc := range tests {
		if got := classifyObfuscation(tc.score); got != tc.want {
			t.Errorf("classifyObfuscation(%v)=%v want %v", tc.score, got, tc.want)
		}
	}
}

func TestObfuscationClassString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		c    ObfuscationClass
		want string
	}{
		{ObfuscationNone, "NONE"},
		{ObfuscationLow, "LOW"},
		{ObfuscationModerate, "MODERATE"},
		{ObfuscationHigh, "HIGH"},
		{ObfuscationClass(99), "UNKNOWN"},
	}
	for _, tc := range tests {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("%d.String()=%q want %q", int(tc.c), got, tc.want)
		}
	}
}

func TestMaxWindowEntropy(t *testing.T) {
	t.Parallel()

	if got := maxWindowEntropy(nil); got != 0 {
		t.Errorf("empty: got %v want 0", got)
	}
	if got := maxWindowEntropy(make([]byte, 100)); got != 0 {
		t.Errorf("uniform zeros: got %v want 0", got)
	}

	// Small buffer (< one window) equals whole-buffer entropy.
	small := make([]byte, 16)
	for i := range small {
		small[i] = byte(i) // 16 distinct -> entropy 4.0
	}
	if got, want := maxWindowEntropy(small), CalculateEntropy(small); math.Abs(got-want) > 1e-9 {
		t.Errorf("small buffer: maxWindow=%v whole=%v, should be equal", got, want)
	}

	// The headline behavior: a high-entropy blob buried in low-entropy filler
	// must surface as the sliding-window MAX, even though the GLOBAL mean is low.
	// Filler length is a stride multiple so the blob aligns to one window.
	const filler = 15 * entropyWindowStride // align the blob to exactly one window
	data := make([]byte, 0, filler+256+filler)
	data = append(data, make([]byte, filler)...)
	for i := 0; i < 256; i++ {
		data = append(data, byte(i)) // 256 distinct -> window entropy 8.0
	}
	data = append(data, make([]byte, filler)...)

	win := maxWindowEntropy(data)
	global := CalculateEntropy(data)
	if win < 7.9 {
		t.Errorf("embedded blob not surfaced: maxWindow=%v want >=7.9", win)
	}
	if global > 1.5 {
		t.Errorf("global entropy unexpectedly high: %v", global)
	}
	if win-global < 5 {
		t.Errorf("sliding-max (%v) should dwarf global mean (%v)", win, global)
	}
}

// TestStructuralConstOperands pins the pointer-identity assumption behind the
// ByteRun 513->256 fix: the operand slots returned by structuralConstOperands
// must be the SAME *ssa.Value pointers that instr.Operands() returns, so the
// skip-set membership test works. If a future x/tools bump changes Operands()
// to return copies (or reorders fields), this fails at the helper rather than
// surfacing later as a mysterious entropy drift on every []byte literal.
func TestStructuralConstOperands(t *testing.T) {
	t.Parallel()
	dummy := &ssa.Const{} // any non-nil ssa.Value; we only test slot identity

	t.Run("IndexAddr skips index, keeps base", func(t *testing.T) {
		ia := &ssa.IndexAddr{X: dummy, Index: dummy}
		skip := structuralConstOperands(ia)
		ops := ia.Operands(nil) // order: &X, &Index
		if len(ops) != 2 {
			t.Fatalf("IndexAddr.Operands len=%d want 2", len(ops))
		}
		if skip[ops[0]] {
			t.Error("array-base slot wrongly skipped")
		}
		if !skip[ops[1]] {
			t.Error("index slot not skipped — pointer identity with Operands() is broken")
		}
		if ops[1] != &ia.Index {
			t.Error("Operands() no longer returns &Index — x/tools API changed")
		}
	})

	t.Run("Index skips index", func(t *testing.T) {
		i := &ssa.Index{X: dummy, Index: dummy}
		skip := structuralConstOperands(i)
		if !skip[&i.Index] {
			t.Error("Index subscript slot not skipped")
		}
		if skip[&i.X] {
			t.Error("Index base X wrongly skipped")
		}
	})

	t.Run("Lookup skips index", func(t *testing.T) {
		l := &ssa.Lookup{X: dummy, Index: dummy}
		skip := structuralConstOperands(l)
		if !skip[&l.Index] {
			t.Error("Lookup index slot not skipped")
		}
		if skip[&l.X] {
			t.Error("Lookup base X wrongly skipped")
		}
	})

	t.Run("Slice skips bounds, keeps base", func(t *testing.T) {
		s := &ssa.Slice{X: dummy, Low: dummy, High: dummy, Max: dummy}
		skip := structuralConstOperands(s)
		if !skip[&s.Low] || !skip[&s.High] || !skip[&s.Max] {
			t.Error("slice bound slot(s) not skipped")
		}
		if skip[&s.X] {
			t.Error("slice base X wrongly skipped")
		}
	})

	t.Run("non-structural returns nil", func(t *testing.T) {
		if structuralConstOperands(&ssa.Jump{}) != nil {
			t.Error("Jump has no structural operands; want nil skip-set")
		}
	})
}

// FuzzMaxWindowEntropy: result is always a valid Shannon entropy in [0,8], never
// panics, and for sub-window inputs equals the whole-buffer entropy.
func FuzzMaxWindowEntropy(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("hello world"))
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		e := maxWindowEntropy(data)
		if math.IsNaN(e) || e < 0 || e > 8.0000001 {
			t.Fatalf("maxWindowEntropy out of range: %v (len=%d)", e, len(data))
		}
		if len(data) > 0 && len(data) <= entropyWindowSize {
			if w := CalculateEntropy(data); math.Abs(e-w) > 1e-9 {
				t.Fatalf("sub-window mismatch: maxWindow=%v whole=%v", e, w)
			}
		}
	})
}


