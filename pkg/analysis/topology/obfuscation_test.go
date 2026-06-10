package topology_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/testutil"
)

// itoa is a tiny dependency-free int formatter for building array-literal source.
func itoa(n int) string { return fmt.Sprintf("%d", n) }

// arr builds an n-element []byte composite literal with high-entropy contents
// (a scrambled permutation, order-independent for entropy but distinct bytes).
func arr(n int) string {
	var b strings.Builder
	b.WriteString("[]byte{")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(itoa((i*167 + 13) % 256))
	}
	b.WriteByte('}')
	return b.String()
}

func analyze(t *testing.T, src, fn string) topology.ObfuscationProfile {
	t.Helper()
	f := testutil.CompileAndGetFunction(t, src, fn)
	topo := topology.ExtractTopology(f)
	if topo == nil {
		t.Fatal("ExtractTopology returned nil")
	}
	return topo.Obfuscation
}

func hasIndicator(p topology.ObfuscationProfile, name string) bool {
	for _, ind := range p.Indicators {
		if ind == name {
			return true
		}
	}
	return false
}

func TestAnalyzeObfuscation_Integration(t *testing.T) {
	t.Parallel()

	payload256 := "package main\nfunc f() byte { p := " + arr(256) + "\n\treturn p[0] }"

	tests := []struct {
		name  string
		src   string
		fn    string
		check func(t *testing.T, p topology.ObfuscationProfile)
	}{
		{
			name: "clean function scores zero",
			src:  "package main\nfunc f(a, b int) int { return a + b }",
			fn:   "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.Class != topology.ObfuscationNone {
					t.Errorf("class=%s want NONE (score %.3f)", p.Class, p.Score)
				}
				if len(p.Indicators) != 0 {
					t.Errorf("unexpected indicators: %v", p.Indicators)
				}
			},
		},
		{
			name: "indirect-only is capped below moderate",
			src:  "package main\nfunc f(g func(), h func(), k func()) { g(); h(); k() }",
			fn:   "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.IndirectCallRatio != 1.0 {
					t.Errorf("IndirectCallRatio=%.2f want 1.0", p.IndirectCallRatio)
				}
				if p.Score >= 0.50 {
					t.Errorf("lone corroborating signal not capped: score=%.3f class=%s", p.Score, p.Class)
				}
				if !hasIndicator(p, "indirect-dispatch") {
					t.Errorf("missing indirect-dispatch indicator: %v", p.Indicators)
				}
			},
		},
		{
			name: "local packed payload is HIGH",
			src:  payload256,
			fn:   "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.Class != topology.ObfuscationHigh {
					t.Errorf("class=%s want HIGH (score %.3f)", p.Class, p.Score)
				}
				if p.Score < 0.9 {
					t.Errorf("score=%.3f want >=0.9", p.Score)
				}
				for _, want := range []string{"high-entropy-window", "high-entropy-const-pool", "byte-array-payload"} {
					if !hasIndicator(p, want) {
						t.Errorf("missing dispositive indicator %q: %v", want, p.Indicators)
					}
				}
			},
		},
		{
			name: "flattened state machine fires flattening indicator",
			src: `package main
func f(n int) int {
	state, r := 0, 0
	for {
		switch state {
		case 0: r += 1; state = 1
		case 1: r += 2; state = 2
		case 2: r += 3; state = 3
		case 3: r += 4; state = 4
		case 4: r += 5; state = 5
		case 5: r += 6; state = 6
		case 6: return r
		default: state = 0
		}
	}
}`,
			fn: "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.FlatteningScore <= 0 {
					t.Errorf("FlatteningScore=%.3f want >0", p.FlatteningScore)
				}
				if !hasIndicator(p, "control-flow-flattening") {
					t.Errorf("missing control-flow-flattening: %v", p.Indicators)
				}
			},
		},
		{
			name: "sequential ifs do not look flattened",
			src: `package main
func f(a, b, c, d, e, g int) int {
	r := 0
	if a > 0 { r += 1 }
	if b > 0 { r += 2 }
	if c > 0 { r += 3 }
	if d > 0 { r += 4 }
	if e > 0 { r += 5 }
	if g > 0 { r += 6 }
	return r
}`,
			fn: "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.FlatteningScore != 0 {
					t.Errorf("FlatteningScore=%.3f want 0 (not flattened)", p.FlatteningScore)
				}
				if p.Class != topology.ObfuscationNone {
					t.Errorf("class=%s want NONE", p.Class)
				}
			},
		},
		{
			name: "normal loop with decoder shape is capped (lone corroborating)",
			src: `package main
func f(xs []int) int {
	sum := 0
	for _, x := range xs {
		if x < 0 { continue }
		if x > 100 { break }
		sum += x
	}
	return sum
}`,
			fn: "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.Score >= 0.50 {
					t.Errorf("benign loop not capped: score=%.3f class=%s indicators=%v", p.Score, p.Class, p.Indicators)
				}
			},
		},
		{
			name: "wide-int constants fold but do not form a byte run",
			src:  "package main\nfunc f() uint64 { return 0x4142434445464748 }",
			fn:   "f",
			check: func(t *testing.T, p topology.ObfuscationProfile) {
				if p.ConstPoolEntropy <= 0 {
					t.Errorf("ConstPoolEntropy=%.3f want >0 (fold should populate pool)", p.ConstPoolEntropy)
				}
				if p.ByteArrayPayloadBytes != 0 {
					t.Errorf("ByteArrayPayloadBytes=%d want 0 (wide ints are not a byte run)", p.ByteArrayPayloadBytes)
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.check(t, analyze(t, tc.src, tc.fn))
		})
	}
}

// TestAnalyzeObfuscation_ByteRunNotDoubled pins the structural-operand fix: a
// 256-element []byte literal must report exactly 256 payload bytes (not ~513),
// and removing the index ramp must let window entropy reach its true maximum.
func TestAnalyzeObfuscation_ByteRunNotDoubled(t *testing.T) {
	t.Parallel()
	src := "package main\nfunc f() byte { p := " + arr(256) + "\n\treturn p[0] }"
	p := analyze(t, src, "f")
	if p.ByteArrayPayloadBytes != 256 {
		t.Errorf("ByteArrayPayloadBytes=%d want 256 (array subscripts must be excluded)", p.ByteArrayPayloadBytes)
	}
	if p.MaxWindowEntropy < 7.99 {
		t.Errorf("MaxWindowEntropy=%.4f want ~8.0 (index ramp must not dilute)", p.MaxWindowEntropy)
	}
}

// TestAnalyzeObfuscation_CorroborationMonotonic pins the dispositive floor:
// adding a decoder loop to a real payload must never lower the score.
func TestAnalyzeObfuscation_CorroborationMonotonic(t *testing.T) {
	t.Parallel()
	alone := analyze(t, "package main\nfunc f() byte { p := "+arr(64)+"\n\treturn p[0] }", "f")
	withDecoder := analyze(t,
		"package main\nfunc f(k byte) byte { p := "+arr(64)+"\n\tfor i := 0; i < len(p); i++ { p[i] = p[i] ^ k }\n\treturn p[0] }",
		"f")
	if withDecoder.Score < alone.Score {
		t.Errorf("corroboration lowered score: payload+decoder %.4f < payload-alone %.4f", withDecoder.Score, alone.Score)
	}
}

// TestAnalyzeObfuscation_PackageLevelPayloadInvisible documents the known scope
// limit: package-level payload globals lower their constants into package init,
// not the consuming function, so per-function analysis cannot see them. If a
// future per-package pass changes this, this test fails loudly to prompt review.
func TestAnalyzeObfuscation_PackageLevelPayloadInvisible(t *testing.T) {
	t.Parallel()
	src := "package main\nvar gp = " + arr(256) + "\nfunc f() byte { return gp[0] }"
	p := analyze(t, src, "f")
	if p.Score != 0 || p.ByteArrayPayloadBytes != 0 {
		t.Errorf("package-level payload became visible: score=%.3f bytes=%d — scope limit changed, update docs/test",
			p.Score, p.ByteArrayPayloadBytes)
	}
}

// TestAnalyzeObfuscation_NilFnFallback exercises the synthesized-topology path
// (t.fn == nil): string + call-signature signals still compute, structural SSA
// signals are zero, and nothing panics.
func TestAnalyzeObfuscation_NilFnFallback(t *testing.T) {
	t.Parallel()
	topo := &topology.FunctionTopology{
		StringLiterals: []string{"some-benign-config-string"},
		CallSignatures: map[string]int{"dynamic:func()": 1, "net.Dial": 1},
	}
	p := topology.AnalyzeObfuscation(topo) // must not panic with nil fn
	if p.IndirectCallRatio != 0.5 {
		t.Errorf("IndirectCallRatio=%.2f want 0.5 (1 of 2 calls indirect)", p.IndirectCallRatio)
	}
	if p.FlatteningScore != 0 || p.DecoderLoopLikelihood != 0 {
		t.Errorf("structural signals should be 0 with nil fn: flat=%.3f decoder=%.3f", p.FlatteningScore, p.DecoderLoopLikelihood)
	}
	if p.ByteArrayPayloadBytes != 0 {
		t.Errorf("ByteArrayPayloadBytes=%d want 0 (no SSA to walk)", p.ByteArrayPayloadBytes)
	}
}

// FuzzAnalyzeObfuscation drives the fallback path with arbitrary strings/calls
// and asserts the output invariants hold no matter the input.
func FuzzAnalyzeObfuscation(f *testing.F) {
	f.Add("hello", "net.Dial", 1)
	f.Add("", "dynamic:x", 0)
	f.Add(strings.Repeat("\x00\xff", 500), "reflect:Call", 7)
	f.Fuzz(func(t *testing.T, s, callSig string, count int) {
		if count < 0 {
			count = -count
		}
		if count > 1<<20 {
			count = 1 << 20
		}
		topo := &topology.FunctionTopology{
			StringLiterals: []string{s},
			CallSignatures: map[string]int{callSig: count},
		}
		p := topology.AnalyzeObfuscation(topo)

		if p.Score < 0 || p.Score > 1 {
			t.Fatalf("Score out of range: %v", p.Score)
		}
		if p.MaxWindowEntropy < 0 || p.MaxWindowEntropy > 8.0000001 {
			t.Fatalf("MaxWindowEntropy out of range: %v", p.MaxWindowEntropy)
		}
		if p.ConstPoolEntropy < 0 || p.ConstPoolEntropy > 8.0000001 {
			t.Fatalf("ConstPoolEntropy out of range: %v", p.ConstPoolEntropy)
		}
		if p.IndirectCallRatio < 0 || p.IndirectCallRatio > 1 {
			t.Fatalf("IndirectCallRatio out of range: %v", p.IndirectCallRatio)
		}
		// Class must agree with Score's band.
		switch p.Class {
		case topology.ObfuscationNone:
			if !(p.Score < 0.25) {
				t.Fatalf("class NONE but score %v", p.Score)
			}
		case topology.ObfuscationLow:
			if !(p.Score >= 0.25 && p.Score < 0.50) {
				t.Fatalf("class LOW but score %v", p.Score)
			}
		case topology.ObfuscationModerate:
			if !(p.Score >= 0.50 && p.Score < 0.75) {
				t.Fatalf("class MODERATE but score %v", p.Score)
			}
		case topology.ObfuscationHigh:
			if !(p.Score >= 0.75) {
				t.Fatalf("class HIGH but score %v", p.Score)
			}
		}
	})
}

func BenchmarkAnalyzeObfuscation(b *testing.B) {
	// Fallback path over a large high-entropy pool — exercises pool build,
	// sliding-window entropy (the dominant cost), and aggregation.
	var sb strings.Builder
	for i := 0; i < 64*1024; i++ {
		sb.WriteByte(byte((i*167 + 13) % 256))
	}
	topo := &topology.FunctionTopology{
		StringLiterals: []string{sb.String()},
		CallSignatures: map[string]int{"dynamic:func()": 3, "net.Dial": 1},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = topology.AnalyzeObfuscation(topo)
	}
}
