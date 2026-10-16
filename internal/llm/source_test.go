package llm

import (
	"slices"
	"strings"
	"testing"
)

const indexedSource = `package p

import "os/exec"

// F is documented.
func F(a int) int {
	g := func() { exec.Command("x").Run() }
	g()
	return helper(a)
}

func helper(a int) int { return a }

type T struct{}

func (t *T) M() { helper(1); t.N() }
func (t T) N()  {}

type G[P any] struct{}

func (g *G[P]) Get() {}

func Gen[P any](p P) { Gen[int](1) }
`

func TestSourceIndex_NamesAndRanges(t *testing.T) {
	idx := NewSourceIndex("p.go", []byte(indexedSource))

	var names []string
	for _, fn := range idx.Functions() {
		names = append(names, fn.Name)
	}
	want := []string{"F", "helper", "(*T).M", "(T).N", "(*G).Get", "Gen"}
	if !slices.Equal(names, want) {
		t.Fatalf("functions = %v; want %v", names, want)
	}

	f, note, ok := idx.Lookup("F")
	if !ok || note != "" {
		t.Fatalf("Lookup(F) = %v, %q, %v", f, note, ok)
	}
	// The documentation comment belongs to the declaration.
	if f.Start != 5 || f.End != 10 {
		t.Errorf("F spans %d-%d; want 5-10", f.Start, f.End)
	}
	src := idx.Source(f)
	if !strings.HasPrefix(src, "5: // F is documented.\n6: func F(a int) int {\n") || !strings.HasSuffix(src, "10: }\n") {
		t.Errorf("Source(F) = %q", src)
	}
}

func TestSourceIndex_LookupResolvesClosuresAndTypeArgs(t *testing.T) {
	idx := NewSourceIndex("p.go", []byte(indexedSource))
	cases := []struct{ name, want, noteWord string }{
		{"F$1", "F", "F$1 is inside F"},
		{"(*T).M$2$1", "(*T).M", "inside (*T).M"},
		{"Gen[int]", "Gen", "inside Gen"},
		{"(*G[int]).Get", "(*G).Get", "inside (*G).Get"},
	}
	for _, tc := range cases {
		fn, note, ok := idx.Lookup(tc.name)
		if !ok || fn.Name != tc.want {
			t.Errorf("Lookup(%q) = %v, %v; want %s", tc.name, fn, ok, tc.want)
			continue
		}
		if !strings.Contains(note, tc.noteWord) {
			t.Errorf("Lookup(%q) note = %q; want it to say %q", tc.name, note, tc.noteWord)
		}
	}
	if _, _, ok := idx.Lookup("missing"); ok {
		t.Error("Lookup(missing) found something")
	}
	var nilIdx *SourceIndex
	if _, _, ok := nilIdx.Lookup("F"); ok || nilIdx.LineCount() != 0 || nilIdx.Lines(1, 3) != "" {
		t.Error("a nil index must serve nothing")
	}
}

func TestSourceIndex_CalleesAndCallers(t *testing.T) {
	idx := NewSourceIndex("p.go", []byte(indexedSource))

	f, _, _ := idx.Lookup("F")
	// Sorted, as written; a call on a call expression is "_.Method".
	if want := []string{"_.Run", "exec.Command", "g", "helper"}; !slices.Equal(f.Callees, want) {
		t.Errorf("callees(F) = %v; want %v", f.Callees, want)
	}
	gen, _, _ := idx.Lookup("Gen")
	if want := []string{"Gen"}; !slices.Equal(gen.Callees, want) {
		t.Errorf("callees(Gen) = %v; want %v (instantiation stripped)", gen.Callees, want)
	}

	if got, want := idx.Callers("helper"), []string{"F", "(*T).M"}; !slices.Equal(got, want) {
		t.Errorf("Callers(helper) = %v; want %v", got, want)
	}
	// A method is matched by its method name through any receiver.
	if got, want := idx.Callers("(T).N"), []string{"(*T).M"}; !slices.Equal(got, want) {
		t.Errorf("Callers((T).N) = %v; want %v", got, want)
	}
	if got := idx.Callers("(*G).Get"); got != nil {
		t.Errorf("Callers((*G).Get) = %v; want none", got)
	}
}

// A file that does not parse still serves its lines, and the declarations
// before the error.
func TestSourceIndex_PartialParse(t *testing.T) {
	idx := NewSourceIndex("p.go", []byte("package p\n\nfunc A() {}\n\nfunc B( {\n"))
	if idx.LineCount() != 6 {
		t.Errorf("LineCount = %d; want 6", idx.LineCount())
	}
	if _, _, ok := idx.Lookup("A"); !ok {
		t.Error("A was not indexed")
	}
	if got := idx.Lines(0, 100); !strings.HasPrefix(got, "1: package p\n") {
		t.Errorf("Lines clamps to the file; got %q", got)
	}
}
