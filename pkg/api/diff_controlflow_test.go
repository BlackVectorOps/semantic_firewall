package api_test

import (
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

func hasOp(ops []string, substr string) bool {
	for _, op := range ops {
		if strings.Contains(op, substr) {
			return true
		}
	}
	return false
}

// Control-flow changes keep every operation and its operands, so the
// data-flow alignment pairs all of them. They must still be reported as
// modified, with the branch or the moved instruction as evidence.
func TestDiff_ControlFlowChangesAreModified(t *testing.T) {
	cases := []struct {
		name, fn, oldSrc, newSrc, evidence string
	}{
		{
			name: "swapped returns",
			fn:   "ValidToken",
			oldSrc: `package p
import "crypto/subtle"
func ValidToken(got, want []byte) bool {
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false
	}
	return true
}`,
			newSrc: `package p
import "crypto/subtle"
func ValidToken(got, want []byte) bool {
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return true
	}
	return false
}`,
			evidence: "if ",
		},
		{
			name: "negated condition",
			fn:   "Authorize",
			oldSrc: `package p
import "errors"
func Authorize(user string, isAdmin bool) error {
	if !isAdmin {
		return errors.New(user)
	}
	return nil
}`,
			newSrc: `package p
import "errors"
func Authorize(user string, isAdmin bool) error {
	if isAdmin {
		return errors.New(user)
	}
	return nil
}`,
			evidence: "if ",
		},
		{
			name: "call moved out of its guard",
			fn:   "Cleanup",
			oldSrc: `package p
import "os"
func Cleanup(path string, confirmed bool) error {
	if confirmed {
		return os.RemoveAll(path)
	}
	return nil
}`,
			newSrc: `package p
import "os"
func Cleanup(path string, confirmed bool) error {
	err := os.RemoveAll(path)
	if confirmed {
		return err
	}
	return nil
}`,
			evidence: "os.RemoveAll",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := diffSources(t, c.oldSrc, c.newSrc)
			f := findFunc(t, out, c.fn)
			if f.Status != models.StatusModified {
				t.Fatalf("status = %q; want modified: %+v", f.Status, f)
			}
			if !hasOp(f.AddedOps, c.evidence) || !hasOp(f.RemovedOps, c.evidence) {
				t.Errorf("want %q in added and removed ops; added=%v removed=%v", c.evidence, f.AddedOps, f.RemovedOps)
			}
			if out.Summary.SemanticMatchPct == 100 {
				t.Errorf("semantic_match_pct = 100 for a modified function")
			}
		})
	}
}

// Reordering independent statements inside one block keeps the blocks
// corresponding, so no instruction is reported as moved.
func TestDiff_SameBlockReorderHasNoMovedOps(t *testing.T) {
	out := diffSources(t, `package p
func F(a, b int) (int, int) {
	x := a * 3
	y := b * 5
	return x, y
}`, `package p
func F(a, b int) (int, int) {
	y := b * 5
	x := a * 3
	return x, y
}`)
	f := findFunc(t, out, "F")
	if len(f.AddedOps) != 0 || len(f.RemovedOps) != 0 {
		t.Errorf("reordering within a block produced ops: added=%v removed=%v", f.AddedOps, f.RemovedOps)
	}
}

// A changed parameter list does not hide the body's changes: parameters are
// aligned by name and type, and the uses of a new parameter are reported.
func TestDiff_SignatureChangeKeepsOps(t *testing.T) {
	out := diffSources(t, `package p
import "os"
func Save(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
`, `package p
import (
	"os"
	"os/exec"
)
func Save(path string, data []byte, hook string) error {
	exec.Command(hook).Run()
	return os.WriteFile(path, data, 0o777)
}
`)
	f := findFunc(t, out, "Save")
	if f.Status != models.StatusModified {
		t.Fatalf("Save: status %q; want modified", f.Status)
	}
	for _, want := range []string{"os/exec.Command(hook", "os.WriteFile(path, data, 511"} {
		if !hasOp(f.AddedOps, want) {
			t.Errorf("added_ops %q lack %q", f.AddedOps, want)
		}
	}
	if !hasOp(f.RemovedOps, "os.WriteFile(path, data, 384") {
		t.Errorf("removed_ops %q lack the 0o600 WriteFile", f.RemovedOps)
	}
}

// Type parameters are compared by position: renaming one is not a change,
// reordering them is.
func TestDiff_TypeParameterRename(t *testing.T) {
	out := diffSources(t, `package p
type List[T any] struct{ items []T }
func (l *List[T]) Push(v T) { l.items = append(l.items, v) }
func (l *List[T]) Each(f func(T)) {
	for _, v := range l.items {
		func() { f(v) }()
	}
}
func Pair[K comparable, V any](k K, v V) map[K]V { return map[K]V{k: v} }
func Tagged[T any](v T) any { return struct{ T T }{v} }
`, `package p
type List[E any] struct{ items []E }
func (l *List[E]) Push(v E) { l.items = append(l.items, v) }
func (l *List[E]) Each(f func(E)) {
	for _, v := range l.items {
		func() { f(v) }()
	}
}
func Pair[V comparable, K any](k V, v K) map[V]K { return map[V]K{k: v} }
func Tagged[E any](v E) any { return struct{ T E }{v} }
`)
	if out.Summary.RenamedFunctions != 0 {
		t.Errorf("renamed_functions = %d; want 0", out.Summary.RenamedFunctions)
	}
	for _, name := range []string{"(*List[T]).Push → (*List[E]).Push", "(*List[T]).Each → (*List[E]).Each", "(*List[T]).Each$1 → (*List[E]).Each$1", "Pair", "Tagged"} {
		if f := findFunc(t, out, name); f.Status != models.StatusPreserved {
			t.Errorf("%s: status %q; want preserved (added %q, removed %q)", name, f.Status, f.AddedOps, f.RemovedOps)
		}
	}

	out = diffSources(t, `package p
func Pair[K comparable, V any](k K, v V) map[K]V { return map[K]V{k: v} }
`, `package p
func Pair[V any, K comparable](k K, v V) map[K]V { return map[K]V{k: v} }
`)
	if f := findFunc(t, out, "Pair"); f.Status != models.StatusModified {
		t.Errorf("Pair with reordered type parameters: status %q; want modified", f.Status)
	}
}

// When a generic method changes along with its type parameter's name, only
// the changed instructions are reported.
func TestDiff_TypeParameterRenameWithChange(t *testing.T) {
	out := diffSources(t, `package p
type List[T any] struct{ items []T }
func (l *List[T]) Push(v T) { l.items = append(l.items, v) }
func (l *List[T]) Fill(v T, n int) {
	for i := 0; i < n; i++ {
		l.Push(v)
	}
}
`, `package p
import "os"
type List[E any] struct{ items []E }
func (l *List[E]) Push(v E) { l.items = append(l.items, v) }
func (l *List[E]) Fill(v E, n int) {
	for i := 0; i < n; i++ {
		l.Push(v)
	}
	os.RemoveAll("/tmp/x")
}
`)
	f := findFunc(t, out, "(*List[T]).Fill → (*List[E]).Fill")
	if f.Status != models.StatusModified {
		t.Fatalf("Fill: status %q; want modified", f.Status)
	}
	if hasOp(f.AddedOps, "Push") || hasOp(f.RemovedOps, "Push") {
		t.Errorf("unchanged Push call reported: added %q, removed %q", f.AddedOps, f.RemovedOps)
	}
	if !hasOp(f.AddedOps, "os.RemoveAll") {
		t.Errorf("added_ops %q lack os.RemoveAll", f.AddedOps)
	}
}

// Struct fields are identified by name: reordering or inserting fields does
// not change an accessor, reading a different field that took the old one's
// position does.
func TestDiff_FieldsByName(t *testing.T) {
	const oldSrc = `package p
type User struct {
	IsAdmin  bool
	IsBanned bool
	Name     string
}
func CanDelete(u *User) bool { return u.IsAdmin }
func Label(u User) string    { return u.Name }
`
	out := diffSources(t, oldSrc, `package p
type User struct {
	IsBanned bool
	Comment  string
	IsAdmin  bool
	Name     string
}
func CanDelete(u *User) bool { return u.IsAdmin }
func Label(u User) string    { return u.Name }
`)
	for _, name := range []string{"CanDelete", "Label"} {
		if f := findFunc(t, out, name); f.Status != models.StatusPreserved {
			t.Errorf("%s after a field reorder: status %q; want preserved", name, f.Status)
		}
	}

	out = diffSources(t, oldSrc, `package p
type User struct {
	IsBanned bool
	IsAdmin  bool
	Name     string
}
func CanDelete(u *User) bool { return u.IsBanned }
func Label(u User) string    { return u.Name }
`)
	f := findFunc(t, out, "CanDelete")
	if f.Status != models.StatusModified {
		t.Fatalf("CanDelete reading IsBanned instead of IsAdmin: status %q; want modified", f.Status)
	}
	if !hasOp(f.AddedOps, "IsBanned") || !hasOp(f.RemovedOps, "IsAdmin") {
		t.Errorf("field change missing from ops: added %q, removed %q", f.AddedOps, f.RemovedOps)
	}
}
