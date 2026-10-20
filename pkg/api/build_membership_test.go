package api_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

const membershipAuth = "package p\n\nimport \"crypto/hmac\"\n\nfunc Valid(a, b []byte) bool { return hmac.Equal(a, b) }\n"

// A file that leaves a default build it was in reads as removed there,
// whatever its code; one that enters the default builds from none reads as
// added. Both are marked with a "build" change. Diff and DiffBatch agree.
func TestDiff_BuildMembershipChange(t *testing.T) {
	const gomod = "module example.com/m\n\ngo 1.22\n"
	dial := "package p\n\nimport \"net\"\n\nfunc Dial(a string) { net.Dial(\"tcp\", a) }\n"
	cases := []struct {
		name                 string
		oldName, oldSrc      string
		newName, newSrc      string
		change               string // the build change, or "" for none
		removed, added, high bool
	}{
		{name: "build line excludes it", oldName: "auth.go", oldSrc: membershipAuth,
			newName: "auth.go", newSrc: "//go:build ignore\n\n" + membershipAuth,
			change: "removed", removed: true, high: true},
		{name: "renamed to another GOOS", oldName: "auth.go", oldSrc: membershipAuth,
			newName: "auth_plan9.go", newSrc: membershipAuth,
			change: "modified", removed: true, added: true, high: true},
		{name: "build line removed", oldName: "dial.go", oldSrc: "//go:build ignore\n\n" + dial,
			newName: "dial.go", newSrc: dial,
			change: "added", added: true, high: true},
		{name: "build line widened", oldName: "auth.go", oldSrc: "//go:build linux\n\n" + membershipAuth,
			newName: "auth.go", newSrc: "//go:build linux || darwin\n\n" + membershipAuth},
		{name: "constraints unchanged", oldName: "auth.go", oldSrc: membershipAuth,
			newName: "auth.go", newSrc: membershipAuth},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"base/go.mod": gomod, "base/p/p.go": "package p\n", "base/p/" + c.oldName: c.oldSrc,
				"head/go.mod": gomod, "head/p/p.go": "package p\n", "head/p/" + c.newName: c.newSrc,
			})
			oldPath, newPath := filepath.Join(dir, "base/p", c.oldName), filepath.Join(dir, "head/p", c.newName)
			single, err := api.Diff(oldPath, newPath)
			if err != nil {
				t.Fatal(err)
			}
			batch := api.DiffBatch([]api.DiffPair{{Old: oldPath, New: newPath}})[0]
			for i, out := range []*models.DiffOutput{single, batch} {
				change := ""
				for _, u := range out.Unanalyzed {
					if u.Kind == "build" {
						change = u.Change
					}
				}
				if change != c.change {
					t.Errorf("(%d) build change %q; want %q", i, change, c.change)
				}
				if (out.Summary.Removed > 0) != c.removed || (out.Summary.Added > 0) != c.added || (out.Summary.HighRiskChanges > 0) != c.high {
					t.Errorf("(%d) summary %+v; want removed %v, added %v, high risk %v", i, out.Summary, c.removed, c.added, c.high)
				}
				if c.removed && !strings.Contains(findFunc(t, out, "Valid").TopologyDelta, "RemovedCheck(crypto/hmac.Equal)") {
					t.Errorf("(%d) Valid not removed with its check: %+v", i, out.Functions)
				}
			}
		})
	}
}
