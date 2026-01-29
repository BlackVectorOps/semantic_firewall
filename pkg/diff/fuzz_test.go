package diff_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/testutil"
)

func FuzzFingerprintSource(f *testing.F) {
	f.Add("package main\nfunc test() {}")
	f.Add("package main\nfunc loop() { for {} }")

	f.Fuzz(func(t *testing.T, src string) {
		// Valid Go source sanity check
		if len(src) < 8 || src[:7] != "package" {
			return
		}

		dir, cleanup := testutil.SetupTestEnv(t, "fuzz-")
		defer cleanup()
		path := filepath.Join(dir, "main.go")
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			return
		}

		// Should not panic
		_, _ = diff.FingerprintSource(path, src, ir.DefaultLiteralPolicy)
	})
}
