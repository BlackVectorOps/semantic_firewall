package diff_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/diff"
)

// VendorDir follows the go command's rule for building from a vendor
// directory: the module's when its go.mod says go 1.14 or later (1.16 when
// it says nothing), the workspace's when its go.work says go 1.22 or later.
func TestVendorDir(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // "" is a directory
		dir   string            // relative to the root; "" is the root
		want  string            // relative to the root; "" is none
	}{
		{"module go 1.14", map[string]string{"go.mod": "module m\n\ngo 1.14\n", "vendor": ""}, "", "vendor"},
		{"module go 1.13", map[string]string{"go.mod": "module m\n\ngo 1.13\n", "vendor": ""}, "", ""},
		{"module without a go line", map[string]string{"go.mod": "module m\n", "vendor": ""}, "", "vendor"},
		// The comment must not hide the version: unread, a missing go line
		// would count as 1.16 and vendor.
		{"go line with a comment", map[string]string{"go.mod": "module m\n\ngo 1.13 // old\n", "vendor": ""}, "", ""},
		{"no vendor directory", map[string]string{"go.mod": "module m\n\ngo 1.22\n"}, "", ""},
		{"vendor is a file", map[string]string{"go.mod": "module m\n\ngo 1.22\n", "vendor": "x"}, "", ""},
		{"no go.mod", map[string]string{"vendor": ""}, "", ""},
		{"subdirectory of the module", map[string]string{"go.mod": "module m\n\ngo 1.22\n", "vendor": "", "a/b/x.go": "package b\n"}, "a/b", "vendor"},
		{"nested module", map[string]string{"go.mod": "module m\n\ngo 1.22\n", "vendor": "", "n/go.mod": "module n\n\ngo 1.22\n"}, "n", ""},
		{"workspace go 1.22", map[string]string{"go.work": "go 1.22\n\nuse ./m\n", "vendor": "", "m/go.mod": "module m\n\ngo 1.22\n", "m/vendor": ""}, "m", "vendor"},
		{"workspace go 1.21", map[string]string{"go.work": "go 1.21\n\nuse ./m\n", "vendor": "", "m/go.mod": "module m\n\ngo 1.22\n", "m/vendor": ""}, "m", ""},
		{"workspace without a go line", map[string]string{"go.work": "use ./m\n", "vendor": "", "m/go.mod": "module m\n\ngo 1.22\n", "m/vendor": ""}, "m", ""},
		{"workspace without a vendor directory", map[string]string{"go.work": "go 1.22\n\nuse ./m\n", "m/go.mod": "module m\n\ngo 1.22\n", "m/vendor": ""}, "m", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range c.files {
				p := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if content == "" {
					if err := os.Mkdir(p, 0o755); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want := ""
			if c.want != "" {
				want = filepath.Join(root, c.want)
			}
			if got := diff.VendorDir(filepath.Join(root, c.dir)); got != want {
				t.Errorf("VendorDir = %q; want %q", got, want)
			}
			env := diff.HardenedEnvFor(filepath.Join(root, c.dir))
			if vendored := env[len(env)-1] == "GOFLAGS=-mod=vendor"; vendored != (want != "") {
				t.Errorf("HardenedEnvFor ends with %q; want -mod=vendor: %v", env[len(env)-1], want != "")
			}
			if slices.Contains(env, "GOFLAGS=-mod=readonly") != true {
				t.Errorf("HardenedEnvFor lacks the readonly default: %q", env)
			}
		})
	}
}

// vendoredModule writes a module whose dependency exists only in its vendor
// directory: no module cache or go.sum entry can supply it.
func vendoredModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":                        "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"vendor/modules.txt":            "# example.com/dep v1.0.0\n## explicit; go 1.22\nexample.com/dep\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nimport \"os/exec\"\n\nfunc Run() { exec.Command(\"x\").Run() }\n",
		"main.go":                       "package app\n\nimport \"example.com/dep\"\n\nfunc F() { dep.Run() }\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A module with a vendor directory loads its dependencies from it.
func TestFingerprintSource_Vendored(t *testing.T) {
	root := vendoredModule(t)
	path := filepath.Join(root, "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	results, err := diff.FingerprintSource(path, string(src), ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource: %v", err)
	}
	if !slices.ContainsFunc(results, func(r diff.FingerprintResult) bool { return r.FunctionName == "example.com/app.F" }) {
		t.Errorf("F not fingerprinted: %+v", results)
	}
}
