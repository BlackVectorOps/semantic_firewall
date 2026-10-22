package diff

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
)

// customBuildTags keeps only the tags a build must be given with -tags:
// platform, toolchain, release and experiment tags are set by the build
// itself, and ignore is never supplied.
func TestCustomBuildTags(t *testing.T) {
	src := "//go:build (integration || e2e) && unix && cgo && gc && !gccgo && linux && amd64 && go1.22 && goexperiment.rangefunc && !ignore\n\npackage p\n"
	if got, want := customBuildTags(src), []string{"e2e", "integration"}; !slices.Equal(got, want) {
		t.Errorf("customBuildTags = %v; want %v", got, want)
	}
	// Constraints after the package clause are not build constraints.
	if got := customBuildTags("package p\n\n//go:build late\n"); len(got) != 0 {
		t.Errorf("customBuildTags after package = %v; want none", got)
	}
}

// A GOARCH tag outside knownPlatforms is a platform tag, not a custom one:
// given with -tags it would also select the standard library's own files
// for that architecture beside the host's, and the load would fail.
func TestBuildConfigFor_EveryDistArch(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":    "module example.com/p\n\ngo 1.22\n",
		"arch_a.go": "//go:build !mips\n\npackage p\n\nfunc Arch() int { return 1 }\n",
		"arch_m.go": "//go:build linux && mips\n\npackage p\n\nfunc Arch() int { return 2 }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := filepath.Join(root, "arch_m.go")
	if goos, goarch, tags, ok := buildConfigFor(m, files["arch_m.go"]); !ok || goos != "linux" || goarch != "mips" || len(tags) != 0 {
		t.Errorf("buildConfigFor = %s/%s tags %v ok %v; want linux/mips, no tags", goos, goarch, tags, ok)
	}
	res, err := FingerprintSource(m, files["arch_m.go"], ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource: %v", err)
	}
	found := false
	for _, r := range res {
		found = found || (r.Filename == m && strings.HasSuffix(r.FunctionName, ".Arch"))
	}
	if !found {
		t.Errorf("Arch from arch_m.go not fingerprinted: %v", res)
	}
}

// A file behind a custom tag is loaded with the tag set, as part of its
// package: its siblings are in the load and it type-checks against them.
// Loaded alone (the fallback for a file no configuration includes), its
// call into a sibling would be undefined.
func TestLoadPackagesFromSource_CustomTagKeepsPackage(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":    "module example.com/p\n\ngo 1.22\n",
		"helper.go": "package p\n\nfunc helper() int { return 1 }\n",
		"tagged.go": "//go:build integration\n\npackage p\n\nfunc Seed() int { return helper() }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tagged := filepath.Join(root, "tagged.go")
	pkgs, err := loadPackagesFromSource(tagged, files["tagged.go"])
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("loaded %d packages; want 1", len(pkgs))
	}
	p := pkgs[0]
	if len(p.Errors) != 0 {
		t.Errorf("package errors: %v", p.Errors)
	}
	if !slices.Contains(p.CompiledGoFiles, filepath.Join(root, "helper.go")) {
		t.Errorf("files %v; want the sibling helper.go loaded with the tagged file", p.CompiledGoFiles)
	}
}

// VendorDir resolves a directory outside any module to no vendor
// directory, whatever the working directory holds: a module in the
// working directory must not be read in its place.
func TestVendorDir_IgnoresWorkingDirectory(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "go.mod"), []byte("module w\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if got := VendorDir(t.TempDir()); got != "" {
		t.Errorf("VendorDir(dir outside any module) = %q; want none", got)
	}
}
