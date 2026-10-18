package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/internal/sandbox"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
)

// SFW_TYPE_CACHE=on or off decides; a direct setting passes through;
// unset, only a terminal outside CI gets the cache; without a user cache
// directory there is none.
func TestTypeCacheSetting(t *testing.T) {
	cacheDir := func() (string, error) { return "/home/u/.cache", nil }
	noCacheDir := func() (string, error) { return "", errors.New("no home") }
	want := "rw:" + filepath.Join("/home/u/.cache", "sfw", "types")
	for _, tc := range []struct {
		name        string
		env         map[string]string
		interactive bool
		dir         func() (string, error)
		want        string
	}{
		{"terminal", nil, true, cacheDir, want},
		{"terminal in CI", map[string]string{"CI": "true"}, true, cacheDir, "off"},
		{"no terminal", nil, false, cacheDir, "off"},
		{"on without a terminal", map[string]string{diff.TypeCacheEnvVar: "on", "CI": "1"}, false, cacheDir, want},
		{"off at a terminal", map[string]string{diff.TypeCacheEnvVar: "off"}, true, cacheDir, "off"},
		{"unknown value", map[string]string{diff.TypeCacheEnvVar: "yes"}, true, cacheDir, "off"},
		{"read-only directory", map[string]string{diff.TypeCacheEnvVar: "ro:/srv/types", "CI": "1"}, false, cacheDir, "ro:/srv/types"},
		{"writable directory", map[string]string{diff.TypeCacheEnvVar: "rw:/srv/types"}, false, noCacheDir, "rw:/srv/types"},
		{"no user cache directory", nil, true, noCacheDir, "off"},
		{"on, no user cache directory", map[string]string{diff.TypeCacheEnvVar: "on"}, true, noCacheDir, "off"},
	} {
		getenv := func(k string) string { return tc.env[k] }
		if got := typeCacheSetting(getenv, tc.interactive, tc.dir); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if sandbox.EnvTypeCache != diff.TypeCacheEnvVar {
		t.Errorf("the sandbox passes %s, the loader reads %s", sandbox.EnvTypeCache, diff.TypeCacheEnvVar)
	}
}

// ConfigureTypeCache records its decision in the environment.
func TestConfigureTypeCache(t *testing.T) {
	t.Setenv(diff.TypeCacheEnvVar, "ro:/srv/types")
	ConfigureTypeCache()
	if got := os.Getenv(diff.TypeCacheEnvVar); got != "ro:/srv/types" {
		t.Errorf("got %q", got)
	}
	t.Setenv(diff.TypeCacheEnvVar, "off")
	ConfigureTypeCache()
	if got := os.Getenv(diff.TypeCacheEnvVar); got != "off" {
		t.Errorf("got %q", got)
	}
}

// Neither a regular file nor the null device is a terminal.
func TestIsTerminal(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for _, g := range []*os.File{f, null} {
		if isTerminal(g) {
			t.Errorf("%s is a terminal", g.Name())
		}
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		t.Skip("no terminal to test with")
	}
	defer tty.Close()
	if !isTerminal(tty) {
		t.Errorf("/dev/tty is not a terminal")
	}
}
