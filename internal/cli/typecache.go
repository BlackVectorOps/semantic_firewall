package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
)

// ConfigureTypeCache decides, once at startup, whether this run uses the
// persistent type cache (see diff.TypeCacheEnvVar), and records the
// decision in the environment, where the analysis and any worker it starts
// read it. SFW_TYPE_CACHE=on or off decides, and "rw:DIR" or "ro:DIR"
// names a cache directly. Unset, the cache is on only for a person at a
// terminal: stderr is a terminal and CI is unset. An automated run, where
// a pull request's code may have run earlier under the same account,
// starts clean. The cache lives under sfw/types in the user cache
// directory; a sandboxed worker only reads it (see internal/sandbox).
func ConfigureTypeCache() {
	os.Setenv(diff.TypeCacheEnvVar, typeCacheSetting(os.Getenv, isTerminal(os.Stderr), os.UserCacheDir))
}

// typeCacheSetting returns the diff.TypeCacheEnvVar value for a run with
// the given environment, whether stderr is a terminal, and the user cache
// directory.
func typeCacheSetting(getenv func(string) string, interactive bool, userCacheDir func() (string, error)) string {
	switch v := getenv(diff.TypeCacheEnvVar); {
	case strings.HasPrefix(v, "rw:"), strings.HasPrefix(v, "ro:"):
		return v
	case v == "on", v == "" && interactive && getenv("CI") == "":
	default:
		return "off"
	}
	dir, err := userCacheDir()
	if err != nil {
		return "off"
	}
	return "rw:" + filepath.Join(dir, "sfw", "types")
}

// isTerminal reports whether f is a terminal: a character device other
// than the null device.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(info, null)
}
