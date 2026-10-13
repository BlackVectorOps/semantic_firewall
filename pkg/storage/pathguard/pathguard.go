// Package pathguard refuses database writes under operating-system
// directories. Creating or writing a signature database in a system root
// could let an attacker who controls the database path overwrite binaries or
// configuration when the process runs with elevated privileges.
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxSymlinkHops bounds manual symlink resolution, matching the Linux
// kernel's MAXSYMLINKS.
const maxSymlinkHops = 40

// unixSystemDirs are the roots a writable database may not live under on
// Unix-like systems. /usr/local, where administrators install shared data,
// is exempt.
var unixSystemDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib32", "/lib64", "/proc", "/sys", "/dev"}

// darwinSystemDirs extends unixSystemDirs: /etc is a symlink to /private/etc
// on macOS, and /System holds the sealed system volume.
var darwinSystemDirs = append(append([]string{}, unixSystemDirs...), "/private/etc", "/System")

// CheckWritable returns an error if path lies under a system directory,
// either as written or after resolving symlinks. Symlinks are resolved in the
// longest prefix of path that exists, so a database that does not exist yet
// cannot be placed under a system directory through a symlinked parent.
func CheckWritable(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", path, err)
	}
	resolved, err := resolve(abs, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", path, err)
	}
	systemRoot := os.Getenv("SystemRoot")
	for _, p := range []string{abs, resolved} {
		if dir := SystemDir(runtime.GOOS, p, systemRoot); dir != "" {
			return fmt.Errorf("security violation: refusing to write a database under system directory %s (%q)", dir, p)
		}
	}
	return nil
}

// resolve evaluates the symlinks of an absolute path whose trailing
// components may not exist yet.
func resolve(path string, hops int) (string, error) {
	if hops > maxSymlinkHops {
		return "", errors.New("too many levels of symbolic links")
	}
	existing := filepath.Clean(path)
	var rest []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		rest = append([]string{filepath.Base(existing)}, rest...)
		existing = parent
	}

	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		// Lstat succeeded, so every directory above existing resolves and
		// only existing itself can be a dangling symlink: follow it by hand.
		target, lerr := os.Readlink(existing)
		if lerr != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(existing), target)
		}
		return resolve(filepath.Join(append([]string{target}, rest...)...), hops+1)
	}
	return filepath.Join(append([]string{resolved}, rest...)...), nil
}

// SystemDir returns the system directory of the given GOOS that contains
// path, or "" if there is none. systemRoot is the Windows %SystemRoot%
// directory and is ignored elsewhere. Matching is by whole path component, so
// /etc does not cover /etcd-data.
func SystemDir(goos, path, systemRoot string) string {
	if goos == "windows" {
		return windowsSystemDir(path, systemRoot)
	}
	path = filepath.ToSlash(filepath.Clean(path))
	if path == "/usr/local" || strings.HasPrefix(path, "/usr/local/") {
		return ""
	}
	dirs := unixSystemDirs
	if goos == "darwin" {
		dirs = darwinSystemDirs
	}
	for _, dir := range dirs {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return dir
		}
	}
	return ""
}

// windowsSystemDir matches path against %SystemRoot% (C:\Windows by default),
// case-insensitively and with either separator.
func windowsSystemDir(path, systemRoot string) string {
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	norm := func(s string) string {
		return strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(s, `\`, "/")), "/")
	}
	p, root := norm(path), norm(systemRoot)
	if p == root || strings.HasPrefix(p, root+"/") {
		return systemRoot
	}
	return ""
}
