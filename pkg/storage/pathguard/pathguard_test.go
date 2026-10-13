package pathguard

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSystemDir(t *testing.T) {
	cases := []struct {
		goos, path, want string
	}{
		{"linux", "/etc/sfw/db", "/etc"},
		{"linux", "/etc", "/etc"},
		{"linux", "/usr/share/sfw", "/usr"},
		{"linux", "/etcd-data/signatures.db", ""},
		{"linux", "/usrdata/db", ""},
		{"linux", "/usr/local/share/sfw/db", ""},
		{"linux", "/root/.sfw/signatures.db", ""},
		{"linux", "/home/runner/signatures.db", ""},
		{"linux", "/tmp/x/../../etc/passwd.db", "/etc"},
		{"freebsd", "/boot/sigs.db", "/boot"},
		{"darwin", "/private/etc/sigs.db", "/private/etc"},
		{"darwin", "/System/Library/sigs.db", "/System"},
		{"darwin", "/private/var/folders/x/sigs.db", ""},
		{"linux", "/private/etc/sigs.db", ""},
		{"windows", `C:\Windows\System32\sigs.db`, `C:\Windows`},
		{"windows", `c:/windows/sigs.db`, `C:\Windows`},
		{"windows", `C:\WindowsApps\sigs.db`, ""},
		{"windows", `D:\data\sigs.db`, ""},
	}
	for _, c := range cases {
		if got := SystemDir(c.goos, c.path, ""); got != c.want {
			t.Errorf("SystemDir(%q, %q) = %q; want %q", c.goos, c.path, got, c.want)
		}
	}
	if got := SystemDir("windows", `E:\WinNT\x.db`, `E:\WinNT`); got != `E:\WinNT` {
		t.Errorf("custom SystemRoot not honored: got %q", got)
	}
}

func requireUnixEtc(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses /etc")
	}
	if _, err := os.Stat("/etc"); err != nil {
		t.Skip("/etc not present")
	}
}

func TestCheckWritable_AllowsOrdinaryPaths(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{filepath.Join(dir, "signatures.db"), filepath.Join(dir, "new", "sub", "sigs.json")} {
		if err := CheckWritable(p); err != nil {
			t.Errorf("CheckWritable(%q) = %v; want nil", p, err)
		}
	}
}

func TestCheckWritable_RefusesSystemDir(t *testing.T) {
	requireUnixEtc(t)
	if err := CheckWritable("/etc/sfw-test.db"); err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Errorf("CheckWritable(/etc/sfw-test.db) = %v; want a security violation", err)
	}
}

// A database that does not exist yet must not reach a system directory
// through a symlinked parent directory.
func TestCheckWritable_SymlinkedParent(t *testing.T) {
	requireUnixEtc(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	for _, p := range []string{filepath.Join(link, "new.db"), filepath.Join(link, "a", "b", "new.db")} {
		if err := CheckWritable(p); err == nil || !strings.Contains(err.Error(), "security violation") {
			t.Errorf("CheckWritable(%q) = %v; want a security violation", p, err)
		}
	}
}

// A dangling symlink whose target lies in a system directory is refused.
func TestCheckWritable_DanglingSymlink(t *testing.T) {
	requireUnixEtc(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "db")
	if err := os.Symlink("/etc/sfw-does-not-exist/signatures.db", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := CheckWritable(link); err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Errorf("CheckWritable(%q) = %v; want a security violation", link, err)
	}
}

func TestCheckWritable_SymlinkLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := CheckWritable(filepath.Join(a, "db")); err == nil {
		t.Error("CheckWritable through a symlink loop = nil; want an error")
	}
}
