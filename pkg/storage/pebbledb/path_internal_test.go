package pebbledb

import (
	"runtime"
	"strings"
	"testing"
)

func TestSensitiveSystemDir(t *testing.T) {
	cases := map[string]string{
		"/etc/sfw/db":                "/etc",
		"/etc":                       "/etc",
		"/usr/share/sfw":             "/usr",
		"/etcd-data/signatures.db":   "",
		"/usrdata/db":                "",
		"/usr/local/share/sfw/db":    "",
		"/root/.sfw/signatures.db":   "",
		"/home/runner/signatures.db": "",
		"/tmp/x/../../etc/passwd.db": "/etc",
	}
	for path, want := range cases {
		if got := sensitiveSystemDir(path); got != want {
			t.Errorf("sensitiveSystemDir(%q) = %q; want %q", path, got, want)
		}
	}
}

// Writable opens under a system directory are refused before anything is
// created; read-only opens are not subject to the check.
func TestNewPebbleScanner_SystemDirOnlyBlocksWrites(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("system-directory check is Linux-only")
	}
	opts := DefaultPebbleScannerOptions()
	if _, err := NewPebbleScanner("/etc/sfw-test-signatures.db", opts); err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Errorf("writable open under /etc: err = %v; want a security violation", err)
	}

	opts.ReadOnly = true
	_, err := NewPebbleScanner("/etc/sfw-test-signatures.db", opts)
	if err != nil && strings.Contains(err.Error(), "security violation") {
		t.Errorf("read-only open under /etc was refused by the write check: %v", err)
	}
}
