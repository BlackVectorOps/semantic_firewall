package pebbledb

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// Writable opens under a system directory are refused before anything is
// created; read-only opens are not subject to the check. The directory list
// itself is tested in pkg/storage/pathguard.
func TestNewPebbleScanner_SystemDirOnlyBlocksWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /etc")
	}
	if _, err := os.Stat("/etc"); err != nil {
		t.Skip("/etc not present")
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
