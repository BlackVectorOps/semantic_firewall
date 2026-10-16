package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A diff whose two sides have no functions (an empty or whitespace-only
// file, /dev/null) prints "functions": [], as a failed batch pair does:
// jq's '.functions[]' fails on null ("Cannot iterate over null").
//
// "functions" is always a JSON array; [] when empty.
func TestDiff_EmptyDiffPrintsFunctionsArray(t *testing.T) {
	dir := t.TempDir()
	blank := filepath.Join(dir, "blank.go")
	if err := os.WriteFile(blank, []byte(" \n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var single bytes.Buffer
	if err := RunDiffLogic(RealFileSystem{}, &single, blank, os.DevNull); err != nil {
		t.Fatalf("RunDiffLogic: %v", err)
	}
	var one map[string]json.RawMessage
	if err := json.Unmarshal(single.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if got := string(one["functions"]); got != "[]" {
		t.Errorf("sfw diff: \"functions\": %s; want []", got)
	}

	var batch bytes.Buffer
	if err := RunDiffBatchLogic(RealFileSystem{}, &batch, writePairs(t, blank+"\x00"+os.DevNull+"\x00")); err != nil {
		t.Fatalf("RunDiffBatchLogic: %v", err)
	}
	var many []map[string]json.RawMessage
	if err := json.Unmarshal(batch.Bytes(), &many); err != nil {
		t.Fatal(err)
	}
	if got := string(many[0]["functions"]); got != "[]" {
		t.Errorf("sfw diff --batch: \"functions\": %s; want []", got)
	}
}
