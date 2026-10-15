package diff

import (
	"testing"

	"golang.org/x/tools/go/ssa"
)

// GenerateFingerprint accepts any function; one outside a program has no
// position.
func TestFunctionPosition_WithoutProgram(t *testing.T) {
	if file, line := functionPosition(&ssa.Function{}); file != "" || line != 0 {
		t.Errorf("got %q:%d, want no position", file, line)
	}
}
