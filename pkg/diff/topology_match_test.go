package diff

import (
	"testing"
)

func TestShortFuncName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "github.com/pkg/repo/pkg.Function",
			expected: "Function",
		},
		{
			input:    "github.com/pkg/repo/pkg.Function[int]",
			expected: "Function[int]",
		},
		{
			input:    "github.com/pkg/repo/pkg.Function[github.com/other/pkg.Type]",
			expected: "Function[Type]",
		},
		{
			input:    "github.com/pkg/repo/pkg.(*github.com/other/pkg.Type).Method",
			expected: "(*Type).Method",
		},
		{
			input:    "github.com/pkg/repo/pkg.Function[func(int) int]",
			expected: "Function[func(int) int]",
		},
		{
			input:    "github.com/pkg/repo/pkg.Type[int].Method",
			expected: "Type[int].Method",
		},
		{
			input:    "github.com/pkg/repo/pkg.Function[github.com/pkg/repo/pkg.List[int]]",
			expected: "Function[List[int]]",
		},
		{
			input:    "github.com/pkg/repo/pkg.Function[github.com/pkg/repo/pkg.List[github.com/other/pkg.Val]]",
			expected: "Function[List[Val]]",
		},
		// Variadic
		{
			input:    "github.com/pkg/repo/pkg.Func[...int]",
			expected: "Func[...int]",
		},
		// Map
		{
			input:    "github.com/pkg/repo/pkg.Func[map[github.com/pkg.Key]github.com/pkg.Val]",
			expected: "Func[map[Key]Val]",
		},
		// Anonymous struct
		{
			input:    "github.com/pkg/repo/pkg.Func[struct{F github.com/pkg.Type}]",
			expected: "Func[struct{F Type}]",
		},
		// Pointer in generics
		{
			input:    "github.com/pkg/repo/pkg.Func[*github.com/pkg.Type]",
			expected: "Func[*Type]",
		},
		// Dot method
		{
			input:    "(*github.com/pkg.Type).Method",
			expected: "(*Type).Method",
		},
		// No path
		{
			input:    "int",
			expected: "int",
		},
		{
			input:    "pkg.Type",
			expected: "Type",
		},
		{
			input:    "Type",
			expected: "Type",
		},
		{
			input:    "vendor/github.com/pkg/name",
			expected: "name",
		},
	}

	for _, tt := range tests {
		got := ShortFuncName(tt.input)
		if got != tt.expected {
			t.Errorf("ShortFuncName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
