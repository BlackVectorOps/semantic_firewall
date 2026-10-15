package diff

import "testing"

func TestReplaceTypeParamWords(t *testing.T) {
	positions := map[string]string{"T": "#0", "x": "#1"}
	cases := map[string]string{
		"(*List[T]).Push":        "(*List[#0]).Push",
		"(*Pair[T, x]).Get$1":    "(*Pair[#0, #1]).Get$1",
		"(*List[a.Tx]).Push":     "(*List[a.Tx]).Push",
		"(*List[T.x]).Push":      "(*List[T.x]).Push",
		"(*Tree[Map[T, x]]).Len": "(*Tree[Map[#0, #1]]).Len",
		"T":                      "T",
	}
	for in, want := range cases {
		if got := replaceTypeParamWords(in, positions); got != want {
			t.Errorf("replaceTypeParamWords(%q) = %q; want %q", in, got, want)
		}
	}
}

// Closures pair by content within their enclosing function, and declared
// initializers and their closures within "init#"; other names, including
// go/ssa's synthetic "$bound" and "$thunk" wrappers, pair by name.
func TestContentGroup(t *testing.T) {
	for name, want := range map[string]struct {
		group     string
		byContent bool
	}{
		"F":        {"F", false},
		"F$1":      {"F", true},
		"F$0":      {"F", true},
		"F$9":      {"F", true},
		"F$1$3":    {"F", true},
		"(*T).M$2": {"(*T).M", true},
		"F$":       {"F$", false},
		"F$1$":     {"F$1$", false},
		"F$/":      {"F$/", false},
		"F$:":      {"F$:", false},
		"F$bound":  {"F$bound", false},
		"$1":       {"$1", false},
		"init":     {"init", false},
		"init#1":   {"init#", true},
		"init#12":  {"init#", true},
		"init#2$1": {"init#", true},
		"init#":    {"init#", false},
		"init#x":   {"init#x", false},
		"main#1":   {"main#1", false},
	} {
		if group, byContent := contentGroup(name); group != want.group || byContent != want.byContent {
			t.Errorf("contentGroup(%q) = %q, %v; want %q, %v", name, group, byContent, want.group, want.byContent)
		}
	}
}
