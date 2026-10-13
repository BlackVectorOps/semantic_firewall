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
