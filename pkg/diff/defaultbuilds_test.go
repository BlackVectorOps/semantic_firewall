package diff

import (
	"slices"
	"testing"
)

func TestDefaultBuilds(t *testing.T) {
	const body = "package p\n\nfunc F() {}\n"
	cases := []struct {
		name, src string
		in, out   []string
	}{
		{"plain.go", body, []string{"linux/amd64", "linux/amd64/cgo", "windows/arm64", "plan9/amd64"}, nil},
		{"f_windows.go", body, []string{"windows/amd64", "windows/arm64/cgo"}, []string{"linux/amd64", "darwin/arm64"}},
		{"f_arm64.go", body, []string{"linux/arm64", "darwin/arm64"}, []string{"linux/amd64"}},
		{"tagged.go", "//go:build linux && !cgo\n\n" + body, []string{"linux/amd64"}, []string{"linux/amd64/cgo", "darwin/arm64"}},
		{"custom.go", "//go:build mytag\n\n" + body, nil, []string{"linux/amd64", "linux/amd64/cgo"}},
		{"ignored.go", "//go:build ignore\n\n" + body, nil, []string{"linux/amd64", "linux/amd64/cgo"}},
		{"cgo.go", "package p\n\nimport \"C\"\n\nfunc F() {}\n", []string{"linux/amd64/cgo"}, []string{"linux/amd64"}},
		{"_hidden.go", body, nil, []string{"linux/amd64"}},
		{".hidden.go", body, nil, []string{"linux/amd64"}},
		{"f_test.go", body, nil, []string{"linux/amd64"}},
	}
	for _, c := range cases {
		got := DefaultBuilds("/m/p/"+c.name, c.src)
		for _, b := range c.in {
			if !slices.Contains(got, b) {
				t.Errorf("%s: builds %v; want %s among them", c.name, got, b)
			}
		}
		for _, b := range c.out {
			if slices.Contains(got, b) {
				t.Errorf("%s: builds %v; want no %s", c.name, got, b)
			}
		}
		if c.in == nil && len(got) != 0 {
			t.Errorf("%s: builds %v; want none", c.name, got)
		}
	}
}
