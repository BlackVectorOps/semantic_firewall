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
		// Feature tags hold at the architecture's default level only, not
		// at the host's.
		{"feature.go", "//go:build amd64 && arm64.v8.0\n\n" + body, nil, []string{"linux/amd64"}},
		{"level.go", "//go:build amd64 && amd64.v1\n\n" + body, []string{"linux/amd64", "windows/amd64"}, []string{"linux/arm64"}},
		{"bsd.go", "//go:build openbsd && arm64\n\n" + body, []string{"openbsd/arm64"}, []string{"linux/arm64"}},
		{"future.go", "//go:build go1.99\n\n" + body, nil, []string{"linux/amd64"}},
		{"legacy.go", "// +build linux\n\n" + body, []string{"linux/amd64"}, []string{"darwin/arm64"}},
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
