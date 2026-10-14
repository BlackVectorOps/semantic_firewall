package topology

import (
	"reflect"
	"testing"
)

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"isCSRFTokenValid": {"is", "csrf", "token", "valid"},
		"authorize":        {"authorize"},
		"HTTPServer":       {"http", "server"},
		"has_role2":        {"has", "role"},
		"VerifyPKCS1v15":   {"verify", "pkcs", "v"},
	}
	for in, want := range cases {
		if got := splitWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitWords(%q) = %q; want %q", in, got, want)
		}
	}
	for name, want := range map[string]bool{
		"authorize": true, "IsAdmin": true, "hasPermission": true, "validateToken": true,
		"checkCache": false, "formatRow": false, "Close": false, "authorName": true,
	} {
		if got := isVerificationName(name); got != want {
			t.Errorf("isVerificationName(%q) = %v; want %v", name, got, want)
		}
	}
}
