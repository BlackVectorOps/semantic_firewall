package api_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// deletionCase is one old/new pair for a single function and the label its
// diff must (or must not) carry.
type deletionCase struct {
	name, fn, oldSrc, newSrc, label string
	high                            bool
}

func runDeletionCases(t *testing.T, cases []deletionCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := findFunc(t, diffSources(t, c.oldSrc, c.newSrc), c.fn)
			has := strings.Contains(f.TopologyDelta, c.label)
			if c.high && (!has || f.RiskScore < models.RiskScoreHigh) {
				t.Errorf("%s: risk %d, delta %q; want %s with risk >= %d", c.fn, f.RiskScore, f.TopologyDelta, c.label, models.RiskScoreHigh)
			}
			if !c.high && (has || f.RiskScore >= models.RiskScoreHigh) {
				t.Errorf("%s: risk %d, delta %q; want no %s and risk < %d", c.fn, f.RiskScore, f.TopologyDelta, c.label, models.RiskScoreHigh)
			}
		})
	}
}

const guardedPurge = `package p
import ("errors";"os")
func Purge(dir string, isAdmin bool) error {
	if !isAdmin { return errors.New("forbidden") }
	return os.RemoveAll(dir)
}
`

// A capability call whose every old reference ran under a condition gains a
// reference that runs unconditionally.
func TestDiffRisk_Unguarded(t *testing.T) {
	runDeletionCases(t, []deletionCase{
		{name: "guard deleted", fn: "Purge", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: guardedPurge,
			newSrc: `package p
import ("errors";"os")
var _ = errors.New
func Purge(dir string, isAdmin bool) error { return os.RemoveAll(dir) }
`},
		{name: "call hoisted out of its guard", fn: "Cleanup", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: `package p
import "os"
func Cleanup(path string, confirmed bool) error {
	if confirmed { return os.RemoveAll(path) }
	return nil
}
`,
			newSrc: `package p
import "os"
func Cleanup(path string, confirmed bool) error {
	err := os.RemoveAll(path)
	if confirmed { return err }
	return nil
}
`},
		{name: "log.Fatal guard deleted", fn: "Purge", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: `package p
import ("log";"os")
func Purge(dir string, ok bool) error {
	if !ok { log.Fatal("no") }
	return os.RemoveAll(dir)
}
`,
			newSrc: `package p
import ("log";"os")
var _ = log.Fatal
func Purge(dir string, ok bool) error { return os.RemoveAll(dir) }
`},
		{name: "unguarded call added beside a guarded one", fn: "Purge", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: guardedPurge,
			newSrc: `package p
import ("errors";"os")
func Purge(dir string, isAdmin bool) error {
	os.RemoveAll(dir + ".tmp")
	if !isAdmin { return errors.New("forbidden") }
	return os.RemoveAll(dir)
}
`},
		{name: "guard kept", fn: "Purge", label: "Unguarded",
			oldSrc: guardedPurge,
			newSrc: `package p
import ("errors";"fmt";"os")
func Purge(dir string, isAdmin bool) error {
	if !isAdmin { return errors.New("forbidden") }
	fmt.Println("purging", dir)
	return os.RemoveAll(dir)
}
`},
		{name: "loop condition is not a guard", fn: "Clean", label: "Unguarded",
			oldSrc: `package p
import "os"
func Clean(fs []string) { for _, f := range fs { os.Remove(f) } }
`,
			newSrc: `package p
import "os"
func Clean(fs []string) { os.Remove(fs[0]) }
`},
		{name: "switch cases removed before the guarded case", fn: "Do", label: "Unguarded",
			oldSrc: `package p
import "os"
func Do(cmd, p string) error {
	switch cmd {
	case "a": return nil
	case "b": return nil
	case "rm": return os.RemoveAll(p)
	}
	return nil
}
`,
			newSrc: `package p
import "os"
func Do(cmd, p string) error {
	switch cmd {
	case "rm": return os.RemoveAll(p)
	}
	return nil
}
`},
		{name: "guard bypassed by a constant flag", fn: "Purge", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: guardedPurge,
			newSrc: `package p
import ("errors";"os")
const skipAuth = true
func Purge(dir string, isAdmin bool) error {
	if !skipAuth && !isAdmin { return errors.New("forbidden") }
	return os.RemoveAll(dir)
}
`},
		{name: "call copied into both sides of its guard", fn: "Purge", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: guardedPurge,
			newSrc: `package p
import "os"
func Purge(dir string, isAdmin bool) error {
	if !isAdmin { return os.RemoveAll(dir) }
	return os.RemoveAll(dir)
}
`},
		{name: "guard deleted from a worker loop", fn: "Worker", label: "Unguarded(os.RemoveAll)", high: true,
			oldSrc: `package p
import "os"
type Job struct{ Path string; Admin, Last bool }
func Worker(jobs <-chan Job) { for { j := <-jobs; if j.Admin { os.RemoveAll(j.Path) }; if j.Last { return } } }
`,
			newSrc: `package p
import "os"
type Job struct{ Path string; Admin, Last bool }
func Worker(jobs <-chan Job) { for { j := <-jobs; os.RemoveAll(j.Path); if j.Last { return } } }
`},
		{name: "a worker's early return made a continue", fn: "Worker", label: "Unguarded",
			oldSrc: `package p
import "os"
func Worker(jobs <-chan string) { for { p := <-jobs; if p == "" { return }; os.Remove(p) } }
`,
			newSrc: `package p
import "os"
func Worker(jobs <-chan string) { for { p := <-jobs; if p == "" { continue }; os.Remove(p) } }
`},
		{name: "os.Exit moved into a helper", fn: "Purge", label: "Unguarded",
			oldSrc: `package p
import "os"
func Purge(dir string, ok bool) { if !ok { println("forbidden"); os.Exit(1) }; os.RemoveAll(dir) }
`,
			newSrc: `package p
import "os"
func die(msg string) { println(msg); os.Exit(1) }
func Purge(dir string, ok bool) { if !ok { die("forbidden") }; os.RemoveAll(dir) }
`},
		{name: "WriteHeader of a nil constant", fn: "F", label: "Unguarded",
			oldSrc: `package p
type Header map[string]string
type W interface{ WriteHeader(h Header) }
func F(w W, ok bool) { if !ok { return }; w.WriteHeader(Header{"a": "b"}) }
`,
			newSrc: `package p
type Header map[string]string
type W interface{ WriteHeader(h Header) }
func F(w W, ok bool) { if !ok { w.WriteHeader(nil); return }; w.WriteHeader(Header{"a": "b"}) }
`},
	})
}

// Calls to the code's own verification helpers are checks too.
func TestDiffRisk_RemovedCheckHelper(t *testing.T) {
	runDeletionCases(t, []deletionCase{
		{name: "authorize helper call removed", fn: "(*S).Admin", label: "RemovedCheck((command-line-arguments.S).authorize)", high: true,
			oldSrc: `package p
import ("net/http";"strings")
type S struct{ token string }
func (s *S) authorize(r *http.Request) bool { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == s.token }
func (s *S) Admin(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) { http.Error(w, "no", 403); return }
	w.Write([]byte("secrets"))
}
`,
			newSrc: `package p
import ("net/http";"strings")
type S struct{ token string }
func (s *S) authorize(r *http.Request) bool { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == s.token }
func (s *S) Admin(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secrets")) }
`},
		{name: "interface verifier call removed", fn: "Accept", label: "RemovedCheck((command-line-arguments.Verifier).Verify)", high: true,
			oldSrc: `package p
type Verifier interface{ Verify(msg, sig []byte) error }
func Accept(v Verifier, msg, sig []byte) ([]byte, error) {
	if err := v.Verify(msg, sig); err != nil { return nil, err }
	return msg, nil
}
`,
			newSrc: `package p
type Verifier interface{ Verify(msg, sig []byte) error }
func Accept(v Verifier, msg, sig []byte) ([]byte, error) { return msg, nil }
`},
		{name: "helper that reaches hmac.Equal removed", fn: "Handle", label: "RemovedCheck(command-line-arguments.tokenOK,crypto/hmac.Equal)", high: true,
			oldSrc: `package p
import ("crypto/hmac";"crypto/sha256")
func tokenOK(key, msg, mac []byte) bool { m := hmac.New(sha256.New, key); m.Write(msg); return hmac.Equal(m.Sum(nil), mac) }
func Handle(key, msg, mac []byte) string {
	if !tokenOK(key, msg, mac) { return "denied" }
	return string(msg)
}
`,
			newSrc: `package p
import ("crypto/hmac";"crypto/sha256")
func tokenOK(key, msg, mac []byte) bool { m := hmac.New(sha256.New, key); m.Write(msg); return hmac.Equal(m.Sum(nil), mac) }
func Handle(key, msg, mac []byte) string { return string(msg) }
`},
		{name: "unrelated helpers removed", fn: "Get", label: "RemovedCheck",
			oldSrc: `package p
import "fmt"
func checkCache(k string) bool { return len(k) > 3 }
func formatRole(r string) string { return "<" + r + ">" }
func Get(k string) string {
	if checkCache(k) { return "hit" }
	fmt.Println(formatRole(k))
	return k
}
`,
			newSrc: `package p
func checkCache(k string) bool { return len(k) > 3 }
func formatRole(r string) string { return "<" + r + ">" }
func Get(k string) string { return k }
`},
		{name: "a primitive's result logged instead of checked", fn: "Handle", label: "RemovedCheck(crypto/hmac.Equal)", high: true,
			oldSrc: checkedMAC,
			newSrc: `package p
import ("crypto/hmac";"log")
func Handle(mac, want []byte) error { ok := hmac.Equal(mac, want); log.Printf("mac ok: %v", ok); return nil }
`},
		{name: "a primitive's result dropped", fn: "Handle", label: "RemovedCheck(crypto/hmac.Equal)", high: true,
			oldSrc: checkedMAC,
			newSrc: `package p
import "crypto/hmac"
func Handle(mac, want []byte) error { hmac.Equal(mac, want); return nil }
`},
		{name: "a check moved into a helper that ignores it", fn: "Handle", label: "RemovedCheck(crypto/hmac.Equal)", high: true,
			oldSrc: checkedMAC,
			newSrc: `package p
import ("crypto/hmac";"errors")
func macOK(mac, want []byte) bool { hmac.Equal(mac, want); return true }
func Handle(mac, want []byte) error { if !macOK(mac, want) { return errors.New("bad mac") }; return nil }
`},
		{name: "a check moved into a helper", fn: "Handle", label: "RemovedCheck",
			oldSrc: `package p
import ("crypto/hmac";"errors")
func Handle(mac, want []byte) error { if !hmac.Equal(mac, want) { return errors.New("bad mac") }; return nil }
`,
			newSrc: `package p
import ("crypto/hmac";"errors")
func macOK(mac, want []byte) bool { return hmac.Equal(mac, want) }
func Handle(mac, want []byte) error { if !macOK(mac, want) { return errors.New("bad mac") }; return nil }
`},
		{name: "a helper's result no longer decides", fn: "Handle", label: "RemovedCheck(command-line-arguments.tokenOK,crypto/hmac.Equal)", high: true,
			oldSrc: `package p
import "crypto/hmac"
func tokenOK(mac, want []byte) bool { return hmac.Equal(mac, want) }
func Handle(mac, want []byte, msg string) string { if !tokenOK(mac, want) { return "denied" }; return msg }
`,
			newSrc: `package p
import ("crypto/hmac";"log")
func tokenOK(mac, want []byte) bool { return hmac.Equal(mac, want) }
func Handle(mac, want []byte, msg string) string { ok := tokenOK(mac, want); log.Printf("token ok: %v", ok); return msg }
`},
		{name: "a check returned under a defer removed", fn: "(*S).Check", label: "RemovedCheck((command-line-arguments.S).verifyToken)", high: true,
			oldSrc: `package p
import "sync"
type S struct{ mu sync.Mutex; token string }
func (s *S) verifyToken(t string) error { return nil }
func (s *S) Check(t string) error { s.mu.Lock(); defer s.mu.Unlock(); return s.verifyToken(t) }
`,
			newSrc: `package p
import "sync"
type S struct{ mu sync.Mutex; token string }
func (s *S) verifyToken(t string) error { return nil }
func (s *S) Check(t string) error { s.mu.Lock(); defer s.mu.Unlock(); return nil }
`},
		{name: "a getter call replaced by its field", fn: "Label", label: "RemovedCheck",
			oldSrc: `package p
type Commit struct{ author string }
func (c *Commit) Author() string { return c.author }
func Label(c *Commit) string { return c.Author() }
`,
			newSrc: `package p
type Commit struct{ author string }
func (c *Commit) Author() string { return c.author }
func Label(c *Commit) string { return c.author }
`},
		{name: "os.IsPermission replaced by errors.Is", fn: "Open", label: "RemovedCheck",
			oldSrc: `package p
import "os"
func Open(p string) (*os.File, error) { f, err := os.Open(p); if os.IsPermission(err) { return nil, nil }; return f, err }
`,
			newSrc: `package p
import ("errors";"io/fs";"os")
func Open(p string) (*os.File, error) { f, err := os.Open(p); if errors.Is(err, fs.ErrPermission) { return nil, nil }; return f, err }
`},
	})
}

const checkedMAC = `package p
import ("crypto/hmac";"errors")
func Handle(mac, want []byte) error { if !hmac.Equal(mac, want) { return errors.New("bad mac") }; return nil }
`

// Security settings that weaken on their own appear, or settings whose
// removal weakens disappear.
func TestDiffRisk_WeakenedSecurity(t *testing.T) {
	runDeletionCases(t, []deletionCase{
		{name: "InsecureSkipVerify set", fn: "Cfg", label: "WeakenedSecurity(crypto/tls.Config.InsecureSkipVerify=true)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }\n"},
		{name: "MinVersion lowered", fn: "Cfg", label: "WeakenedSecurity(crypto/tls.Config.MinVersion=TLS1.0)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { c := &tls.Config{}; c.MinVersion = tls.VersionTLS12; return c }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { c := &tls.Config{}; c.MinVersion = tls.VersionTLS10; return c }\n"},
		{name: "client certificate verification dropped", fn: "Cfg", label: "WeakenedSecurity(-crypto/tls.Config.ClientAuth=RequireAndVerifyClientCert)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{ClientAuth: tls.RequestClientCert} }\n"},
		{name: "cookie loses Secure, gains SameSite=None", fn: "Set", label: "WeakenedSecurity(-net/http.Cookie.Secure=true,net/http.Cookie.SameSite=SameSiteNoneMode)", high: true,
			oldSrc: "package p\nimport \"net/http\"\nfunc Set(w http.ResponseWriter, v string) { http.SetCookie(w, &http.Cookie{Name: \"s\", Value: v, Secure: true, HttpOnly: true}) }\n",
			newSrc: "package p\nimport \"net/http\"\nfunc Set(w http.ResponseWriter, v string) { http.SetCookie(w, &http.Cookie{Name: \"s\", Value: v, HttpOnly: true, SameSite: http.SameSiteNoneMode}) }\n"},
		{name: "TLS minimum raised", fn: "Cfg", label: "WeakenedSecurity",
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg(n string) *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg(n string) *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: n} }\n"},
		{name: "a legacy TLS minimum raised", fn: "Cfg", label: "WeakenedSecurity",
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS10} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS11} }\n"},
		{name: "a legacy TLS maximum lowered", fn: "Cfg", label: "WeakenedSecurity(crypto/tls.Config.MaxVersion=TLS1.0)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MaxVersion: tls.VersionTLS11} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MaxVersion: tls.VersionTLS10} }\n"},
		{name: "settings hidden behind a defined type", fn: "Cfg", label: "WeakenedSecurity(crypto/tls.Config.InsecureSkipVerify=true)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\ntype cfg tls.Config\nfunc Cfg() *tls.Config { return (*tls.Config)(&cfg{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) }\n"},
		{name: "Secure and HttpOnly set, then cleared", fn: "Set", label: "WeakenedSecurity(-net/http.Cookie.HttpOnly=true,-net/http.Cookie.Secure=true)", high: true,
			oldSrc: secureCookie,
			newSrc: "package p\nimport \"net/http\"\nfunc Set(w http.ResponseWriter, v string) { c := &http.Cookie{Name: \"s\", Value: v, Secure: true, HttpOnly: true}; c.Secure, c.HttpOnly = false, false; http.SetCookie(w, c) }\n"},
		{name: "a decoy secure cookie", fn: "Set", label: "WeakenedSecurity(-net/http.Cookie.HttpOnly=true,-net/http.Cookie.Secure=true)", high: true,
			oldSrc: secureCookie,
			newSrc: "package p\nimport \"net/http\"\nfunc Set(w http.ResponseWriter, v string) {\n\thttp.SetCookie(w, &http.Cookie{Name: \"pref\", Value: \"1\", Secure: true, HttpOnly: true})\n\thttp.SetCookie(w, &http.Cookie{Name: \"s\", Value: v})\n}\n"},
		{name: "ClientAuth set, then lowered", fn: "Cfg", label: "WeakenedSecurity(-crypto/tls.Config.ClientAuth=RequireAndVerifyClientCert)", high: true,
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { c := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}; c.ClientAuth = tls.NoClientCert; return c }\n"},
		{name: "cookie construction moved into a helper", fn: "Set", label: "WeakenedSecurity",
			oldSrc: secureCookie,
			newSrc: "package p\nimport \"net/http\"\nfunc session(v string) *http.Cookie { return &http.Cookie{Name: \"s\", Value: v, Secure: true, HttpOnly: true} }\nfunc Set(w http.ResponseWriter, v string) { http.SetCookie(w, session(v)) }\n"},
		{name: "cookie hardening moved into a helper", fn: "Set", label: "WeakenedSecurity",
			oldSrc: secureCookie,
			newSrc: "package p\nimport \"net/http\"\nfunc harden(c *http.Cookie) { c.Secure, c.HttpOnly = true, true }\nfunc Set(w http.ResponseWriter, v string) { c := &http.Cookie{Name: \"s\", Value: v}; harden(c); http.SetCookie(w, c) }\n"},
		{name: "TLS config construction moved into a helper", fn: "Cfg", label: "WeakenedSecurity",
			oldSrc: "package p\nimport \"crypto/tls\"\nfunc Cfg() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} }\n",
			newSrc: "package p\nimport \"crypto/tls\"\nfunc server() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} }\nfunc Cfg() *tls.Config { return server() }\n"},
	})
}

const secureCookie = "package p\nimport \"net/http\"\nfunc Set(w http.ResponseWriter, v string) { http.SetCookie(w, &http.Cookie{Name: \"s\", Value: v, Secure: true, HttpOnly: true}) }\n"

// Capabilities reached without naming the dangerous call, and calls that
// name a dangerous package but do nothing dangerous.
func TestDiffRisk_HiddenCapabilities(t *testing.T) {
	runDeletionCases(t, []deletionCase{
		{name: "exec.Cmd run through an interface", fn: "Run", label: "Capability+exec((os/exec.Cmd).Run)", high: true,
			oldSrc: "package p\nfunc Run(x string) error { return nil }\n",
			newSrc: "package p\nimport \"os/exec\"\ntype runner interface{ Run() error }\nfunc Run(x string) error { var r runner = &exec.Cmd{Path: \"/bin/sh\", Args: []string{\"sh\", \"-c\", x}}; return r.Run() }\n"},
		{name: "exec.Cmd run through a generic helper", fn: "Run", label: "Capability+exec((os/exec.Cmd).Run)", high: true,
			oldSrc: "package p\nfunc Run(x string) error { return nil }\n",
			newSrc: "package p\nimport \"os/exec\"\nfunc run[T interface{ Run() error }](c T) error { return c.Run() }\nfunc Run(x string) error { return run(&exec.Cmd{Path: \"/bin/sh\", Args: []string{\"sh\", \"-c\", x}}) }\n"},
		{name: "http.DefaultClient through an interface", fn: "Fetch", label: "Capability+network((net/http.Client).Do)", high: true,
			oldSrc: "package p\nimport \"net/http\"\nfunc Fetch(req *http.Request) (*http.Response, error) { return nil, nil }\n",
			newSrc: "package p\nimport \"net/http\"\ntype doer interface{ Do(*http.Request) (*http.Response, error) }\nfunc Fetch(req *http.Request) (*http.Response, error) { var d doer = http.DefaultClient; return d.Do(req) }\n"},
		{name: "a request sent through http.DefaultTransport", fn: "Fetch", label: "Capability+network((net/http.RoundTripper).RoundTrip)", high: true,
			oldSrc: "package p\nimport \"net/http\"\nfunc Fetch(req *http.Request) (*http.Response, error) { return nil, nil }\n",
			newSrc: "package p\nimport \"net/http\"\nfunc Fetch(req *http.Request) (*http.Response, error) { return http.DefaultTransport.RoundTrip(req) }\n"},
		{name: "a method called by name through reflection", fn: "Invoke", label: "Capability+reflection((reflect.Value).MethodByName)", high: true,
			oldSrc: "package p\nfunc Invoke(x any, m string) error { return nil }\n",
			newSrc: "package p\nimport \"reflect\"\nfunc Invoke(x any, m string) error { return reflect.ValueOf(x).MethodByName(m).Interface().(func() error)() }\n"},
		{name: "ioutil.WriteFile", fn: "Save", label: "Capability+filesystem(io/ioutil.WriteFile)", high: true,
			oldSrc: "package p\nfunc Save(p string, b []byte) error { return nil }\n",
			newSrc: "package p\nimport \"io/ioutil\"\nfunc Save(p string, b []byte) error { return ioutil.WriteFile(p, b, 0o644) }\n"},
		{name: "a read-only handle made setuid", fn: "Fix", label: "Capability+filesystem((os.File).Chmod)", high: true,
			oldSrc: "package p\nimport \"os\"\nfunc Fix(p string) error { _, err := os.Open(p); return err }\n",
			newSrc: "package p\nimport \"os\"\nfunc Fix(p string) error { f, err := os.Open(p); if err != nil { return err }; return f.Chmod(0o4777) }\n"},
		{name: "a temporary file dropped", fn: "Drop", label: "Capability+filesystem(os.CreateTemp)", high: true,
			oldSrc: "package p\nfunc Drop(dir string, b []byte) error { return nil }\n",
			newSrc: "package p\nimport \"os\"\nfunc Drop(dir string, b []byte) error { f, err := os.CreateTemp(dir, \"*.desktop\"); if err != nil { return err }; _, err = f.Write(b); return err }\n"},
		{name: "the page size read through syscall", fn: "Page", label: "Capability",
			oldSrc: "package p\nimport \"os\"\nfunc Page() int { return os.Getpagesize() }\n",
			newSrc: "package p\nimport \"syscall\"\nfunc Page() int { return syscall.Getpagesize() }\n"},
		{name: "a tool looked up, not run", fn: "HasGit", label: "Capability",
			oldSrc: "package p\nimport \"os\"\nfunc HasGit() bool { _, err := os.Stat(\"/usr/bin/git\"); return err == nil }\n",
			newSrc: "package p\nimport \"os/exec\"\nfunc HasGit() bool { _, err := exec.LookPath(\"git\"); return err == nil }\n"},
	})
}

// ssh.InsecureIgnoreHostKey disables host key verification. The test stubs
// golang.org/x/crypto/ssh with a local replacement module.
func TestDiffRisk_InsecureIgnoreHostKey(t *testing.T) {
	shared := map[string]string{
		"go.mod":         "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/crypto v0.0.0\n\nreplace golang.org/x/crypto => ./xcrypto\n",
		"xcrypto/go.mod": "module golang.org/x/crypto\n\ngo 1.22\n",
		"xcrypto/ssh/ssh.go": "package ssh\n\ntype HostKeyCallback func(string) error\n\ntype ClientConfig struct{ HostKeyCallback HostKeyCallback }\n\n" +
			"func InsecureIgnoreHostKey() HostKeyCallback { return func(string) error { return nil } }\n\n" +
			"func FixedHostKey(k string) HostKeyCallback { return func(h string) error { return nil } }\n",
	}
	oldDir, newDir := writeModule(t, shared,
		map[string]string{"a.go": "package m\n\nimport \"golang.org/x/crypto/ssh\"\n\nfunc Client(k string) *ssh.ClientConfig { return &ssh.ClientConfig{HostKeyCallback: ssh.FixedHostKey(k)} }\n"},
		map[string]string{"a.go": "package m\n\nimport \"golang.org/x/crypto/ssh\"\n\nfunc Client(k string) *ssh.ClientConfig { return &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()} }\n"})
	out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	f := findFunc(t, out, "Client")
	if !strings.Contains(f.TopologyDelta, "WeakenedSecurity(golang.org/x/crypto/ssh.InsecureIgnoreHostKey())") || f.RiskScore < models.RiskScoreHigh {
		t.Errorf("Client: risk %d, delta %q; want WeakenedSecurity for InsecureIgnoreHostKey", f.RiskScore, f.TopologyDelta)
	}
}
