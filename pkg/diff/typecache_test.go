package diff

import (
	"crypto/sha256"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
)

// withStore makes loads use s, starting from an empty in-process cache as
// a new process does, until the test ends.
func withStore(t *testing.T, s *typeStore) {
	t.Helper()
	origStore, origCache := activeTypeStore, depCache
	activeTypeStore = func() *typeStore { return s }
	t.Cleanup(func() { activeTypeStore, depCache = origStore, origCache })
	freshProcess(s)
}

// freshProcess empties the in-process cache and s's counters, as a new
// process starts.
func freshProcess(s *typeStore) {
	depCache = &packageCache{m: make(map[string]*cacheEntry)}
	if s != nil {
		s.hits.Store(0)
		s.misses.Store(0)
	}
}

func newStore(t *testing.T, writable bool) *typeStore {
	return &typeStore{dir: t.TempDir(), writable: writable, binary: "test-binary"}
}

// entries returns the entry files in s, keyed by their key.
func entries(t *testing.T, s *typeStore) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(s.dir, "??", "*"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string)
	for _, f := range files {
		out[filepath.Base(f)] = f
	}
	return out
}

// storedKeyOf returns the persistent key the in-process cache holds for
// the dependency with the given path, or "".
func storedKeyOf(path string) string {
	depCache.mu.Lock()
	defer depCache.mu.Unlock()
	for _, e := range depCache.m {
		if e.value.types != nil && e.value.types.Path() == path {
			return e.stored.key
		}
	}
	return ""
}

func snapshotOf(t *testing.T, root string, patterns ...string) []string {
	t.Helper()
	roots, err := loadSource(sourceLoaderConfig(root, nil), patterns...)
	if err != nil {
		t.Fatal(err)
	}
	return loaderSnapshot(t, roots)
}

func goPackagesSnapshot(t *testing.T, root string, patterns ...string) []string {
	t.Helper()
	want, err := packages.Load(sourceLoaderConfig(root, nil), patterns...)
	if err != nil {
		t.Fatal(err)
	}
	return loaderSnapshot(t, want)
}

// cachedModule writes a module whose root uses the standard library's
// network, TLS and HTTP types and a pinned module's generics, constants
// and methods.
func cachedModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"r/r.go": "package r\n\nimport (\n\t\"crypto/tls\"\n\t\"net\"\n\t\"net/http\"\n\n\t\"example.com/dep\"\n)\n\n" +
			"func R(addrs []string, insecure bool) (*http.Client, error) {\n\tcfg := &tls.Config{MinVersion: tls.VersionTLS12}\n\tif insecure {\n\t\tcfg.InsecureSkipVerify = true\n\t}\n" +
			"\tfor _, a := range dep.Map(addrs, dep.Trim) {\n\t\tif dep.On {\n\t\t\tif _, err := net.Dial(\"tcp\", a); err != nil {\n\t\t\t\treturn nil, err\n\t\t\t}\n\t\t}\n\t}\n" +
			"\tvar l dep.List[string]\n\tl.Push(\"x\")\n\treturn &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}, nil\n}\n",
	})
	pinnedModules(t, root, map[string]map[string]string{
		"example.com/dep@v1.0.0": {
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"dep.go": "package dep\n\nimport \"strings\"\n\nconst On = false\n\n" +
				"func Map[A, B any](xs []A, f func(A) B) []B {\n\tout := make([]B, 0, len(xs))\n\tfor _, x := range xs {\n\t\tout = append(out, f(x))\n\t}\n\treturn out\n}\n\n" +
				"func Trim(s string) string { return strings.TrimSpace(s) }\n\n" +
				"type List[T any] struct{ items []T }\n\nfunc (l *List[T]) Push(v T) { l.items = append(l.items, v) }\n",
		},
	})
	return root
}

// A cold load fills the cache; a load in a new process takes every shared
// dependency from it; both give go/packages' result.
func TestTypeCache_WarmLoadMatchesGoPackages(t *testing.T) {
	root := cachedModule(t)
	want := goPackagesSnapshot(t, root, "./r")
	s := newStore(t, true)
	withStore(t, s)

	if d := firstDifference(want, snapshotOf(t, root, "./r")); d != "" {
		t.Fatalf("cold load differs from go/packages: %s", d)
	}
	stored := entries(t, s)
	if s.hits.Load() != 0 || len(stored) == 0 || s.misses.Load() != int64(len(stored)) {
		t.Fatalf("cold load: %d hits, %d misses, %d entries; want 0 hits and an entry per miss", s.hits.Load(), s.misses.Load(), len(stored))
	}
	if storedKeyOf("example.com/dep") == "" || stored[storedKeyOf("net/http")] == "" {
		t.Fatalf("no entry for the pinned module or net/http")
	}

	freshProcess(s)
	if d := firstDifference(want, snapshotOf(t, root, "./r")); d != "" {
		t.Fatalf("warm load differs from go/packages: %s", d)
	}
	if s.misses.Load() != 0 || s.hits.Load() != int64(len(stored)) {
		t.Errorf("warm load: %d hits, %d misses; want %d hits", s.hits.Load(), s.misses.Load(), len(stored))
	}
}

// Two loads at once, as a batch's two trees load, share one cached
// package per dependency and both give go/packages' result.
func TestTypeCache_ConcurrentLoads(t *testing.T) {
	root := cachedModule(t)
	want := goPackagesSnapshot(t, root, "./r")
	s := newStore(t, true)
	withStore(t, s)
	snapshotOf(t, root, "./r")
	stored := len(entries(t, s))

	for _, warm := range []bool{false, true} {
		freshProcess(s)
		if !warm {
			for _, f := range entries(t, s) {
				os.Remove(f)
			}
		}
		var wg sync.WaitGroup
		snaps := make([][]string, 2)
		for i := range snaps {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				roots, err := loadSource(sourceLoaderConfig(root, nil), "./r")
				if err != nil {
					t.Error(err)
					return
				}
				snaps[i] = loaderSnapshot(t, roots)
			}(i)
		}
		wg.Wait()
		for i, snap := range snaps {
			if d := firstDifference(want, snap); d != "" {
				t.Errorf("warm=%v load %d differs from go/packages: %s", warm, i, d)
			}
		}
		if got := s.hits.Load() + s.misses.Load(); got != int64(stored) {
			t.Errorf("warm=%v: %d lookups for %d shared dependencies; want one each", warm, got, stored)
		}
	}
}

// An edit to a dependency's file, even in the module cache under the same
// version, changes its key: the load misses and sees the edit.
func TestTypeCache_EditedDependencyMisses(t *testing.T) {
	root := cachedModule(t)
	s := newStore(t, true)
	withStore(t, s)
	roots, err := loadSource(sourceLoaderConfig(root, nil), "./r")
	if err != nil {
		t.Fatal(err)
	}
	before := loaderSnapshot(t, roots)
	file := roots[0].Imports["example.com/dep"].CompiledGoFiles[0]
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Dir(file), 0o755)
	os.Chmod(file, 0o644)
	if err := os.WriteFile(file, []byte(strings.Replace(string(src), "const On = false", "const On = true", 1)), 0o644); err != nil {
		t.Fatal(err)
	}

	freshProcess(s)
	after := snapshotOf(t, root, "./r")
	if d := firstDifference(goPackagesSnapshot(t, root, "./r"), after); d != "" {
		t.Fatalf("load after the edit differs from go/packages: %s", d)
	}
	if strings.Join(before, "\n") == strings.Join(after, "\n") {
		t.Errorf("the edit did not change the result")
	}
	if s.misses.Load() != 1 {
		t.Errorf("%d misses; want 1, the edited package", s.misses.Load())
	}
}

// Every input of a key changes it; a package without digests, or with an
// import that has no key, has none; unsafe needs no key.
func TestTypeCache_KeyCoversItsInputs(t *testing.T) {
	s := &typeStore{binary: "b"}
	base := func() (*packages.Package, [][sha256.Size]byte) {
		imp := &packages.Package{PkgPath: "example.com/imp"}
		return &packages.Package{
			PkgPath:         "example.com/p",
			Name:            "p",
			TypesSizes:      types.SizesFor("gc", "amd64"),
			Module:          &packages.Module{GoVersion: "1.22"},
			CompiledGoFiles: []string{"/m/p/a.go", "/m/p/b.go"},
			Imports:         map[string]*packages.Package{"example.com/imp": imp, "unsafe": {PkgPath: "unsafe"}},
		}, [][sha256.Size]byte{{1}, {2}}
	}
	importKey := func(p *packages.Package) string {
		if p.PkgPath == "unsafe" {
			t.Errorf("unsafe's key was asked for")
		}
		return "impkey"
	}
	p, digests := base()
	want := s.key(p, digests, importKey)
	if want == "" {
		t.Fatal("no key")
	}
	t.Setenv("GODEBUG", "")
	for name, change := range map[string]func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string{
		"binary": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			s.binary = "c"
			return importKey
		},
		"path": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.PkgPath += "x"
			return importKey
		},
		"name": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.Name = "q"
			return importKey
		},
		"sizes": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.TypesSizes = types.SizesFor("gc", "386")
			return importKey
		},
		"version": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.Module.GoVersion = "1.23"
			return importKey
		},
		"no module": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.Module = nil
			return importKey
		},
		"file": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.CompiledGoFiles[1] = "/m/p/c.go"
			return importKey
		},
		"digest": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			d[1][0] = 3
			return importKey
		},
		"import key": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			return func(*packages.Package) string { return "otherkey" }
		},
		"import path": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			p.Imports["example.com/imp2"] = p.Imports["example.com/imp"]
			delete(p.Imports, "example.com/imp")
			return importKey
		},
		"GODEBUG": func(p *packages.Package, d [][sha256.Size]byte, s *typeStore) func(*packages.Package) string {
			t.Setenv("GODEBUG", "gotypesalias=0")
			return importKey
		},
	} {
		p, digests := base()
		st := &typeStore{binary: s.binary}
		ik := change(p, digests, st)
		if got := st.key(p, digests, ik); got == want || got == "" {
			t.Errorf("changing the %s: key %q, want a new one", name, got)
		}
		t.Setenv("GODEBUG", "")
	}

	p, digests = base()
	if got := s.key(p, digests[:1], importKey); got != "" {
		t.Errorf("a file without a digest: key %q", got)
	}
	if got := s.key(p, nil, importKey); got != "" {
		t.Errorf("no digests: key %q", got)
	}
	if got := s.key(p, digests, func(*packages.Package) string { return "" }); got != "" {
		t.Errorf("an import without a key: key %q", got)
	}
}

// A damaged entry is a miss: the load is correct and rewrites it.
func TestTypeCache_DamagedEntryIsAMiss(t *testing.T) {
	root := cachedModule(t)
	want := goPackagesSnapshot(t, root, "./r")
	s := newStore(t, true)
	withStore(t, s)
	snapshotOf(t, root, "./r")
	stored := entries(t, s)
	damage := []func([]byte) []byte{
		func(b []byte) []byte { b[len(b)-1] ^= 1; return b },               // payload
		func(b []byte) []byte { b[len(entryMagic)] ^= 1; return b },        // checksum
		func(b []byte) []byte { b[0] = 'x'; return b },                     // magic
		func(b []byte) []byte { return b[:len(entryMagic)+sha256.Size-1] }, // truncated
	}
	i := 0
	for _, f := range stored {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, damage[i%len(damage)](b), 0o600); err != nil {
			t.Fatal(err)
		}
		i++
	}

	freshProcess(s)
	if d := firstDifference(want, snapshotOf(t, root, "./r")); d != "" {
		t.Fatalf("load from damaged entries differs from go/packages: %s", d)
	}
	if s.hits.Load() != 0 || s.misses.Load() != int64(len(stored)) {
		t.Errorf("%d hits, %d misses; want every damaged entry a miss", s.hits.Load(), s.misses.Load())
	}
	freshProcess(s)
	snapshotOf(t, root, "./r")
	if s.hits.Load() != int64(len(stored)) {
		t.Errorf("%d hits after rewriting %d entries", s.hits.Load(), len(stored))
	}
}

// A read-only cache supplies its entries and writes none.
func TestTypeCache_ReadOnly(t *testing.T) {
	root := cachedModule(t)
	want := goPackagesSnapshot(t, root, "./r")
	rw := newStore(t, true)
	withStore(t, rw)
	snapshotOf(t, root, "./r")
	stored := len(entries(t, rw))

	for _, ro := range []*typeStore{
		{dir: rw.dir, binary: rw.binary},
		{dir: t.TempDir(), binary: rw.binary},
	} {
		activeTypeStore = func() *typeStore { return ro }
		freshProcess(ro)
		if d := firstDifference(want, snapshotOf(t, root, "./r")); d != "" {
			t.Fatalf("read-only load differs from go/packages: %s", d)
		}
		if got := len(entries(t, ro)); ro.dir == rw.dir && (got != stored || ro.hits.Load() != int64(stored)) {
			t.Errorf("filled read-only cache: %d entries, %d hits; want %d of each", got, ro.hits.Load(), stored)
		} else if ro.dir != rw.dir && got != 0 {
			t.Errorf("empty read-only cache: %d entries written", got)
		}
	}
}

// A package with errors is not stored, nor is anything that imports it,
// and it keeps its errors when loaded again.
func TestTypeCache_ErrorsAreNotStored(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":    "module example.com/m\n\ngo 1.22\n\nrequire example.com/broken v1.0.0\n",
		"root/r.go": "package root\n\nimport \"example.com/broken/c\"\n\nfunc R() int { return len(c.Y) }\n",
	})
	pinnedModules(t, root, map[string]map[string]string{
		"example.com/broken@v1.0.0": {
			"go.mod": "module example.com/broken\n\ngo 1.22\n",
			"b/b.go": "package b\n\nvar X []undefinedType\n",
			"c/c.go": "package c\n\nimport \"example.com/broken/b\"\n\nvar Y = b.X\n",
		},
	})
	want := goPackagesSnapshot(t, root, "./root")
	s := newStore(t, true)
	withStore(t, s)
	for run := 0; run < 2; run++ {
		freshProcess(s)
		if d := firstDifference(want, snapshotOf(t, root, "./root")); d != "" {
			t.Fatalf("run %d differs from go/packages: %s", run, d)
		}
		for _, path := range []string{"example.com/broken/b", "example.com/broken/c"} {
			if key := storedKeyOf(path); key != "" && entries(t, s)[key] != "" {
				t.Errorf("run %d: %s was stored", run, path)
			}
		}
	}
	mustContain(t, want, "package example.com/m/root illTyped=true")
}

// An entry decodes only for its own package, against the packages that
// package imports: one that would refer to another package is rejected.
func TestTypeCache_DecodeChecksItsPackage(t *testing.T) {
	root := cachedModule(t)
	s := newStore(t, true)
	withStore(t, s)
	roots, err := loadSource(sourceLoaderConfig(root, nil), "./r")
	if err != nil {
		t.Fatal(err)
	}
	var bufio *packages.Package
	packages.Visit(roots, nil, func(p *packages.Package) {
		if p.PkgPath == "bufio" {
			bufio = p
		}
	})
	if bufio == nil {
		t.Fatal("bufio was not loaded")
	}
	payload := s.read(storedKeyOf("bufio"))
	if payload == nil {
		t.Fatal("no entry for bufio")
	}
	if decode(payload, bufio) == nil {
		t.Errorf("bufio's entry did not decode for bufio")
	}
	if decode(payload, &packages.Package{PkgPath: "bufio", Name: "other"}) != nil {
		t.Errorf("bufio's entry decoded for a package of another name")
	}
	if decode(payload, &packages.Package{PkgPath: "bufio", Name: "bufio"}) != nil {
		t.Errorf("bufio's entry decoded without the packages it refers to")
	}
	if decode(payload[:len(payload)/2], bufio) != nil {
		t.Errorf("half an entry decoded")
	}
}

// Only "rw:" and "ro:" with an absolute directory open a cache; a writable
// one is created private.
func TestOpenTypeStore(t *testing.T) {
	dir := t.TempDir()
	for _, setting := range []string{"", "off", "on", "rw", "rw:", "rw:relative/dir", "xx:" + dir, "RW:" + dir} {
		if s := openTypeStore(setting); s != nil {
			t.Errorf("%q opened a cache", setting)
		}
	}
	ro := openTypeStore("ro:" + filepath.Join(dir, "absent"))
	if ro == nil || ro.writable || ro.binary == "" {
		t.Fatalf("ro: got %+v", ro)
	}
	if _, err := os.Stat(ro.dir); !os.IsNotExist(err) {
		t.Errorf("a read-only cache created its directory")
	}
	rw := openTypeStore("rw:" + filepath.Join(dir, "new", "cache"))
	if rw == nil || !rw.writable || rw.binary != ro.binary {
		t.Fatalf("rw: got %+v", rw)
	}
	if info, err := os.Stat(rw.dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("writable cache directory: %v %v; want mode 0700", info, err)
	}
	if _, err := os.Stat(filepath.Join(rw.dir, "trim.txt")); err != nil {
		t.Errorf("opening a writable cache did not trim it: %v", err)
	}
	orig := executableID
	executableID = func() (string, error) { return "", os.ErrPermission }
	if s := openTypeStore("rw:" + filepath.Join(dir, "unhashed")); s != nil {
		t.Errorf("a cache opened without the executable's hash")
	}
	executableID = orig
	if _, err := os.Stat(filepath.Join(dir, "unhashed")); !os.IsNotExist(err) {
		t.Errorf("a cache that did not open created its directory")
	}
	exe, _ := os.Executable()
	data, _ := os.ReadFile(exe)
	if id, err := executableID(); err != nil || id != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Errorf("executableID: %s %v; want the SHA-256 of %s", id, err, exe)
	}
	blocked := filepath.Join(dir, "file")
	os.WriteFile(blocked, nil, 0o600)
	if s := openTypeStore("rw:" + filepath.Join(blocked, "cache")); s != nil {
		t.Errorf("a writable cache opened where its directory cannot be made")
	}
}

// Trimming removes the entries unused for trimAge, at most once per
// trimInterval; a hit refreshes an old entry's time in a writable cache.
func TestTypeStore_TrimAndTouch(t *testing.T) {
	s := newStore(t, true)
	now := time.Now()
	write := func(name string, age time.Duration) string {
		f := filepath.Join(s.dir, name[:2], name)
		os.MkdirAll(filepath.Dir(f), 0o700)
		payload := []byte("payload")
		sum := sha256.Sum256(payload)
		if err := os.WriteFile(f, append(append([]byte(entryMagic), sum[:]...), payload...), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(f, now.Add(-age), now.Add(-age))
		return f
	}
	old, recent := write("aaold", trimAge+time.Hour), write("aarecent", trimAge-time.Hour)
	tmp := write("bbtmp-123", trimAge+time.Hour)

	marker := filepath.Join(s.dir, "trim.txt")
	os.WriteFile(marker, nil, 0o600)
	os.Chtimes(marker, now.Add(-trimInterval+time.Hour), now.Add(-trimInterval+time.Hour))
	s.trim(now)
	if _, err := os.Stat(old); err != nil {
		t.Errorf("trimmed within trimInterval of the last trim")
	}

	os.Chtimes(marker, now.Add(-trimInterval-time.Hour), now.Add(-trimInterval-time.Hour))
	s.trim(now)
	for f, kept := range map[string]bool{old: false, tmp: false, recent: true} {
		if _, err := os.Stat(f); (err == nil) != kept {
			t.Errorf("%s: kept=%v, want %v", filepath.Base(f), err == nil, kept)
		}
	}
	if info, err := os.Stat(marker); err != nil || now.Sub(info.ModTime()) > time.Minute {
		t.Errorf("the trim was not recorded")
	}

	for _, writable := range []bool{false, true} {
		s.writable = writable
		os.Chtimes(recent, now.Add(-touchInterval-time.Hour), now.Add(-touchInterval-time.Hour))
		if s.read("aarecent") == nil {
			t.Fatal("entry not read")
		}
		info, _ := os.Stat(recent)
		if touched := now.Sub(info.ModTime()) < touchInterval; touched != writable {
			t.Errorf("writable=%v: hit refreshed the entry's time: %v", writable, touched)
		}
	}
	os.Chtimes(recent, now.Add(-time.Minute), now.Add(-time.Minute))
	s.read("aarecent")
	if info, _ := os.Stat(recent); now.Sub(info.ModTime()) < 30*time.Second {
		t.Errorf("a hit refreshed an entry used within touchInterval")
	}

	// The trim is recorded at the time it was given: a trim two days on,
	// then one an hour after that, removes only once.
	later := now.Add(48 * time.Hour)
	s.trim(later)
	stale := write("ccstale", 0)
	os.Chtimes(stale, later.Add(-trimAge-time.Hour), later.Add(-trimAge-time.Hour))
	s.trim(later.Add(time.Hour))
	if _, err := os.Stat(stale); err != nil {
		t.Errorf("trimmed again an hour after the last trim")
	}
}

// An entry that cannot be written is not: a cache directory the user may
// not write leaves no entry and no error.
func TestTypeStore_SaveToUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to read-only directories")
	}
	s := newStore(t, true)
	key := strings.Repeat("ab", 32)
	shard := filepath.Dir(s.path(key))
	if err := os.MkdirAll(shard, 0o500); err != nil {
		t.Fatal(err)
	}
	os.Chmod(shard, 0o500)
	t.Cleanup(func() { os.Chmod(shard, 0o700) })
	s.save(key, types.NewPackage("example.com/p", "p"))
	if files, _ := os.ReadDir(shard); len(files) != 0 {
		t.Errorf("wrote %v", files)
	}
}

// A write that cannot be completed leaves nothing behind: here a directory
// stands where the entry would go.
func TestTypeStore_FailedSaveLeavesNothing(t *testing.T) {
	s := newStore(t, true)
	key := strings.Repeat("cd", 32)
	if err := os.MkdirAll(s.path(key), 0o700); err != nil {
		t.Fatal(err)
	}
	s.save(key, types.NewPackage("example.com/p", "p"))
	files, _ := os.ReadDir(filepath.Dir(s.path(key)))
	if len(files) != 1 || !files[0].IsDir() {
		t.Errorf("left %v; want only the directory", files)
	}
}
