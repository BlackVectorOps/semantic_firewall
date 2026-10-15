package diff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/gcexportdata"
	"golang.org/x/tools/go/packages"
)

// TypeCacheEnvVar configures the persistent type cache, which keeps the
// declarations of shareable dependencies (see dependencyKey) across
// processes: "rw:DIR" reads and writes entries in the absolute directory
// DIR, "ro:DIR" only reads them, and any other value turns the cache off.
//
// An entry is keyed by everything that determines the types: the running
// executable's contents, the package path and name, the type sizes, the Go
// language version, GODEBUG, each compiled file's path and content hash,
// and the keys of its imports. A hit therefore means the same source bytes
// checked by the same program. Only packages without errors are stored;
// an entry that fails its checksum or does not decode is a miss.
const TypeCacheEnvVar = "SFW_TYPE_CACHE"

// typeCacheFormat is part of every key; change it when the entry format
// or what an entry holds changes.
const typeCacheFormat = "sfw-types-1"

// entryMagic starts every entry file, before the payload's SHA-256.
const entryMagic = "sfw-types\n"

const (
	// trimInterval is how often a writable cache removes unused entries.
	trimInterval = 24 * time.Hour
	// trimAge is how long an entry may go unused before it is removed.
	trimAge = 7 * 24 * time.Hour
	// touchInterval bounds how often a hit refreshes an entry's time.
	touchInterval = time.Hour
)

// typeStore is a persistent type cache directory.
type typeStore struct {
	dir      string
	writable bool
	// binary identifies the running executable: its contents' SHA-256.
	binary string
	// hits and misses count the packages loaded from the cache and those
	// it could not supply.
	hits, misses atomic.Int64
}

// activeTypeStore returns the cache TypeCacheEnvVar configures, or nil;
// tests replace it.
var activeTypeStore = sync.OnceValue(func() *typeStore {
	return openTypeStore(os.Getenv(TypeCacheEnvVar))
})

// openTypeStore opens the cache a TypeCacheEnvVar value describes, or
// returns nil: for another value, a relative directory, an executable it
// cannot read, or a writable directory it cannot create. Opening a
// writable cache removes the entries unused for trimAge, at most once per
// trimInterval.
func openTypeStore(setting string) *typeStore {
	mode, dir, _ := strings.Cut(setting, ":")
	if (mode != "rw" && mode != "ro") || !filepath.IsAbs(dir) {
		return nil
	}
	binary, err := executableID()
	if err != nil {
		return nil
	}
	s := &typeStore{dir: dir, writable: mode == "rw", binary: binary}
	if s.writable {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil
		}
		s.trim(time.Now())
	}
	return s
}

// executableID returns the SHA-256 of the running executable; tests make
// it fail. Without it no cache opens: its entries could have been written
// by another version of sfw.
var executableID = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// digests returns the SHA-256 of each of p's compiled files, or nil when
// one cannot be read.
func (s *typeStore) digests(p *packages.Package) [][sha256.Size]byte {
	sums := make([][sha256.Size]byte, len(p.CompiledGoFiles))
	for i, name := range p.CompiledGoFiles {
		src, err := readSourceFile(name)
		if err != nil {
			return nil
		}
		sums[i] = sha256.Sum256(src)
	}
	return sums
}

// key returns the entry key of p, whose files' digests are given and whose
// imports' keys importKey gives, or "" when there are no digests or an
// import has no key.
func (s *typeStore) key(p *packages.Package, digests [][sha256.Size]byte, importKey func(*packages.Package) string) string {
	if len(digests) != len(p.CompiledGoFiles) {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%#v\x00%s\x00", typeCacheFormat, s.binary, p.PkgPath, p.Name, p.TypesSizes, os.Getenv("GODEBUG"))
	if p.Module != nil {
		fmt.Fprintf(h, "go%s\x00", p.Module.GoVersion)
	}
	for i, name := range p.CompiledGoFiles {
		fmt.Fprintf(h, "%s\x00%x\x00", name, digests[i])
	}
	paths := make([]string, 0, len(p.Imports))
	for path := range p.Imports {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		imp := p.Imports[path]
		ik := "unsafe"
		if imp.PkgPath != "unsafe" {
			ik = importKey(imp)
		}
		if ik == "" {
			return ""
		}
		fmt.Fprintf(h, "%s=%s\x00", path, ik)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *typeStore) path(key string) string {
	return filepath.Join(s.dir, key[:2], key)
}

// exportMu serializes encoding and decoding: decoding may add objects to
// the packages it is given.
var exportMu sync.Mutex

// read returns the payload of the entry stored under key, or nil when
// there is none or it fails its checksum. A writable cache records the use
// in the entry's time, at most once per touchInterval.
func (s *typeStore) read(key string) []byte {
	data, err := os.ReadFile(s.path(key))
	if err != nil || len(data) < len(entryMagic)+sha256.Size || string(data[:len(entryMagic)]) != entryMagic {
		return nil
	}
	sum, payload := data[len(entryMagic):len(entryMagic)+sha256.Size], data[len(entryMagic)+sha256.Size:]
	if got := sha256.Sum256(payload); !bytes.Equal(sum, got[:]) {
		return nil
	}
	if s.writable {
		now := time.Now()
		if info, err := os.Stat(s.path(key)); err == nil && now.Sub(info.ModTime()) > touchInterval {
			os.Chtimes(s.path(key), now, now)
		}
	}
	return payload
}

// decode returns the types in payload for p, decoded against the packages
// p imports, directly or not, or nil. A decoded package that refers to any
// other package than those is rejected.
func decode(payload []byte, p *packages.Package) *types.Package {
	view := make(map[string]*types.Package)
	packages.Visit([]*packages.Package{p}, nil, func(q *packages.Package) {
		if q != p {
			view[q.PkgPath] = q.Types
		}
	})
	given := make(map[string]*types.Package, len(view))
	for path, pkg := range view {
		given[path] = pkg
	}
	exportMu.Lock()
	pkg, err := gcexportdata.Read(bytes.NewReader(payload), sharedFset, view, p.PkgPath)
	exportMu.Unlock()
	if err != nil || pkg.Name() != p.Name {
		return nil
	}
	for _, imp := range pkg.Imports() {
		if given[imp.Path()] != imp {
			return nil
		}
	}
	return pkg
}

// save stores pkg under key, when the cache is writable. The entry appears
// whole or not at all.
func (s *typeStore) save(key string, pkg *types.Package) {
	if !s.writable {
		return
	}
	var payload bytes.Buffer
	exportMu.Lock()
	err := gcexportdata.Write(&payload, sharedFset, pkg)
	exportMu.Unlock()
	if err != nil {
		return
	}
	dir := filepath.Dir(s.path(key))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, "tmp-")
	if err != nil {
		return
	}
	sum := sha256.Sum256(payload.Bytes())
	_, err = tmp.Write(append(append([]byte(entryMagic), sum[:]...), payload.Bytes()...))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.path(key))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
}

// trim removes the entries, and the files of interrupted writes, unused
// for trimAge, unless it did so within trimInterval of now.
func (s *typeStore) trim(now time.Time) {
	marker := filepath.Join(s.dir, "trim.txt")
	if info, err := os.Stat(marker); err == nil && now.Sub(info.ModTime()) < trimInterval {
		return
	}
	files, _ := filepath.Glob(filepath.Join(s.dir, "??", "*"))
	for _, f := range files {
		if info, err := os.Lstat(f); err == nil && now.Sub(info.ModTime()) > trimAge {
			os.Remove(f)
		}
	}
	if err := os.WriteFile(marker, nil, 0o600); err == nil {
		os.Chtimes(marker, now, now)
	}
}
