package api

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// riskNonGoCode is charged for an added or modified file a batch diff's
// tree compiles that is not Go: assembly, C and the other languages cgo
// compiles, and the files they include. Machine code (.syso and other
// objects) scores riskUnanalyzedSyso, and an embedded or other used file
// riskUnanalyzedOther.
const riskNonGoCode = models.RiskScoreHigh

// BatchOptions adjusts DiffBatchWithOptions.
type BatchOptions struct {
	// NonGo has a pair with no Go file on either side reported by what the
	// build makes of the file (see nonGoDiff), rather than loaded as Go.
	NonGo bool
}

// isGoPair reports whether either side of p is a Go file.
func isGoPair(p DiffPair) bool {
	return strings.HasSuffix(p.Old, ".go") || strings.HasSuffix(p.New, ".go")
}

// nonGoUse is how a tree's build uses one non-Go file: its unanalyzed kind
// and content hash.
type nonGoUse struct{ kind, hash string }

// nonGoTrees holds, per module root, what its build uses that is not Go
// source (see treeUses), or why that could not be listed.
type nonGoTrees map[string]struct {
	uses map[string]nonGoUse
	err  error
}

// load lists the tree of the module the file at path is in, once.
func (trees nonGoTrees) load(fsys FileSystem, path string) {
	if path == "" || path == os.DevNull {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	if root := moduleRoot(fsys, abs); root != "" {
		if _, ok := trees[root]; !ok {
			t := trees[root]
			t.uses, t.err = treeUses(root)
			trees[root] = t
		}
	}
}

// find looks the file at path up in every listed tree: an assembly file
// can #include a file outside its own module. A file no tree uses is
// unused unless some tree could not be listed.
func (trees nonGoTrees) find(path string) (nonGoUse, bool, error) {
	if path == "" || path == os.DevNull {
		return nonGoUse{}, false, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nonGoUse{}, false, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	var failed error
	for _, t := range trees {
		if t.err != nil {
			failed = t.err
			continue
		}
		if u, ok := t.uses[abs]; ok {
			return u, true, nil
		}
	}
	return nonGoUse{}, false, failed
}

// nonGoDiff reports a pair with no Go file on either side, looked up in
// trees, which must hold every module of the batch's files. A file that
// neither tree's build uses (documentation, configuration, test data, a
// file outside any module) gives an empty result. Otherwise, unless both
// sides hold the same content under the same use, the result lists the
// file under Unanalyzed, added, modified or removed, with the kinds of
// sfw deps diff: assembly and c score riskNonGoCode, syso and object
// riskUnanalyzedSyso, embed and other riskUnanalyzedOther, and a removal 0.
// A tree whose packages can't be listed fails the pair.
func nonGoDiff(fsys FileSystem, trees nonGoTrees, p DiffPair) *models.DiffOutput {
	out := &models.DiffOutput{OldFile: p.Old, NewFile: p.New, Functions: []models.FunctionDiff{}}
	if _, onDisk := fsys.(RealFileSystem); !onDisk {
		out.ErrorMessage = "a non-Go file can only be diffed on the real file system"
		return out
	}
	oldUse, inOld, err := trees.find(p.Old)
	if err == nil {
		var newUse nonGoUse
		var inNew bool
		newUse, inNew, err = trees.find(p.New)
		if err == nil {
			fc, changed := nonGoChange(p, oldUse, inOld, newUse, inNew)
			if changed {
				out.Unanalyzed = []models.FileChange{fc}
				if fc.RiskScore >= models.RiskScoreHigh {
					out.Summary.HighRiskChanges = 1
				}
			}
			return out
		}
	}
	out.ErrorMessage = err.Error()
	return out
}

// nonGoChange compares a non-Go file's use in the two trees.
func nonGoChange(p DiffPair, oldUse nonGoUse, inOld bool, newUse nonGoUse, inNew bool) (models.FileChange, bool) {
	switch {
	case !inOld && !inNew:
		return models.FileChange{}, false
	case !inNew:
		return models.FileChange{File: p.Old, Kind: oldUse.kind, Change: "removed"}, true
	case inOld && oldUse == newUse:
		return models.FileChange{}, false
	}
	fc := models.FileChange{File: p.New, Kind: newUse.kind, Change: "modified"}
	if !inOld {
		fc.Change = "added"
	}
	switch newUse.kind {
	case "assembly", "c":
		fc.RiskScore = riskNonGoCode
	case "syso", "object":
		fc.RiskScore = riskUnanalyzedSyso
	default:
		fc.RiskScore = riskUnanalyzedOther
	}
	return fc, true
}

// nonGoRank orders the kinds a file can be listed under, so a file used
// two ways (a header also embedded) gets the riskier kind.
var nonGoRank = map[string]int{"other": 1, "embed": 2, "c": 3, "assembly": 3, "object": 4, "syso": 4}

// treeUses lists, by absolute path with links resolved, the non-Go files
// the build of the module at root uses, with their kinds and hashes: the
// inventory sfw deps diff takes of a dependency (see inventory), over
// every package the module's packages import from this tree, its vendor
// directory and directories ./... skips (testdata, _x) included. The
// packages are those of the host's build; so that another platform's
// imports count too, every assembly, C or object file beside a Go file
// anywhere in the tree (nested modules aside) is listed as well, with the
// files the assembly includes.
func treeUses(root string) (map[string]nonGoUse, error) {
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps |
			packages.NeedEmbedFiles,
		Dir: root,
		Env: diff.HardenedEnvFor(root),
	}
	roots, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("listing the packages of %s: %w", root, err)
	}
	m := &depModule{dir: root}
	packages.Visit(roots, nil, func(p *packages.Package) {
		if dir := packageDir(p); dir != "" && (dir == root || strings.HasPrefix(dir, root+string(filepath.Separator))) {
			m.pkgs = append(m.pkgs, p)
		}
	})
	inv := inventory(m)
	besideGo(root, inv)
	uses := make(map[string]nonGoUse)
	for key, hash := range inv {
		kind, rel, _ := strings.Cut(key, ":")
		if kind == "linkname" || kind == "cgo" || kind == "excluded-go" {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real
		}
		if prev, ok := uses[abs]; !ok || nonGoRank[kind] > nonGoRank[prev.kind] {
			uses[abs] = nonGoUse{kind: kind, hash: hash}
		}
	}
	return uses, nil
}

// packageDir returns the directory of a package's files, or "" when it has
// none listed.
func packageDir(p *packages.Package) string {
	for _, files := range [][]string{p.GoFiles, p.OtherFiles, p.IgnoredFiles} {
		if len(files) > 0 {
			return filepath.Dir(files[0])
		}
	}
	return ""
}

// besideGo adds to inv, keyed as inventory keys, every assembly, C or
// object file in a directory under root that holds a .go file, and the
// files the assembly includes, skipping version control directories and
// nested modules.
func besideGo(root string, inv map[string]string) {
	listed := make(map[string]bool)
	for key := range inv {
		_, rel, _ := strings.Cut(key, ":")
		listed[filepath.Join(root, filepath.FromSlash(rel))] = true
	}
	hash := func(kind, f string) {
		if listed[f] {
			return
		}
		if sum, ok := hashFile(f); ok {
			rel, err := filepath.Rel(root, f)
			if err != nil {
				return
			}
			inv[kind+":"+filepath.ToSlash(rel)] = sum
			listed[f] = true
		}
	}
	included := make(map[string]bool)
	filepath.WalkDir(root, func(dir string, e fs.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return nil
		}
		switch e.Name() {
		case ".git", ".hg", ".svn", ".bzr":
			return filepath.SkipDir
		}
		if dir != root {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return filepath.SkipDir
			}
		}
		entries, _ := os.ReadDir(dir)
		hasGo := false
		for _, f := range entries {
			hasGo = hasGo || strings.HasSuffix(f.Name(), ".go")
		}
		if !hasGo {
			return nil
		}
		for _, f := range entries {
			path := filepath.Join(dir, f.Name())
			if f.IsDir() || !isRegular(path, f) {
				continue
			}
			switch kind := fileKind(path); kind {
			case "assembly":
				hash(kind, path)
				hashIncludes(path, included, hash)
			case "c", "syso", "object":
				hash(kind, path)
			}
		}
		return nil
	})
}
