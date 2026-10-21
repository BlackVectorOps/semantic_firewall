package api

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// unanalyzedSource is what a diff reads from a Go file's text because its
// SSA does not show it.
type unanalyzedSource struct {
	// bodyless maps each function declared without a Go body, by the name
	// SSAFunctionName gives it, to its parameter and result types. Its code
	// is assembly, or another function a //go:linkname directive names, so
	// it has no SSA.
	bodyless map[string]string
	// linknames are the file's //go:linkname directives (see fileLinknames).
	linknames []string
	// builds are the default builds that compile the file (see
	// diff.DefaultBuilds).
	builds []string
}

// parseUnanalyzed reads a file's unanalyzedSource. A file that does not
// parse has none but its builds: its load fails before the diff gets here.
func parseUnanalyzed(abs string, src []byte) unanalyzedSource {
	builds := diff.DefaultBuilds(abs, string(src))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return unanalyzedSource{builds: builds}
	}
	bodyless := make(map[string]string)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body != nil {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			name = "(" + exprString(fset, fd.Recv.List[0].Type) + ")." + name
		}
		bodyless[name] = fieldTypes(fset, fd.Type.Params) + " " + fieldTypes(fset, fd.Type.Results)
	}
	return unanalyzedSource{bodyless: bodyless, linknames: fileLinknames(f), builds: builds}
}

// fieldTypes prints a parameter or result list's types, one per name, so a
// renamed parameter is no change.
func fieldTypes(fset *token.FileSet, fl *ast.FieldList) string {
	if fl == nil {
		return "()"
	}
	var types []string
	for _, field := range fl.List {
		t := exprString(fset, field.Type)
		for range max(len(field.Names), 1) {
			types = append(types, t)
		}
	}
	return "(" + strings.Join(types, ", ") + ")"
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	printer.Fprint(&b, fset, e)
	return b.String()
}

// diffBodyless compares the body-less functions of two versions of a file.
// An added one, or one whose signature changed, is high-risk: code the
// analysis cannot read becomes callable. A removed one scores 0.
func diffBodyless(oldDecls, newDecls map[string]string) []models.FunctionDiff {
	names := make([]string, 0, len(oldDecls)+len(newDecls))
	for name := range oldDecls {
		names = append(names, name)
	}
	for name := range newDecls {
		if _, ok := oldDecls[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	diffs := make([]models.FunctionDiff, 0, len(names))
	for _, name := range names {
		o, inOld := oldDecls[name]
		n, inNew := newDecls[name]
		d := models.FunctionDiff{Function: name}
		switch {
		case !inNew:
			d.Status, d.TopologyDelta = models.StatusRemoved, "NoBody"
		case !inOld:
			d.Status, d.TopologyDelta, d.RiskScore = models.StatusAdded, "NoBody", models.RiskScoreHigh
		case o == n:
			d.Status, d.FingerprintMatch = models.StatusPreserved, true
		default:
			d.Status, d.TopologyDelta, d.RiskScore = models.StatusModified, "NoBody, Signature~", models.RiskScoreHigh
		}
		diffs = append(diffs, d)
	}
	return diffs
}

// diffLinknames reports the //go:linkname directives added to or removed
// from a file, scored as deps diff scores a package's. A directive applies
// package-wide, to a function or variable declared in any file, so each one
// is reported whatever it names. A changed target is a removed directive
// and an added one.
func diffLinknames(oldPath, newPath string, oldDirs, newDirs []string) []models.FileChange {
	keyed := func(dirs []string) map[string]string {
		inv := make(map[string]string, len(dirs))
		for _, d := range dirs {
			inv["linkname:"+d] = d
		}
		return inv
	}
	changes := diffInventories(keyed(oldDirs), keyed(newDirs))
	for i, fc := range changes {
		path := newPath
		if fc.Change == "removed" {
			path = oldPath
		}
		changes[i].File = path + ": " + fc.File
	}
	return changes
}
