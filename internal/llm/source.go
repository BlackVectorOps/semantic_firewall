package llm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// SourceIndex is one side of an audited diff as text: its lines and the
// functions declared in it, keyed the way the diff names them ("F",
// "(*T).M", "F$1" for the first closure in F). It is built with go/parser
// alone, which reads text and runs nothing, so the auditor can serve source
// outside the sandbox the diff ran in.
type SourceIndex struct {
	path  string
	lines []string
	funcs []*sourceFunc
	// byName maps a declaration's diff name to it. Closures have no entry:
	// lookup resolves them to the declaration that encloses them.
	byName map[string]*sourceFunc
}

// sourceFunc is a function or method declaration: its diff name, its line
// range (1-based, inclusive, documentation comment included) and the calls
// its body makes, as written ("exec.Command", "v.verifyAudience", "helper").
type sourceFunc struct {
	Name       string
	Start, End int
	Callees    []string
}

// NewSourceIndex indexes src, which came from path. A file with syntax
// errors is indexed as far as it parses: the lines are always served, and a
// function that failed to parse is simply absent.
func NewSourceIndex(path string, src []byte) *SourceIndex {
	idx := &SourceIndex{path: path, byName: map[string]*sourceFunc{}}
	if len(src) == 0 {
		return idx
	}
	idx.lines = strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")

	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if file == nil {
		return idx
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		start := fn.Pos()
		if fn.Doc != nil {
			start = fn.Doc.Pos()
		}
		sf := &sourceFunc{
			Name:    declName(fn),
			Start:   fset.Position(start).Line,
			End:     fset.Position(fn.End()).Line,
			Callees: callees(fn.Body),
		}
		idx.funcs = append(idx.funcs, sf)
		if _, dup := idx.byName[sf.Name]; !dup {
			idx.byName[sf.Name] = sf
		}
	}
	return idx
}

// declName is the diff's name for a declaration: "F" for a function,
// "(*T).M" or "(T).M" for a method, type parameters dropped as the SSA
// name drops them.
func declName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	ptr := ""
	if star, ok := recv.(*ast.StarExpr); ok {
		ptr, recv = "*", star.X
	}
	switch t := recv.(type) {
	case *ast.IndexExpr:
		recv = t.X
	case *ast.IndexListExpr:
		recv = t.X
	}
	return fmt.Sprintf("(%s%s).%s", ptr, types.ExprString(recv), fn.Name.Name)
}

// callees lists the distinct call targets in body as they are written,
// sorted. It is syntactic: a method value and a package function look the
// same ("x.F"); the deterministic analysis, not this, decides what a call
// reaches.
func callees(body *ast.BlockStmt) []string {
	if body == nil {
		return nil
	}
	seen := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			fun := call.Fun
			// A generic instantiation or a parenthesized callee names the
			// same function.
			for {
				switch f := fun.(type) {
				case *ast.ParenExpr:
					fun = f.X
					continue
				case *ast.IndexExpr:
					fun = f.X
					continue
				case *ast.IndexListExpr:
					fun = f.X
					continue
				}
				break
			}
			switch f := fun.(type) {
			case *ast.Ident:
				seen[f.Name] = true
			case *ast.SelectorExpr:
				// "pkg.F" and "v.M" as written; a call on any other
				// expression ("a.b().M()") is "_.M".
				if _, ok := f.X.(*ast.Ident); ok {
					seen[types.ExprString(f)] = true
				} else {
					seen["_."+f.Sel.Name] = true
				}
			}
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Lookup finds the declaration the diff name refers to. A closure name
// ("F$1", "(*T).M$2$1") resolves to its enclosing declaration, and a type
// argument list ("F[int]") is ignored. The note says when the declaration
// shown is not exactly the function asked for.
func (idx *SourceIndex) Lookup(name string) (fn *sourceFunc, note string, ok bool) {
	if idx == nil {
		return nil, "", false
	}
	key := name
	if i := strings.Index(key, "$"); i >= 0 {
		key = key[:i]
	}
	key = stripTypeArgs(key)
	fn, ok = idx.byName[key]
	if !ok {
		return nil, "", false
	}
	if key != name {
		note = fmt.Sprintf("%s is inside %s; showing the whole declaration.", name, key)
	}
	return fn, note, true
}

// stripTypeArgs removes a trailing instantiation from a name: "F[int]" and
// "(*T[int]).M" become "F" and "(*T).M".
func stripTypeArgs(name string) string {
	var b strings.Builder
	depth := 0
	for _, r := range name {
		switch r {
		case '[':
			depth++
			continue
		case ']':
			if depth > 0 {
				depth--
				continue
			}
		}
		if depth == 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Source returns fn's declaration, each line prefixed with its number.
func (idx *SourceIndex) Source(fn *sourceFunc) string {
	return idx.Lines(fn.Start, fn.End)
}

// Lines returns the lines from first to last (1-based, inclusive, clamped
// to the file), each prefixed with its number.
func (idx *SourceIndex) Lines(first, last int) string {
	if idx == nil || len(idx.lines) == 0 {
		return ""
	}
	if first < 1 {
		first = 1
	}
	if last > len(idx.lines) {
		last = len(idx.lines)
	}
	var b strings.Builder
	for i := first; i <= last; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, idx.lines[i-1])
	}
	return b.String()
}

// LineCount is the number of lines in the file.
func (idx *SourceIndex) LineCount() int {
	if idx == nil {
		return 0
	}
	return len(idx.lines)
}

// Functions lists the declarations in file order.
func (idx *SourceIndex) Functions() []*sourceFunc {
	if idx == nil {
		return nil
	}
	return idx.funcs
}

// Callers lists the declarations in this file whose body calls name: a
// function by its name, a method by its method name through any receiver.
// Syntactic, like Callees.
func (idx *SourceIndex) Callers(name string) []string {
	if idx == nil {
		return nil
	}
	key := stripTypeArgs(name)
	if i := strings.Index(key, "$"); i >= 0 {
		key = key[:i]
	}
	method := ""
	if strings.HasPrefix(key, "(") {
		if i := strings.LastIndex(key, ")."); i >= 0 {
			method = key[i+2:]
		}
	}
	var out []string
	for _, fn := range idx.funcs {
		for _, c := range fn.Callees {
			if c == key || (method != "" && strings.HasSuffix(c, "."+method)) {
				out = append(out, fn.Name)
				break
			}
		}
	}
	return out
}
