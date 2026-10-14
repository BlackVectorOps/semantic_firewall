// Command mutate runs mutation testing over the lines a branch changed: it
// applies one small fault at a time (an operator flipped, a condition forced,
// a statement removed) to the Go files changed since a base commit, runs the
// tests of the mutated file's package, and reports every mutant the tests do
// not catch.
//
//	go run ./tools/mutate -base origin/main [-workers 3] [-pkgs ./pkg/...] [-run regexp]
//
// A mutant that does not compile is not counted. A surviving mutant is
// either a missing test or code whose effect no test can observe (dead,
// redundant or performance-only); each one needs one or the other answer.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type mutant struct {
	file   string // module-relative
	line   int
	kind   string
	start  int // byte offsets of the replaced span
	end    int
	repl   string
	status string
	detail string
}

func main() {
	base := flag.String("base", "origin/main", "base commit; only lines changed since it are mutated")
	workers := flag.Int("workers", 2, "mutants tested in parallel")
	pkgs := flag.String("pkgs", "", "comma-separated package patterns whose files to mutate (default: every changed non-test Go file)")
	run := flag.String("run", "", "go test -run regexp")
	timeout := flag.Duration("timeout", 3*time.Minute, "per-mutant test timeout; a mutant that hangs the tests counts as caught")
	only := flag.String("files", "", "regexp: mutate only matching files")
	testPkgs := flag.String("tests", "", "comma-separated packages whose tests judge each mutant (default: the mutated file's package)")
	retest := flag.String("retest", "", "output of an earlier run: test only the mutants it reported as SURVIVED")
	list := flag.Bool("list", false, "print the mutants per file and exit")
	goflags := flag.String("goflags", "", `extra go test flags for every mutant, e.g. "-race -shuffle=on"; -race turns cgo on`)
	exclude := flag.String("exclude", `(_test\.go|^tools/|^testdata/|/testdata/|^internal/actiontest/)`, "regexp of files not to mutate")
	flag.Parse()

	root, err := os.Getwd()
	check(err)
	changed := changedLines(*base)
	ex := regexp.MustCompile(*exclude)
	in := regexp.MustCompile(*only)
	var files []string
	for f := range changed {
		if strings.HasSuffix(f, ".go") && !ex.MatchString(f) && in.MatchString(f) && inPatterns(f, *pkgs) {
			if _, err := os.Stat(f); err == nil {
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)

	var mutants []*mutant
	for _, f := range files {
		mutants = append(mutants, findMutants(f, changed[f])...)
	}
	if *retest != "" {
		mutants = onlySurvivors(mutants, *retest)
	}
	fmt.Printf("%d mutants in %d files\n", len(mutants), len(files))
	if *list {
		perFile := map[string]int{}
		for _, m := range mutants {
			perFile[m.file]++
		}
		for _, f := range files {
			fmt.Printf("%6d %s\n", perFile[f], f)
		}
		return
	}

	// One copy of the module per worker, so mutants run in parallel without
	// touching the working tree. The copies go when the run ends or is
	// interrupted.
	tmp, err := os.MkdirTemp("", "mutate-")
	check(err)
	defer os.RemoveAll(tmp)
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupted
		os.RemoveAll(tmp)
		os.Exit(130)
	}()
	copies := make(chan string, *workers)
	for i := 0; i < *workers; i++ {
		dir := filepath.Join(tmp, strconv.Itoa(i))
		cmd := exec.Command("cp", "-a", root+"/.", dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fail("copying the module: %v\n%s", err, out)
		}
		copies <- dir
	}

	// Every test command must pass on the unmutated code; otherwise each
	// mutant would "fail" for a reason of its own (a flag the platform does
	// not support, a broken test) and count as caught.
	cfg := testConfig{run: *run, testPkgs: *testPkgs, goflags: *goflags, timeout: *timeout}
	baseline := <-copies
	seen := map[string]bool{}
	for _, m := range mutants {
		pkgs := cfg.packages(m)
		key := strings.Join(pkgs, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		if out, err := cfg.goTest(baseline, pkgs); err != nil {
			fail("the tests fail without any mutation (%s); fix them or the flags first:\n%s", key, out)
		}
	}
	copies <- baseline

	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for _, m := range mutants {
		wg.Add(1)
		go func(m *mutant) {
			defer wg.Done()
			dir := <-copies
			defer func() { copies <- dir }()
			m.status, m.detail = cfg.test(dir, m)
			mu.Lock()
			done++
			if m.status == "SURVIVED" || m.status == "ERROR" {
				fmt.Printf("[%d/%d] %s %s:%d %s\n", done, len(mutants), m.status, m.file, m.line, m.kind)
			}
			mu.Unlock()
		}(m)
	}
	wg.Wait()

	counts := map[string]int{}
	for _, m := range mutants {
		counts[m.status]++
	}
	fmt.Printf("\nkilled %d, survived %d, not compiling %d, timed out %d, errors %d\n",
		counts["KILLED"], counts["SURVIVED"], counts["NOCOMPILE"], counts["TIMEOUT"], counts["ERROR"])
	sort.Slice(mutants, func(i, j int) bool {
		if mutants[i].file != mutants[j].file {
			return mutants[i].file < mutants[j].file
		}
		return mutants[i].line < mutants[j].line
	})
	for _, m := range mutants {
		if m.status == "SURVIVED" {
			fmt.Printf("SURVIVED %s:%d %s\n", m.file, m.line, m.kind)
		}
	}
	for _, m := range mutants {
		if m.status == "ERROR" {
			fmt.Printf("ERROR %s:%d %s\n%s\n", m.file, m.line, m.kind, m.detail)
		}
	}
	if counts["SURVIVED"] > 0 || counts["ERROR"] > 0 {
		os.Exit(1)
	}
}

// testConfig is how every mutant, and the baseline, is tested.
type testConfig struct {
	run, testPkgs, goflags string
	timeout                time.Duration
}

// packages returns the packages whose tests judge m.
func (c testConfig) packages(m *mutant) []string {
	if c.testPkgs != "" {
		return strings.Split(c.testPkgs, ",")
	}
	return []string{"./" + filepath.Dir(m.file)}
}

// goTest runs the tests of pkgs in dir.
func (c testConfig) goTest(dir string, pkgs []string) ([]byte, error) {
	// -vet=off: a mutant that only trips a vet check (unreachable code after
	// a removed statement) is not caught by a test. -failfast: one failure
	// is a verdict.
	args := []string{"test", "-count=1", "-vet=off", "-failfast", "-timeout", c.timeout.String()}
	args = append(args, strings.Fields(c.goflags)...)
	if c.run != "" {
		args = append(args, "-run", c.run)
	}
	return goCmd(dir, c.timeout, strings.Contains(" "+c.goflags+" ", " -race "), append(args, pkgs...)...)
}

// testFailed matches go test output that reports a failing or crashing test.
var testFailed = regexp.MustCompile(`(?m)^(--- FAIL|FAIL\s|panic: )`)

// test applies m in dir, runs the tests, and restores the file. A mutant
// is KILLED only when a test reports a failure; a go command that fails for
// another reason is an ERROR, not a catch.
func (c testConfig) test(dir string, m *mutant) (string, string) {
	path := filepath.Join(dir, m.file)
	orig, err := os.ReadFile(path)
	check(err)
	defer os.WriteFile(path, orig, 0o644)
	mutated := append(append(append([]byte{}, orig[:m.start]...), m.repl...), orig[m.end:]...)
	check(os.WriteFile(path, mutated, 0o644))

	out, err := c.goTest(dir, c.packages(m))
	switch {
	case err == context.DeadlineExceeded || bytes.Contains(out, []byte("panic: test timed out")):
		return "TIMEOUT", ""
	case err != nil && (bytes.Contains(out, []byte("[build failed]")) || bytes.Contains(out, []byte("[setup failed]"))):
		return "NOCOMPILE", string(out)
	case err != nil && testFailed.Match(out):
		return "KILLED", ""
	case err != nil:
		return "ERROR", string(out)
	}
	return "SURVIVED", ""
}

func goCmd(dir string, timeout time.Duration, cgo bool, args ...string) ([]byte, error) {
	// go test enforces the timeout itself; the context is the backstop.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	// The code under test loads with cgo off either way; the race detector
	// itself needs cgo.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if cgo {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	}
	// go test runs the test binary as a child; kill the whole group, so a
	// mutant that hangs leaves nothing running.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, context.DeadlineExceeded
	}
	return out, err
}

// onlySurvivors keeps the mutants an earlier run's output reported as
// "SURVIVED file:line kind".
func onlySurvivors(ms []*mutant, report string) []*mutant {
	data, err := os.ReadFile(report)
	check(err)
	want := map[string]int{}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "SURVIVED ") {
			want[strings.TrimPrefix(l, "SURVIVED ")]++
		}
	}
	var out []*mutant
	for _, m := range ms {
		key := fmt.Sprintf("%s:%d %s", m.file, m.line, m.kind)
		if want[key] > 0 {
			want[key]--
			out = append(out, m)
		}
	}
	return out
}

// findMutants lists the mutations of file on the given lines.
func findMutants(file string, lines map[int]bool) []*mutant {
	src, err := os.ReadFile(file)
	check(err)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
	check(err)
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	line := func(p token.Pos) int { return fset.Position(p).Line }
	var out []*mutant
	add := func(pos, end token.Pos, kind, repl string) {
		if lines[line(pos)] {
			out = append(out, &mutant{file: file, line: line(pos), kind: kind, start: off(pos), end: off(end), repl: repl})
		}
	}
	flips := map[token.Token]token.Token{
		token.EQL: token.NEQ, token.NEQ: token.EQL,
		token.LSS: token.GEQ, token.GEQ: token.LSS, token.GTR: token.LEQ, token.LEQ: token.GTR,
		token.LAND: token.LOR, token.LOR: token.LAND,
		token.ADD: token.SUB, token.SUB: token.ADD,
	}
	boundary := map[token.Token]token.Token{token.LSS: token.LEQ, token.LEQ: token.LSS, token.GTR: token.GEQ, token.GEQ: token.GTR}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if to, ok := flips[n.Op]; ok {
				add(n.OpPos, n.OpPos+token.Pos(len(n.Op.String())), "flip "+n.Op.String()+" to "+to.String(), to.String())
			}
			if to, ok := boundary[n.Op]; ok {
				add(n.OpPos, n.OpPos+token.Pos(len(n.Op.String())), "boundary "+n.Op.String()+" to "+to.String(), to.String())
			}
		case *ast.UnaryExpr:
			if n.Op == token.NOT {
				add(n.Pos(), n.X.Pos(), "drop !", "")
			}
		case *ast.Ident:
			if n.Name == "true" {
				add(n.Pos(), n.End(), "true to false", "false")
			} else if n.Name == "false" {
				add(n.Pos(), n.End(), "false to true", "true")
			}
		case *ast.IfStmt:
			add(n.Cond.Pos(), n.Cond.End(), "force if true", "true")
			add(n.Cond.Pos(), n.Cond.End(), "force if false", "false")
		case *ast.BlockStmt:
			for _, s := range n.List {
				switch s.(type) {
				case *ast.ExprStmt, *ast.AssignStmt, *ast.IncDecStmt, *ast.BranchStmt, *ast.IfStmt, *ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt:
					if a, ok := s.(*ast.AssignStmt); ok && a.Tok == token.DEFINE {
						continue // removing a declaration never compiles
					}
					add(s.Pos(), s.End(), "remove "+strings.TrimPrefix(fmt.Sprintf("%T", s), "*ast."), "")
				}
			}
		case *ast.CaseClause:
			for _, s := range n.Body {
				if _, ok := s.(*ast.ReturnStmt); ok {
					continue
				}
				if a, ok := s.(*ast.AssignStmt); ok && a.Tok == token.DEFINE {
					continue
				}
				add(s.Pos(), s.End(), "remove case statement", "")
			}
		}
		return true
	})
	return out
}

// changedLines returns, per file, the lines added or modified since base.
func changedLines(base string) map[string]map[int]bool {
	out, err := exec.Command("git", "diff", "-U0", base, "--", ".").Output()
	check(err)
	res := make(map[string]map[int]bool)
	var file string
	hunk := regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "+++ ") {
			file = strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			continue
		}
		if m := hunk.FindStringSubmatch(l); m != nil {
			start, _ := strconv.Atoi(m[1])
			n := 1
			if m[2] != "" {
				n, _ = strconv.Atoi(m[2])
			}
			if res[file] == nil {
				res[file] = make(map[int]bool)
			}
			for i := 0; i < n; i++ {
				res[file][start+i] = true
			}
		}
	}
	return res
}

func inPatterns(file, patterns string) bool {
	if patterns == "" {
		return true
	}
	for _, p := range strings.Split(patterns, ",") {
		p = strings.TrimPrefix(strings.TrimSpace(p), "./")
		if strings.HasSuffix(p, "/...") {
			if strings.HasPrefix(file, strings.TrimSuffix(p, "...")) {
				return true
			}
		} else if filepath.Dir(file) == p {
			return true
		}
	}
	return false
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mutate: "+format+"\n", args...)
	os.Exit(2)
}
