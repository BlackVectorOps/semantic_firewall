package topology

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Capability classes name the families of security-sensitive operations a
// function can reach. Risk scoring treats the first appearance of a class in
// a function as an escalation, independent of how many calls changed.
const (
	CapExec       = "exec"
	CapSyscall    = "syscall"
	CapPlugin     = "plugin"
	CapNetwork    = "network"
	CapReflection = "reflection"
	CapFilesystem = "filesystem"
)

// collectCallTargets records every function the body calls or references as a
// value, keyed by its fully qualified name ("os/exec.Command",
// "(net/http.Client).Do"). Unlike CallSignatures, which keys on the package
// *name* for signature-matching stability, these keys carry the import path so
// that "crypto/rand.Read" and "math/rand.Read" stay distinct.
//
// Closures are fingerprinted and diffed as functions of their own, so their
// calls are not attributed to the enclosing function -- with one exception:
// the synthetic bodies x/tools creates for range-over-func loops are never
// reported separately, so their calls are folded in here to keep them visible.
func collectCallTargets(fn *ssa.Function, t *FunctionTopology) {
	visited := map[*ssa.Function]bool{fn: true}
	var walk func(f *ssa.Function)
	walk = func(f *ssa.Function) {
		for _, block := range f.Blocks {
			for _, instr := range block.Instrs {
				for _, op := range instr.Operands(nil) {
					if op == nil || *op == nil {
						continue
					}
					callee, ok := (*op).(*ssa.Function)
					if !ok {
						continue
					}
					if callee.Parent() != nil {
						if callee.Synthetic != "" && !visited[callee] {
							visited[callee] = true
							walk(callee)
						}
						continue
					}
					recordCallTarget(t, callee)
				}
			}
		}
	}
	walk(fn)
}

func recordCallTarget(t *FunctionTopology, callee *ssa.Function) {
	// Package initializers are import side effects, not behaviour of the
	// function that triggers them; counting them turns every new import into
	// a "new call".
	if callee.Name() == "init" && callee.Signature.Recv() == nil {
		return
	}

	var pkgPath, recv, name string
	// Object() resolves generic instantiations and bound/thunk wrappers back
	// to the declared function, so "(*T).M$bound" is recorded as "(T).M".
	if obj, ok := callee.Object().(*types.Func); ok {
		name = obj.Name()
		if obj.Pkg() != nil {
			pkgPath = obj.Pkg().Path()
		}
		if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
			recv = receiverTypeName(sig.Recv().Type())
		}
	} else {
		name = callee.Name()
		if callee.Pkg != nil && callee.Pkg.Pkg != nil {
			pkgPath = callee.Pkg.Pkg.Path()
		}
	}

	key := pkgPath + "." + name
	if recv != "" {
		key = "(" + pkgPath + "." + recv + ")." + name
	}
	t.CallTargets[key]++
	if class := ClassifyCallTarget(pkgPath, recv, name); class != "" {
		t.Capabilities[key] = class
	}
}

func receiverTypeName(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return t.String()
}

// ClassifyCallTarget maps a callee, identified by import path, receiver type
// name ("" for package-level functions) and function name, to its capability
// class, or "" when the callee is not security-sensitive.
func ClassifyCallTarget(pkgPath, recv, name string) string {
	switch pkgPath {
	case "os/exec":
		return CapExec
	case "os":
		if recv != "" {
			return ""
		}
		switch name {
		case "StartProcess":
			return CapExec
		case "WriteFile", "Create", "OpenFile", "Remove", "RemoveAll", "Rename",
			"Chmod", "Chown", "Lchown", "Truncate", "Symlink", "Link":
			return CapFilesystem
		}
	case "syscall", "golang.org/x/sys/unix", "golang.org/x/sys/windows":
		// Methods are on value types like Errno and Signal; only the raw
		// entry points are capabilities.
		if recv != "" {
			return ""
		}
		switch name {
		case "Exec", "ForkExec", "StartProcess":
			return CapExec
		}
		return CapSyscall
	case "plugin":
		return CapPlugin
	case "net":
		if hasAnyPrefix(name, "Dial", "Listen", "Lookup", "Resolve", "File") {
			return CapNetwork
		}
	case "net/http":
		switch recv {
		case "", "Client", "Server", "Transport":
			switch name {
			case "Get", "Post", "PostForm", "Head", "Do", "RoundTrip",
				"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
				return CapNetwork
			}
		}
	case "crypto/tls", "net/rpc", "net/rpc/jsonrpc", "net/smtp", "net/textproto":
		if hasAnyPrefix(name, "Dial", "Listen") || name == "SendMail" {
			return CapNetwork
		}
	case "reflect":
		if recv == "Value" && (name == "Call" || name == "CallSlice") {
			return CapReflection
		}
	}
	return ""
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
