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
// Closures, including range-over-func loop bodies, are fingerprinted and
// diffed as functions of their own, so their calls are attributed to them,
// not to the enclosing function.
func collectCallTargets(fn *ssa.Function, t *FunctionTopology) {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				callee, ok := (*op).(*ssa.Function)
				if !ok || callee.Parent() != nil {
					continue
				}
				recordCallTarget(t, callee)
			}
		}
	}
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
	if IsVerificationCall(pkgPath, recv, name) {
		t.Checks[key] = true
	}
}

// IsVerificationCall reports whether a callee, identified like
// ClassifyCallTarget's arguments, is a verification primitive: a constant-time
// or MAC comparison, a signature or certificate check, a password hash
// comparison, or a path containment check.
func IsVerificationCall(pkgPath, recv, name string) bool {
	switch pkgPath {
	case "crypto/subtle":
		return strings.HasPrefix(name, "ConstantTime")
	case "crypto/hmac":
		return name == "Equal"
	case "crypto/ed25519", "crypto/ecdsa", "crypto/rsa":
		return strings.HasPrefix(name, "Verify")
	case "crypto/x509":
		return (recv == "Certificate" || recv == "CertificateRequest") &&
			(strings.HasPrefix(name, "Verify") || name == "CheckSignature" || name == "CheckSignatureFrom")
	case "crypto/tls":
		return recv == "Conn" && name == "VerifyHostname"
	case "golang.org/x/crypto/bcrypt":
		return name == "CompareHashAndPassword"
	case "path/filepath":
		return name == "IsLocal"
	}
	return false
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
		switch recv {
		case "":
			switch name {
			case "StartProcess":
				return CapExec
			case "CopyFS":
				return CapFilesystem
			}
			if isFilesystemMutation(name) {
				return CapFilesystem
			}
		case "Root":
			// os.Root confines paths to a directory but still mutates it.
			if isFilesystemMutation(name) {
				return CapFilesystem
			}
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
	case "crypto/tls", "net/rpc", "net/rpc/jsonrpc", "net/smtp", "net/textproto", "log/syslog":
		if hasAnyPrefix(name, "Dial", "Listen") || name == "SendMail" {
			return CapNetwork
		}
	case "net/http/httptest":
		// The server constructors open a listening socket.
		switch name {
		case "NewServer", "NewTLSServer", "NewUnstartedServer":
			return CapNetwork
		}
	case "net/http/httputil":
		// A reverse proxy forwards each request it serves to its target.
		if recv == "ReverseProxy" && name == "ServeHTTP" {
			return CapNetwork
		}
	case "net/http/cgi":
		// cgi.Handler runs Path as a child process for every request.
		if recv == "Handler" && name == "ServeHTTP" {
			return CapExec
		}
	case "reflect":
		if recv == "Value" && (name == "Call" || name == "CallSlice") {
			return CapReflection
		}
	}
	return ""
}

// isFilesystemMutation reports whether an os function or os.Root method of
// this name creates, writes, removes, renames or changes the metadata of a
// file.
func isFilesystemMutation(name string) bool {
	switch name {
	case "WriteFile", "Create", "OpenFile", "Remove", "RemoveAll", "Rename",
		"Chmod", "Chown", "Lchown", "Truncate", "Symlink", "Link":
		return true
	}
	return false
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
