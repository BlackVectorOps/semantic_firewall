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
//
// Capabilities the body can reach without naming them are recorded too, as
// targets of their own: the methods of a value converted to an interface,
// or passed as a type argument, that the interface or the constraint
// declares (an exec.Cmd run through `interface{ Run() error }`), and an
// interface method that is a capability whatever implements it
// (http.RoundTripper's RoundTrip).
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
			switch v := instr.(type) {
			case *ssa.MakeInterface:
				recordInterfaceTargets(fn.Prog, t, v.X.Type(), v.Type())
			case ssa.CallInstruction:
				common := v.Common()
				if common.IsInvoke() {
					if named, ok := types.Unalias(common.Value.Type()).(*types.Named); ok && named.Obj().Pkg() != nil {
						recordCapabilityTarget(t, named.Obj().Pkg().Path(), named.Obj().Name(), common.Method.Name())
					}
				} else if callee := common.StaticCallee(); callee != nil {
					params := callee.TypeParams()
					for i, arg := range callee.TypeArgs() {
						recordInterfaceTargets(fn.Prog, t, arg, params.At(i).Constraint())
					}
				}
			}
		}
	}
}

// recordInterfaceTargets records the capability methods of concrete that
// iface declares: once a value is converted to iface, or passed for a type
// parameter iface constrains, the code can call them through it.
func recordInterfaceTargets(prog *ssa.Program, t *FunctionTopology, concrete, iface types.Type) {
	// A conversion's target and a constraint are interfaces, and concrete
	// has the methods they declare.
	it := iface.Underlying().(*types.Interface)
	if it.NumMethods() == 0 || types.IsInterface(concrete) {
		return
	}
	mset := prog.MethodSets.MethodSet(concrete)
	for i := 0; i < it.NumMethods(); i++ {
		m := it.Method(i)
		pkgPath, recv, name := funcIdentity(mset.Lookup(m.Pkg(), m.Name()).Obj().(*types.Func))
		recordCapabilityTarget(t, pkgPath, recv, name)
	}
}

// recordCapabilityTarget records a callee the body reaches without naming
// it, when it is a capability.
func recordCapabilityTarget(t *FunctionTopology, pkgPath, recv, name string) {
	if class := ClassifyCallTarget(pkgPath, recv, name); class != "" {
		key := callTargetKey(pkgPath, recv, name)
		t.CallTargets[key]++
		t.Capabilities[key] = class
	}
}

func recordCallTarget(t *FunctionTopology, callee *ssa.Function) {
	pkgPath, recv, name, ok := calleeIdentity(callee)
	if !ok {
		return
	}
	key := callTargetKey(pkgPath, recv, name)
	t.CallTargets[key]++
	if class := ClassifyCallTarget(pkgPath, recv, name); class != "" {
		t.Capabilities[key] = class
	}
}

// calleeIdentity returns the import path, receiver type name ("" for a
// package-level function) and name a call target is classified by. ok is
// false for a package initializer: those are import side effects, not
// behaviour of the function that triggers them, and counting them would turn
// every new import into a "new call".
func calleeIdentity(callee *ssa.Function) (pkgPath, recv, name string, ok bool) {
	if callee.Name() == "init" && callee.Signature.Recv() == nil {
		return "", "", "", false
	}
	// Object() resolves generic instantiations and bound/thunk wrappers back
	// to the declared function, so "(*T).M$bound" is recorded as "(T).M".
	if obj, isFunc := callee.Object().(*types.Func); isFunc {
		pkgPath, recv, name = funcIdentity(obj)
	} else {
		name = callee.Name()
		if callee.Pkg != nil && callee.Pkg.Pkg != nil {
			pkgPath = callee.Pkg.Pkg.Path()
		}
	}
	return pkgPath, recv, name, true
}

// funcIdentity returns the import path, receiver type name and name of a
// declared function or method.
func funcIdentity(obj *types.Func) (pkgPath, recv, name string) {
	if obj.Pkg() != nil {
		pkgPath = obj.Pkg().Path()
	}
	if recvVar := obj.Type().(*types.Signature).Recv(); recvVar != nil {
		recv = receiverTypeName(recvVar.Type())
	}
	return pkgPath, recv, obj.Name()
}

// callTargetKey is the CallTargets key of a callee: "os/exec.Command",
// "(net/http.Client).Do".
func callTargetKey(pkgPath, recv, name string) string {
	if recv != "" {
		return "(" + pkgPath + "." + recv + ")." + name
	}
	return pkgPath + "." + name
}

// IsVerificationCall reports whether a callee, identified like
// ClassifyCallTarget's arguments, is a verification primitive: a constant-time
// or MAC comparison, a signature or certificate check, a password hash
// comparison, or a path containment check.
func IsVerificationCall(pkgPath, recv, name string) bool {
	switch pkgPath {
	case "crypto/subtle":
		// The comparisons; ConstantTimeCopy and ConstantTimeSelect compare
		// nothing.
		switch name {
		case "ConstantTimeCompare", "ConstantTimeEq", "ConstantTimeByteEq", "ConstantTimeLessOrEq":
			return true
		}
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
	// A method may be declared on an alias of its type.
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
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
		// LookPath searches PATH and runs nothing.
		if recv == "" && name == "LookPath" {
			return ""
		}
		return CapExec
	case "io/ioutil":
		switch name {
		case "WriteFile", "TempFile", "TempDir":
			return CapFilesystem
		}
	case "os":
		switch recv {
		case "File":
			// An open file's metadata, whatever mode it was opened in.
			switch name {
			case "Chmod", "Chown", "Truncate":
				return CapFilesystem
			}
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
		if recv != "" || syscallHelpers[name] {
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
		case "", "Client", "Server", "Transport", "RoundTripper":
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
		// MethodByName and Method return a method as a func value the code
		// can call without Call.
		if recv == "Value" && (name == "Call" || name == "CallSlice" || name == "MethodByName" || name == "Method") {
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
	case "WriteFile", "Create", "CreateTemp", "OpenFile", "Remove", "RemoveAll", "Rename",
		"Chmod", "Chown", "Lchown", "Chtimes", "Truncate", "Symlink", "Link",
		"Mkdir", "MkdirAll", "MkdirTemp":
		return true
	}
	return false
}

// syscallHelpers are the functions of syscall, x/sys/unix and x/sys/windows
// that convert or compute and make no system call.
var syscallHelpers = map[string]bool{
	"BytePtrFromString": true, "ByteSliceFromString": true, "StringBytePtr": true, "StringByteSlice": true,
	"BytePtrToString": true, "ByteSliceToString": true,
	"UTF16FromString": true, "UTF16PtrFromString": true, "UTF16ToString": true, "UTF16PtrToString": true,
	"StringToUTF16": true, "StringToUTF16Ptr": true,
	"NsecToTimespec": true, "NsecToTimeval": true, "TimespecToNsec": true, "TimevalToNsec": true,
	"NsecToFiletime": true, "Getpagesize": true, "CmsgLen": true, "CmsgSpace": true,
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// CalleeCapability returns the CallTargets key of a callee and its
// capability class ("" when it has none). ok is false for a package
// initializer, which is not a call target.
func CalleeCapability(callee *ssa.Function) (key, class string, ok bool) {
	pkgPath, recv, name, ok := calleeIdentity(callee)
	if !ok {
		return "", "", false
	}
	return callTargetKey(pkgPath, recv, name), ClassifyCallTarget(pkgPath, recv, name), true
}
