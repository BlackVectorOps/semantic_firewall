package topology

import (
	"go/constant"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// TLS protocol versions (crypto/tls.VersionTLS10 ...) and client
// authentication modes, as the constants a store writes.
const (
	tlsVersion12               = 0x0303
	tlsRequireAndVerifyCert    = 4 // tls.RequireAndVerifyClientCert
	httpSameSiteNoneMode       = 4 // http.SameSiteNoneMode
	settingInsecureIgnoreHosts = "golang.org/x/crypto/ssh.InsecureIgnoreHostKey()"
)

var tlsVersionNames = map[int64]string{0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1"}

// collectSecuritySettings records constant stores to security-sensitive
// configuration fields and calls that disable a check:
//   - t.WeakSettings gets a setting that weakens security on its own:
//     tls.Config.InsecureSkipVerify = true, tls.Config.MinVersion or
//     MaxVersion below TLS 1.2, http.Cookie.SameSite = SameSiteNoneMode, and
//     a call to ssh.InsecureIgnoreHostKey;
//   - t.SecureSettings gets a setting whose removal weakens security:
//     http.Cookie.Secure or HttpOnly = true, and tls.Config.ClientAuth =
//     RequireAndVerifyClientCert.
//
// Settings are written as "crypto/tls.Config.InsecureSkipVerify=true".
// A non-constant value records nothing.
func collectSecuritySettings(fn *ssa.Function, t *FunctionTopology) {
	weak := func(s string) {
		if t.WeakSettings == nil {
			t.WeakSettings = make(map[string]bool)
		}
		t.WeakSettings[s] = true
	}
	secure := func(s string) {
		if t.SecureSettings == nil {
			t.SecureSettings = make(map[string]bool)
		}
		t.SecureSettings[s] = true
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			switch i := instr.(type) {
			case *ssa.Call:
				if callee := i.Call.StaticCallee(); callee != nil {
					if pkgPath, recv, name, ok := calleeIdentity(callee); ok &&
						pkgPath == "golang.org/x/crypto/ssh" && recv == "" && name == "InsecureIgnoreHostKey" {
						weak(settingInsecureIgnoreHosts)
					}
				}
			case *ssa.Store:
				addr, ok := i.Addr.(*ssa.FieldAddr)
				if !ok {
					continue
				}
				c, ok := i.Val.(*ssa.Const)
				if !ok || c.Value == nil {
					continue
				}
				owner, field := structField(addr)
				key := owner + "." + field
				switch owner {
				case "crypto/tls.Config":
					switch field {
					case "InsecureSkipVerify":
						if c.Value.Kind() == constant.Bool && constant.BoolVal(c.Value) {
							weak(key + "=true")
						}
					case "MinVersion", "MaxVersion":
						if v := intConst(c); v != 0 && v < tlsVersion12 {
							name := tlsVersionNames[v]
							if name == "" {
								name = c.Value.ExactString()
							}
							weak(key + "=" + name)
						}
					case "ClientAuth":
						if intConst(c) == tlsRequireAndVerifyCert {
							secure(key + "=RequireAndVerifyClientCert")
						}
					}
				case "net/http.Cookie":
					switch field {
					case "Secure", "HttpOnly":
						if c.Value.Kind() == constant.Bool && constant.BoolVal(c.Value) {
							secure(key + "=true")
						}
					case "SameSite":
						if intConst(c) == httpSameSiteNoneMode {
							weak(key + "=SameSiteNoneMode")
						}
					}
				}
			}
		}
	}
}

// intConst returns the value of an integer constant, or 0 for a constant
// of another kind (a status passed to some other WriteHeader method, say).
func intConst(c *ssa.Const) int64 {
	// A nil Value is the zero value of a type that need not be an integer:
	// nil, or an empty struct.
	if c.Value == nil || c.Value.Kind() != constant.Int {
		return 0
	}
	v, _ := constant.Int64Val(c.Value)
	return v
}

// structField returns the import-path-qualified named struct type a
// FieldAddr selects from ("crypto/tls.Config") and the field's name.
func structField(addr *ssa.FieldAddr) (owner, field string) {
	ptr, ok := addr.X.Type().Underlying().(*types.Pointer)
	if !ok {
		return "", ""
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return "", ""
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || addr.Field >= st.NumFields() {
		return "", ""
	}
	return named.Obj().Pkg().Path() + "." + named.Obj().Name(), st.Field(addr.Field).Name()
}
