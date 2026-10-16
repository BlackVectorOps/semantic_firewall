package topology

import (
	"go/constant"
	"go/types"
	"slices"
	"strings"

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
// configuration fields and references to functions that disable a check:
//   - t.WeakSettings gets a setting that weakens security on its own:
//     tls.Config.InsecureSkipVerify = true, tls.Config.MinVersion or
//     MaxVersion below TLS 1.2, http.Cookie.SameSite = SameSiteNoneMode, and
//     ssh.InsecureIgnoreHostKey, called or taken as a value;
//   - t.SecureSettings gets a setting whose removal weakens security:
//     http.Cookie.Secure or HttpOnly = true, and tls.Config.ClientAuth =
//     RequireAndVerifyClientCert. It counts only when no store in the
//     function writes a weaker constant to that field, and every cookie or
//     config the function allocates gets it, itself or from a helper it is
//     passed to: a second cookie without Secure is not hidden by a first one
//     with it. Settings a helper of the same package returns, up to
//     maxSettingsHelperDepth calls deep, count as the caller's, so moving a
//     cookie's construction into a helper keeps them.
//
// Settings are written as "crypto/tls.Config.InsecureSkipVerify=true".
// A non-constant value records nothing. The fields are those of the
// declared types, also when reached through a defined type over them.
func collectSecuritySettings(fn *ssa.Function, t *FunctionTopology) {
	m := &settingsMemo{secure: make(map[reachKey]map[string]struct{}), scans: make(map[*ssa.Function]*settingsScan)}
	for k := range m.scan(fn).weak {
		if t.WeakSettings == nil {
			t.WeakSettings = make(map[string]bool)
		}
		t.WeakSettings[k] = true
	}
	for k := range m.secureSettings(fn, maxSettingsHelperDepth) {
		if t.SecureSettings == nil {
			t.SecureSettings = make(map[string]bool)
		}
		t.SecureSettings[k] = true
	}
}

// maxSettingsHelperDepth bounds how far secureSettings follows helpers.
const maxSettingsHelperDepth = 3

// settingsMemo holds what one function's settings search has learned.
type settingsMemo struct {
	secure map[reachKey]map[string]struct{}
	scans  map[*ssa.Function]*settingsScan
}

func (m *settingsMemo) scan(fn *ssa.Function) *settingsScan {
	s, ok := m.scans[fn]
	if !ok {
		s = scanSettings(fn)
		m.scans[fn] = s
	}
	return s
}

// settingsScan is what one function body does to security settings.
type settingsScan struct {
	weak     map[string]struct{}
	stored   map[ssa.Value]map[string]bool  // secure settings stored, by struct pointer
	weakened map[string]bool                // secure settings some store writes weaker
	allocs   map[string][]*ssa.Alloc        // allocated cookies and configs, by owner type
	passed   map[*ssa.Alloc][]*ssa.Function // the helpers each allocation is passed to
	helpers  []*ssa.Function                // the package's functions the body calls
}

func scanSettings(fn *ssa.Function) *settingsScan {
	s := &settingsScan{
		weak:     make(map[string]struct{}),
		stored:   make(map[ssa.Value]map[string]bool),
		weakened: make(map[string]bool),
		allocs:   make(map[string][]*ssa.Alloc),
		passed:   make(map[*ssa.Alloc][]*ssa.Function),
	}
	pkg := pkgOf(fn)
	var ops []*ssa.Value
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			ops = instr.Operands(ops[:0])
			for _, op := range ops {
				if callee, ok := (*op).(*ssa.Function); ok {
					if pkgPath, recv, name, _ := calleeIdentity(callee); pkgPath == "golang.org/x/crypto/ssh" && recv == "" && name == "InsecureIgnoreHostKey" {
						s.weak[settingInsecureIgnoreHosts] = struct{}{}
					}
				}
			}
			switch i := instr.(type) {
			case *ssa.Alloc:
				if owner := settingsOwner(i.Type().(*types.Pointer).Elem()); owner != "" {
					s.allocs[owner] = append(s.allocs[owner], i)
				}
			case *ssa.Call:
				callee := i.Call.StaticCallee()
				if callee == nil || callee.Parent() != nil || pkg == nil || pkgOf(callee) != pkg || len(callee.Blocks) == 0 {
					continue
				}
				if !slices.Contains(s.helpers, callee) {
					s.helpers = append(s.helpers, callee)
				}
				for _, arg := range i.Call.Args {
					if a, ok := arg.(*ssa.Alloc); ok {
						s.passed[a] = append(s.passed[a], callee)
					}
				}
			case *ssa.Store:
				if addr, ok := i.Addr.(*ssa.FieldAddr); ok {
					if c, ok := i.Val.(*ssa.Const); ok && c.Value != nil {
						s.store(addr, c)
					}
				}
			}
		}
	}
	return s
}

// store records a constant stored to a field.
func (s *settingsScan) store(addr *ssa.FieldAddr, c *ssa.Const) {
	owner, field := structField(addr)
	key := owner + "." + field
	secure := func(setting string, set bool) {
		if set {
			if s.stored[addr.X] == nil {
				s.stored[addr.X] = make(map[string]bool)
			}
			s.stored[addr.X][setting] = true
		} else {
			s.weakened[setting] = true
		}
	}
	switch owner {
	case "crypto/tls.Config":
		switch field {
		case "InsecureSkipVerify":
			if c.Value.Kind() == constant.Bool && constant.BoolVal(c.Value) {
				s.weak[key+"=true"] = struct{}{}
			}
		case "MinVersion", "MaxVersion":
			if v := intConst(c); v != 0 && v < tlsVersion12 {
				name := tlsVersionNames[v]
				if name == "" {
					name = c.Value.ExactString()
				}
				s.weak[key+"="+name] = struct{}{}
			}
		case "ClientAuth":
			secure(key+"=RequireAndVerifyClientCert", intConst(c) == tlsRequireAndVerifyCert)
		}
	case "net/http.Cookie":
		switch field {
		case "Secure", "HttpOnly":
			secure(key+"=true", c.Value.Kind() == constant.Bool && constant.BoolVal(c.Value))
		case "SameSite":
			if intConst(c) == httpSameSiteNoneMode {
				s.weak[key+"=SameSiteNoneMode"] = struct{}{}
			}
		}
	}
}

// secureSettings returns the secure settings of fn (see
// collectSecuritySettings), following helpers depth calls deep.
func (m *settingsMemo) secureSettings(fn *ssa.Function, depth int) map[string]struct{} {
	key := reachKey{fn: fn, depth: depth}
	if settings, ok := m.secure[key]; ok {
		return settings
	}
	s := m.scan(fn)
	helperSettings := func(h *ssa.Function) map[string]struct{} {
		if depth <= 0 {
			return nil
		}
		return m.secureSettings(h, depth-1)
	}
	// keeps reports whether a setting holds for everything fn configures.
	keeps := func(setting string) bool {
		if s.weakened[setting] {
			return false
		}
		owner := setting[:strings.LastIndex(setting[:strings.Index(setting, "=")], ".")]
		for _, a := range s.allocs[owner] {
			if s.stored[a][setting] {
				continue
			}
			if !slices.ContainsFunc(s.passed[a], func(h *ssa.Function) bool { _, ok := helperSettings(h)[setting]; return ok }) {
				return false
			}
		}
		return true
	}
	settings := make(map[string]struct{})
	for _, stored := range s.stored {
		for setting := range stored {
			if keeps(setting) {
				settings[setting] = struct{}{}
			}
		}
	}
	for _, h := range s.helpers {
		for setting := range helperSettings(h) {
			if keeps(setting) {
				settings[setting] = struct{}{}
			}
		}
	}
	m.secure[key] = settings
	return settings
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
// FieldAddr selects from ("crypto/tls.Config") and the field's name. A
// defined type over another package's struct (type cfg tls.Config) has
// that struct's fields: the owner is the type the field was declared in.
func structField(addr *ssa.FieldAddr) (owner, field string) {
	ptr, ok := addr.X.Type().Underlying().(*types.Pointer)
	if !ok {
		return "", ""
	}
	st, ok := ptr.Elem().Underlying().(*types.Struct)
	if !ok || addr.Field >= st.NumFields() {
		return "", ""
	}
	f := st.Field(addr.Field)
	return declaringType(ptr.Elem(), st, f), f.Name()
}

// settingsOwner returns the owner name of a cookie or TLS config type, or
// "" for any other type.
func settingsOwner(t types.Type) string {
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return ""
	}
	switch owner := declaringType(t, st, st.Field(0)); owner {
	case "crypto/tls.Config", "net/http.Cookie":
		return owner
	}
	return ""
}

// declaringType returns the import-path-qualified name of the named type
// whose underlying struct st, holding field f, was declared: t itself when
// it is declared with f's package, otherwise the type of that package with
// the same underlying struct.
func declaringType(t types.Type, st *types.Struct, f *types.Var) string {
	if f.Pkg() == nil {
		return ""
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		// An unnamed struct cannot have another package's fields.
		return ""
	}
	if named.Obj().Pkg() == f.Pkg() {
		return f.Pkg().Path() + "." + named.Obj().Name()
	}
	scope := f.Pkg().Scope()
	for _, name := range scope.Names() {
		if tn, ok := scope.Lookup(name).(*types.TypeName); ok && !tn.IsAlias() && tn.Type().Underlying() == st {
			return f.Pkg().Path() + "." + name
		}
	}
	return ""
}
