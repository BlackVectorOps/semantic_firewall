package api

import (
	"reflect"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// fileTopo is a function that calls the given capability targets ("key" ->
// class), each with the given number of guards.
func fileTopo(targets map[string]string, guards map[string]int) *topology.FunctionTopology {
	t := &topology.FunctionTopology{CallTargets: map[string]int{}, Capabilities: map[string]string{}, CapabilityGuards: guards}
	for k, class := range targets {
		t.CallTargets[k] = 1
		t.Capabilities[k] = class
	}
	return t
}

func TestAssessTopologyDelta_DeletionSignals(t *testing.T) {
	remove := map[string]string{"os.Remove": topology.CapFilesystem}
	removeAll := map[string]string{"os.RemoveAll": topology.CapFilesystem}
	removeBoth := map[string]string{"os.Remove": topology.CapFilesystem, "os.RemoveAll": topology.CapFilesystem}
	both := map[string]string{"os.Remove": topology.CapFilesystem, "net.Dial": topology.CapNetwork}
	four := map[string]string{"os.Remove": topology.CapFilesystem, "os.Chmod": topology.CapFilesystem,
		"os.Rename": topology.CapFilesystem, "os.Mkdir": topology.CapFilesystem}
	settings := func(t *topology.FunctionTopology, weak, secure []string) *topology.FunctionTopology {
		t.WeakSettings, t.SecureSettings = map[string]bool{}, map[string]bool{}
		for _, s := range weak {
			t.WeakSettings[s] = true
		}
		for _, s := range secure {
			t.SecureSettings[s] = true
		}
		return t
	}
	const skip, cookie = "crypto/tls.Config.InsecureSkipVerify=true", "net/http.Cookie.Secure=true"
	const tls10, tls11 = "crypto/tls.Config.MinVersion=TLS1.0", "crypto/tls.Config.MinVersion=TLS1.1"
	checks := func(keys ...string) *topology.FunctionTopology {
		t := fileTopo(nil, nil)
		t.Checks = map[string]bool{}
		for _, k := range keys {
			t.Checks[k] = true
		}
		return t
	}
	cases := []struct {
		name     string
		old, new *topology.FunctionTopology
		labels   []string
		score    int
	}{
		{"guard deleted", fileTopo(remove, map[string]int{"os.Remove": 1}), fileTopo(remove, map[string]int{"os.Remove": 0}),
			[]string{"Unguarded(os.Remove)"}, models.RiskScoreHigh},
		{"one of two guards deleted", fileTopo(remove, map[string]int{"os.Remove": 2}), fileTopo(remove, map[string]int{"os.Remove": 1}),
			nil, 0},
		{"never guarded", fileTopo(remove, map[string]int{"os.Remove": 0}), fileTopo(remove, map[string]int{"os.Remove": 0}),
			nil, 0},
		{"guard added", fileTopo(remove, map[string]int{"os.Remove": 0}), fileTopo(remove, map[string]int{"os.Remove": 1}),
			nil, 0},
		{"new unguarded call is a new capability, not a deleted guard", fileTopo(nil, map[string]int{}), fileTopo(remove, map[string]int{"os.Remove": 0}),
			[]string{"Capability+filesystem(os.Remove)"}, 10},
		{"guards unknown on the old side", fileTopo(remove, nil), fileTopo(remove, map[string]int{"os.Remove": 0}),
			nil, 0},
		{"two guards deleted are charged once", fileTopo(both, map[string]int{"os.Remove": 1, "net.Dial": 3}),
			fileTopo(both, map[string]int{"os.Remove": 0, "net.Dial": 0}),
			[]string{"Unguarded(net.Dial,os.Remove)"}, models.RiskScoreHigh},

		{"guards deleted, sorted", fileTopo(four, map[string]int{"os.Remove": 1, "os.Chmod": 1, "os.Rename": 1, "os.Mkdir": 1}),
			fileTopo(four, map[string]int{"os.Remove": 0, "os.Chmod": 0, "os.Rename": 0, "os.Mkdir": 0}),
			[]string{"Unguarded(os.Chmod,os.Mkdir,os.Remove,os.Rename)"}, models.RiskScoreHigh},
		{"a guard deleted beside an unguarded call of its class", fileTopo(removeBoth, map[string]int{"os.Remove": 1, "os.RemoveAll": 0}),
			fileTopo(removeBoth, map[string]int{"os.Remove": 0, "os.RemoveAll": 0}),
			[]string{"Unguarded(os.Remove)"}, models.RiskScoreHigh},
		{"a guarded call swapped for an unguarded one of its class", fileTopo(remove, map[string]int{"os.Remove": 1}),
			fileTopo(removeAll, map[string]int{"os.RemoveAll": 0}),
			[]string{"Capability+filesystem(os.RemoveAll)", "Unguarded(os.RemoveAll)", "Calls-1"}, riskAdditionalCapability + models.RiskScoreHigh},
		{"an unguarded call added beside a guarded one of its class", fileTopo(remove, map[string]int{"os.Remove": 1}),
			fileTopo(removeBoth, map[string]int{"os.Remove": 1, "os.RemoveAll": 0}),
			[]string{"Capability+filesystem(os.RemoveAll)", "Unguarded(os.RemoveAll)"}, riskAdditionalCapability + models.RiskScoreHigh},
		{"a guarded call added beside a guarded one", fileTopo(remove, map[string]int{"os.Remove": 1}),
			fileTopo(removeBoth, map[string]int{"os.Remove": 1, "os.RemoveAll": 1}),
			[]string{"Capability+filesystem(os.RemoveAll)"}, riskAdditionalCapability},
		{"an unguarded call added to a class already called unguarded", fileTopo(removeBoth, map[string]int{"os.Remove": 1, "os.RemoveAll": 0}),
			fileTopo(map[string]string{"os.Remove": topology.CapFilesystem, "os.RemoveAll": topology.CapFilesystem, "os.Chmod": topology.CapFilesystem},
				map[string]int{"os.Remove": 1, "os.RemoveAll": 0, "os.Chmod": 0}),
			[]string{"Capability+filesystem(os.Chmod)"}, riskAdditionalCapability},
		{"an unguarded call added to a class with a call of unknown guards", fileTopo(removeBoth, map[string]int{"os.Remove": 1}),
			fileTopo(map[string]string{"os.Remove": topology.CapFilesystem, "os.RemoveAll": topology.CapFilesystem, "os.Chmod": topology.CapFilesystem},
				map[string]int{"os.Remove": 1, "os.Chmod": 0}),
			[]string{"Capability+filesystem(os.Chmod)"}, riskAdditionalCapability},
		{"an unguarded call of another class", fileTopo(remove, map[string]int{"os.Remove": 1}),
			fileTopo(both, map[string]int{"os.Remove": 1, "net.Dial": 0}),
			[]string{"Capability+network(net.Dial)"}, capabilityRisk[topology.CapNetwork]},

		{"guards of a guarded call unknown in the new version", fileTopo(remove, map[string]int{"os.Remove": 1}), fileTopo(remove, nil),
			[]string{"GuardsUnknown(os.Remove)"}, models.RiskScoreHigh},
		{"guards of an unguarded call unknown in the new version", fileTopo(remove, map[string]int{"os.Remove": 0}), fileTopo(remove, nil),
			nil, 0},
		{"guards unknown in both versions", fileTopo(remove, nil), fileTopo(remove, nil),
			nil, 0},
		{"guards unknown after a guarded call's swap", fileTopo(remove, map[string]int{"os.Remove": 1}), fileTopo(removeAll, nil),
			[]string{"Capability+filesystem(os.RemoveAll)", "GuardsUnknown(os.RemoveAll)", "Calls-1"}, riskAdditionalCapability + models.RiskScoreHigh},

		{"weak setting added and secure setting lost, charged once",
			settings(fileTopo(nil, nil), nil, []string{cookie}), settings(fileTopo(nil, nil), []string{skip}, nil),
			[]string{"WeakenedSecurity(-" + cookie + "," + skip + ")"}, models.RiskScoreHigh},
		{"weak setting kept", settings(fileTopo(nil, nil), []string{skip}, nil), settings(fileTopo(nil, nil), []string{skip}, nil),
			nil, 0},
		{"weak setting removed", settings(fileTopo(nil, nil), []string{skip}, nil), settings(fileTopo(nil, nil), nil, nil),
			nil, 0},
		{"secure setting kept", settings(fileTopo(nil, nil), nil, []string{cookie}), settings(fileTopo(nil, nil), nil, []string{cookie}),
			nil, 0},
		{"secure setting added", settings(fileTopo(nil, nil), nil, nil), settings(fileTopo(nil, nil), nil, []string{cookie}),
			nil, 0},
		{"a legacy TLS bound raised", settings(fileTopo(nil, nil), []string{tls10}, nil), settings(fileTopo(nil, nil), []string{tls11}, nil),
			nil, 0},
		{"a TLS bound lowered beside a kept legacy bound", settings(fileTopo(nil, nil), []string{tls10}, nil), settings(fileTopo(nil, nil), []string{tls10, tls11}, nil),
			[]string{"WeakenedSecurity(" + tls11 + ")"}, models.RiskScoreHigh},

		{"a check removed", checks("example.com/p.authorize"), checks(), []string{"RemovedCheck(example.com/p.authorize)"}, models.RiskScoreHigh},
		{"a check exported", checks("(example.com/p.validator).validate"), checks("(example.com/p.Validator).Validate"), nil, 0},
		{"a check renamed", checks("example.com/p.authorize"), checks("example.com/p.authorizeUser"),
			[]string{"RemovedCheck(example.com/p.authorize)"}, models.RiskScoreHigh},
		{"a module's new major version", checks("(github.com/casbin/casbin/v2.Enforcer).Enforce"), checks("(github.com/casbin/casbin/v3.Enforcer).Enforce"),
			[]string{"ReplacedCheck((github.com/casbin/casbin/v2.Enforcer).Enforce->(github.com/casbin/casbin/v3.Enforcer).Enforce)"}, 0},
		{"a fork and a moved library", checks("github.com/go-ozzo/ozzo-validation/v4.ValidateStruct", "(gopkg.in/square/go-jose.v2.JSONWebSignature).Verify"),
			checks("github.com/pocketbase/ozzo-validation/v4.ValidateStruct", "(github.com/go-jose/go-jose/v3.JSONWebSignature).Verify"),
			[]string{"ReplacedCheck((gopkg.in/square/go-jose.v2.JSONWebSignature).Verify->(github.com/go-jose/go-jose/v3.JSONWebSignature).Verify," +
				"github.com/go-ozzo/ozzo-validation/v4.ValidateStruct->github.com/pocketbase/ozzo-validation/v4.ValidateStruct)"}, 0},
		{"the same name in a package of another name", checks("example.com/auth.Verify"), checks("example.com/noop.Verify"),
			[]string{"RemovedCheck(example.com/auth.Verify)"}, models.RiskScoreHigh},
		{"a primitive replaced by a look-alike", checks("crypto/hmac.Equal"), checks("example.com/crypto/hmac.Equal"),
			[]string{"RemovedCheck(crypto/hmac.Equal)"}, models.RiskScoreHigh},
		{"a check replaced by a look-alike primitive", checks("example.com/x/hmac.Equal"), checks("crypto/hmac.Equal"),
			[]string{"RemovedCheck(example.com/x/hmac.Equal)"}, models.RiskScoreHigh},
		{"hmac.Equal replaced by its equivalent", checks("crypto/hmac.Equal"), checks("crypto/subtle.ConstantTimeCompare"), nil, 0},
		{"subtle.ConstantTimeCompare replaced by its equivalent", checks("crypto/subtle.ConstantTimeCompare"), checks("crypto/hmac.Equal"), nil, 0},
		{"a primitive replaced by another primitive", checks("crypto/subtle.ConstantTimeCompare"), checks("crypto/subtle.ConstantTimeEq"),
			[]string{"RemovedCheck(crypto/subtle.ConstantTimeCompare)"}, models.RiskScoreHigh},
		{"a primitive without an equivalent replaced", checks("crypto/ed25519.Verify"), checks("crypto/hmac.Equal"),
			[]string{"RemovedCheck(crypto/ed25519.Verify)"}, models.RiskScoreHigh},
		{"checks removed, sorted", checks("example.com/p.c", "example.com/p.a", "example.com/p.d", "example.com/p.b"), checks(),
			[]string{"RemovedCheck(example.com/p.a,example.com/p.b,example.com/p.c,example.com/p.d)"}, models.RiskScoreHigh},
		{"checks replaced, sorted", checks("x.com/c/v2.Verify", "x.com/a/v2.Verify", "x.com/d/v2.Verify", "x.com/b/v2.Verify"),
			checks("x.com/a/v3.Verify", "x.com/b/v3.Verify", "x.com/c/v3.Verify", "x.com/d/v3.Verify"),
			[]string{"ReplacedCheck(x.com/a/v2.Verify->x.com/a/v3.Verify,x.com/b/v2.Verify->x.com/b/v3.Verify," +
				"x.com/c/v2.Verify->x.com/c/v3.Verify,x.com/d/v2.Verify->x.com/d/v3.Verify)"}, 0},
		{"an exported rename of a non-ASCII name", checks("example.com/p.überprüfeAuth"), checks("example.com/p.ÜberprüfeAuth"), nil, 0},
		{"first letters that share a UTF-8 byte", checks("example.com/p.ÄAuthorize"), checks("example.com/p.ĄAuthorize"),
			[]string{"RemovedCheck(example.com/p.ÄAuthorize)"}, models.RiskScoreHigh},
		{"a generic interface's check moved to another package", checks("(example.com/authz.Checker[example.com/model.User]).Allow"),
			checks("(example.com/noop.Checker[example.com/model.User]).Allow"),
			[]string{"RemovedCheck((example.com/authz.Checker[example.com/model.User]).Allow)"}, models.RiskScoreHigh},
		{"a generic interface's check in a new major version", checks("(x.com/authz/v2.Checker[x.com/model.User]).Allow"),
			checks("(x.com/authz/v3.Checker[x.com/model.User]).Allow"),
			[]string{"ReplacedCheck((x.com/authz/v2.Checker[x.com/model.User]).Allow->(x.com/authz/v3.Checker[x.com/model.User]).Allow)"}, 0},
		{"the first replacement, in order", checks("x.com/a/v2.Verify"),
			checks("x.com/a/v9.Verify", "x.com/a/v5.Verify", "x.com/a/v3.Verify", "x.com/a/v7.Verify", "x.com/a/v4.Verify", "x.com/a/v8.Verify", "x.com/a/v6.Verify"),
			[]string{"ReplacedCheck(x.com/a/v2.Verify->x.com/a/v3.Verify)"}, 0},
		{"a kept check replaces nothing", checks("x.com/a/v2.Verify", "x.com/a/v3.Verify"), checks("x.com/a/v3.Verify"),
			[]string{"RemovedCheck(x.com/a/v2.Verify)"}, models.RiskScoreHigh},
		{"checks moved into literals passed to calls, and one removed", checks("x.com/p.a", "x.com/p.b", "x.com/p.c"),
			&topology.FunctionTopology{MovedChecks: map[string]string{"x.com/p.c": "x.com/p.run", "x.com/p.b": "(x.com/sf.Group).Do"}},
			[]string{"RemovedCheck(x.com/p.a)", "MovedCheck(x.com/p.b via (x.com/sf.Group).Do,x.com/p.c via x.com/p.run)"}, models.RiskScoreHigh},
		{"a check kept beside a moved copy", checks("x.com/p.a"),
			&topology.FunctionTopology{Checks: map[string]bool{"x.com/p.a": true}, MovedChecks: map[string]string{"x.com/p.a": "x.com/p.run"}},
			nil, 0},
		{"error exits removed are labelled, not charged", &topology.FunctionTopology{ErrorExits: 3}, &topology.FunctionTopology{ErrorExits: 1},
			[]string{"ErrorExits-2"}, 0},
		{"error exits added", &topology.FunctionTopology{ErrorExits: 1}, &topology.FunctionTopology{ErrorExits: 3},
			nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := assessTopologyDeltaFor(c.old, c.new, riskProfile{})
			if !reflect.DeepEqual(r.labels, c.labels) || r.score(0) != c.score {
				t.Errorf("labels %q, score %d; want %q, %d", r.labels, r.score(0), c.labels, c.score)
			}
		})
	}
}

// TestAssessTopologyDelta_Scoring checks every row of the README's risk
// scoring tables, the structural cap, and the order of the labels.
func TestAssessTopologyDelta_Scoring(t *testing.T) {
	classOf := map[string]string{
		"os/exec.Command": topology.CapExec, "syscall.Kill": topology.CapSyscall, "plugin.Open": topology.CapPlugin,
		"net.Dial": topology.CapNetwork, "net.DialTimeout": topology.CapNetwork, "net.Listen": topology.CapNetwork,
		"net.LookupHost": topology.CapNetwork, "net.ResolveTCPAddr": topology.CapNetwork,
		"(reflect.Value).Call": topology.CapReflection, "os.Remove": topology.CapFilesystem,
	}
	// mk is a function calling targets, changed by edit.
	mk := func(edit func(*topology.FunctionTopology), targets ...string) *topology.FunctionTopology {
		t := &topology.FunctionTopology{CallTargets: map[string]int{}, Capabilities: map[string]string{}}
		for _, k := range targets {
			t.CallTargets[k] = 1
			if class := classOf[k]; class != "" {
				t.Capabilities[k] = class
			}
		}
		if edit != nil {
			edit(t)
		}
		return t
	}
	loops := func(n int) func(*topology.FunctionTopology) {
		return func(t *topology.FunctionTopology) { t.LoopCount = n }
	}
	branches := func(n int) func(*topology.FunctionTopology) {
		return func(t *topology.FunctionTopology) { t.BranchCount = n }
	}
	entropy := func(e float64) func(*topology.FunctionTopology) {
		return func(t *topology.FunctionTopology) { t.EntropyScore = e }
	}
	obfuscation := func(c topology.ObfuscationClass) func(*topology.FunctionTopology) {
		return func(t *topology.FunctionTopology) { t.Obfuscation.Class = c }
	}
	literals := func(s ...string) func(*topology.FunctionTopology) {
		return func(t *topology.FunctionTopology) { t.StringLiterals = s }
	}
	goes := func(t *topology.FunctionTopology) { t.HasGo = true }
	defers := func(t *topology.FunctionTopology) { t.HasDefer = true }
	panics := func(t *topology.FunctionTopology) { t.HasPanic = true }
	signatures := func(s ...string) *topology.FunctionTopology {
		t := &topology.FunctionTopology{CallSignatures: map[string]int{}}
		for _, k := range s {
			t.CallSignatures[k] = 1
		}
		return t
	}

	type scoringCase struct {
		name     string
		old, new *topology.FunctionTopology
		labels   []string
		score    int
		newCaps  []string
	}
	cases := []scoringCase{
		{"two newly reached targets of a class", mk(nil), mk(nil, "net.Listen", "net.Dial"),
			[]string{"Capability+network(net.Dial,net.Listen)"}, 20 + riskAdditionalCapability, []string{"net.Dial", "net.Listen"}},
		{"five, sorted", mk(nil), mk(nil, "net.ResolveTCPAddr", "net.Listen", "net.LookupHost", "net.DialTimeout", "net.Dial"),
			[]string{"Capability+network(net.Dial,net.DialTimeout,net.Listen,net.LookupHost,net.ResolveTCPAddr)"}, 20 + 4*riskAdditionalCapability,
			[]string{"net.Dial", "net.DialTimeout", "net.Listen", "net.LookupHost", "net.ResolveTCPAddr"}},
		{"a further target of a class already reached", mk(nil, "net.Dial"), mk(nil, "net.Dial", "net.Listen"),
			[]string{"Capability+network(net.Listen)"}, riskAdditionalCapability, []string{"net.Listen"}},
		{"two classes, in class order", mk(nil), mk(nil, "net.Dial", "os/exec.Command"),
			[]string{"Capability+exec(os/exec.Command)", "Capability+network(net.Dial)"}, 30 + 20, []string{"os/exec.Command", "net.Dial"}},
		{"a capability call kept", mk(nil, "net.Dial"), mk(nil, "net.Dial"), nil, 0, nil},
		{"a capability call removed", mk(nil, "net.Dial"), mk(nil), []string{"Calls-1"}, 0, nil},
		{"plain calls added", mk(nil, "a.F"), mk(nil, "a.F", "a.G", "a.H"), []string{"Calls+2"}, 2 * riskPerNewCallTarget, nil},
		{"plain calls added and removed", mk(nil, "a.F", "a.G"), mk(nil, "a.H"), []string{"Calls+1", "Calls-2"}, riskPerNewCallTarget, nil},
		{"calls by package name, without targets", signatures("fmt.Println"), signatures("fmt.Println", "fmt.Printf"),
			[]string{"Calls+1"}, riskPerNewCallTarget, nil},
		{"loops added", mk(loops(1)), mk(loops(2)), []string{"Loops+1"}, riskPerNewLoop, nil},
		{"loops removed", mk(loops(2)), mk(nil), []string{"Loops-2"}, 0, nil},
		{"branches added", mk(branches(1)), mk(branches(4)), []string{"Branches+3"}, 3 * riskPerNewBranch, nil},
		{"branches removed", mk(branches(3)), mk(branches(1)), []string{"Branches-2"}, 0, nil},
		{"a goroutine added", mk(nil), mk(goes), []string{models.TopoDeltaGoroutine}, models.RiskScoreHigh, nil},
		{"a goroutine kept", mk(goes), mk(goes), nil, 0, nil},
		{"a defer added", mk(nil), mk(defers), []string{models.TopoDeltaDefer}, riskNewDefer, nil},
		{"a defer kept", mk(defers), mk(defers), nil, 0, nil},
		{"a panic added", mk(nil), mk(panics), []string{models.TopoDeltaPanic}, riskNewPanic, nil},
		{"a panic kept", mk(panics), mk(panics), nil, 0, nil},
		{"string literals changed", mk(literals("a")), mk(literals("b")), []string{"StringLiterals~"}, 0, nil},
		{"string literals kept", mk(literals("a")), mk(literals("a")), nil, 0, nil},
		{"entropy up by more than 1", mk(entropy(3)), mk(entropy(4.5)), []string{"Entropy+1.5"}, 0, nil},
		{"entropy up by exactly 1", mk(entropy(3)), mk(entropy(4)), nil, 0, nil},
		{"entropy into HIGH", mk(entropy(6)), mk(entropy(6.6)), []string{"EntropyClass:HIGH"}, models.RiskScoreHigh, nil},
		{"entropy from HIGH to PACKED", mk(entropy(7)), mk(entropy(7.6)), []string{"EntropyClass:PACKED"}, models.RiskScoreHigh, nil},
		{"entropy staying HIGH", mk(entropy(6.6)), mk(entropy(7.4)), nil, 0, nil},
		{"entropy from PACKED to HIGH", mk(entropy(7.6)), mk(entropy(7)), nil, 0, nil},
		{"obfuscation to LOW", mk(nil), mk(obfuscation(topology.ObfuscationLow)), nil, 0, nil},
		{"obfuscation to MODERATE", mk(obfuscation(topology.ObfuscationLow)), mk(obfuscation(topology.ObfuscationModerate)),
			[]string{"Obfuscation:MODERATE"}, models.RiskScoreHigh, nil},
		{"obfuscation from MODERATE to HIGH", mk(obfuscation(topology.ObfuscationModerate)), mk(obfuscation(topology.ObfuscationHigh)),
			[]string{"Obfuscation:HIGH"}, models.RiskScoreHigh, nil},
		{"obfuscation staying HIGH", mk(obfuscation(topology.ObfuscationHigh)), mk(obfuscation(topology.ObfuscationHigh)), nil, 0, nil},
		{"churn is capped", mk(nil), mk(loops(2)), []string{"Loops+2"}, maxStructuralRisk, nil},
		{"escalations are not", mk(nil), mk(func(t *topology.FunctionTopology) { t.LoopCount = 2; t.HasGo = true }),
			[]string{"Loops+2", models.TopoDeltaGoroutine}, maxStructuralRisk + models.RiskScoreHigh, nil},
		{"every label, in order", mk(func(t *topology.FunctionTopology) {
			t.LoopCount, t.BranchCount, t.ErrorExits, t.StringLiterals, t.EntropyScore = 1, 1, 1, []string{"a"}, 6
		}, "a.F"), mk(func(t *topology.FunctionTopology) {
			t.LoopCount, t.BranchCount, t.StringLiterals, t.EntropyScore = 2, 2, []string{"b"}, 7.6
			t.HasGo, t.HasDefer, t.HasPanic, t.Obfuscation.Class = true, true, true, topology.ObfuscationHigh
		}, "a.G", "net.Dial"),
			[]string{"Capability+network(net.Dial)", "Calls+1", "Calls-1", "ErrorExits-1", "Loops+1", "Branches+1",
				models.TopoDeltaGoroutine, models.TopoDeltaDefer, models.TopoDeltaPanic, "StringLiterals~", "Entropy+1.6",
				"EntropyClass:PACKED", "Obfuscation:HIGH"},
			maxStructuralRisk + 20 + 3*models.RiskScoreHigh, []string{"net.Dial"}},
	}
	for class, target := range map[string]string{
		topology.CapExec: "os/exec.Command", topology.CapSyscall: "syscall.Kill", topology.CapPlugin: "plugin.Open",
		topology.CapNetwork: "net.Dial", topology.CapReflection: "(reflect.Value).Call", topology.CapFilesystem: "os.Remove",
	} {
		cases = append(cases, scoringCase{"first " + class + " target", mk(nil), mk(nil, target),
			[]string{"Capability+" + class + "(" + target + ")"}, map[string]int{
				topology.CapExec: 30, topology.CapSyscall: 25, topology.CapPlugin: 25,
				topology.CapNetwork: 20, topology.CapReflection: 15, topology.CapFilesystem: 10,
			}[class], []string{target}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := assessTopologyDeltaFor(c.old, c.new, riskProfile{})
			if !reflect.DeepEqual(r.labels, c.labels) || r.score(0) != c.score || !reflect.DeepEqual(r.newCapabilities, c.newCaps) {
				t.Errorf("labels %q, score %d, new capabilities %q; want %q, %d, %q", r.labels, r.score(0), r.newCapabilities, c.labels, c.score, c.newCaps)
			}
		})
	}
}

func TestCalculateTopologyDelta(t *testing.T) {
	checked := fileTopo(map[string]string{"os.Remove": topology.CapFilesystem}, map[string]int{"os.Remove": 1})
	checked.Checks = map[string]bool{"example.com/p.valid": true, "crypto/hmac.Equal": true}
	looped := &topology.FunctionTopology{LoopCount: 1}
	for _, c := range []struct {
		name     string
		old, new *topology.FunctionTopology
		delta    string
		score    int
	}{
		{"no topology", nil, nil, models.TopoDeltaUnknown, 0},
		{"added without structure", nil, &topology.FunctionTopology{}, models.TopoDeltaNew, models.BaseRiskAddedFunc},
		{"added with a loop, capped", nil, looped, "Loops+1", maxStructuralRisk},
		{"added with a capability", nil, checked, "Capability+filesystem(os.Remove)", models.BaseRiskAddedFunc + capabilityRisk[topology.CapFilesystem]},
		{"removed without checks", looped, nil, "", 0},
		{"removed with checks", checked, nil, "RemovedCheck(crypto/hmac.Equal,example.com/p.valid)", models.RiskScoreHigh},
		{"unchanged", looped, looped, models.TopoDeltaNone, 0},
		{"modified", looped, checked, "Capability+filesystem(os.Remove), Loops-1", capabilityRisk[topology.CapFilesystem]},
	} {
		if delta, score := CalculateTopologyDelta(c.old, c.new); delta != c.delta || score != c.score {
			t.Errorf("%s: CalculateTopologyDelta = %q, %d; want %q, %d", c.name, delta, score, c.delta, c.score)
		}
	}
}

func TestAssessTopologyDelta_Profile(t *testing.T) {
	const own, near = "golang.org/x/sys/unix.Syscall6", "golang.org/x/sysfoo.Run"
	oldT := fileTopo(map[string]string{own: topology.CapSyscall, near: topology.CapExec}, map[string]int{own: 1, near: 1})
	newT := fileTopo(map[string]string{own: topology.CapSyscall, near: topology.CapExec, "golang.org/x/sys/unix.Exec": topology.CapExec},
		map[string]int{own: 0, near: 0, "golang.org/x/sys/unix.Exec": 0})
	newT.HasGo = true
	oldCopy, newCopy := *oldT, *newT
	oldCaps, newGuards := len(oldT.Capabilities), len(newT.CapabilityGuards)

	r := assessTopologyDeltaFor(oldT, newT, riskProfile{ownModule: "golang.org/x/sys", labelGoroutines: true})
	// The module's own targets are plain calls; a module whose path merely
	// starts with the same text is not the module; the goroutine is labelled.
	want := []string{"Unguarded(" + near + ")", "Calls+1", models.TopoDeltaGoroutine}
	if !reflect.DeepEqual(r.labels, want) || r.score(0) != models.RiskScoreHigh+riskPerNewCallTarget {
		t.Errorf("own-module profile: labels %q, score %d; want %q, %d", r.labels, r.score(0), want, models.RiskScoreHigh+riskPerNewCallTarget)
	}
	if !reflect.DeepEqual(*oldT, oldCopy) || !reflect.DeepEqual(*newT, newCopy) || len(oldT.Capabilities) != oldCaps || len(newT.CapabilityGuards) != newGuards {
		t.Error("the profile changed the topologies it was given")
	}

	// Every old exec call was guarded, so the new unguarded unix.Exec is
	// one more unguarded call.
	r = assessTopologyDeltaFor(oldT, newT, riskProfile{})
	want = []string{"Capability+exec(golang.org/x/sys/unix.Exec)", "Unguarded(golang.org/x/sys/unix.Exec," + own + "," + near + ")", models.TopoDeltaGoroutine}
	if score := riskAdditionalCapability + 2*models.RiskScoreHigh; !reflect.DeepEqual(r.labels, want) || r.score(0) != score {
		t.Errorf("default profile: labels %q, score %d; want %q, %d", r.labels, r.score(0), want, score)
	}
}

// Unknown guards stay unknown under a dependency's profile.
func TestAssessTopologyDelta_ProfileGuardsUnknown(t *testing.T) {
	const own, other = "golang.org/x/sys/unix.Unlink", "os.Remove"
	targets := map[string]string{own: topology.CapSyscall, other: topology.CapFilesystem}
	r := assessTopologyDeltaFor(fileTopo(targets, map[string]int{own: 1, other: 1}), fileTopo(targets, nil), riskProfile{ownModule: "golang.org/x/sys"})
	if want := []string{"GuardsUnknown(" + other + ")"}; !reflect.DeepEqual(r.labels, want) || r.score(0) != models.RiskScoreHigh {
		t.Errorf("labels %q, score %d; want %q, %d", r.labels, r.score(0), want, models.RiskScoreHigh)
	}
}

// A new weak TLS bound is excused only when it replaces a bound on the same
// field that was no higher and is gone; versions are read by name or value.
func TestRaisesTLSVersion(t *testing.T) {
	const min, max = "crypto/tls.Config.MinVersion=", "crypto/tls.Config.MaxVersion="
	set := func(s ...string) map[string]bool {
		m := map[string]bool{}
		for _, k := range s {
			m[k] = true
		}
		return m
	}
	for _, c := range []struct {
		s        string
		old, cur map[string]bool
		want     bool
	}{
		{min + "TLS1.1", set(min + "TLS1.0"), set(min + "TLS1.1"), true},
		{min + "TLS1.0", set(min + "SSL3.0"), set(min + "TLS1.0"), true},
		{max + "TLS1.1", set(max + "TLS1.0"), set(max + "TLS1.1"), true},
		{min + "770", set(min + "769"), set(min + "770"), true},
		{min + "769", set(min + "TLS1.0"), set(min + "769"), true},
		{min + "TLS1.0", set(min + "TLS1.1"), set(min + "TLS1.0"), false},
		{min + "TLS1.1", set(min + "TLS1.0"), set(min+"TLS1.0", min+"TLS1.1"), false},
		{min + "TLS1.1", set(max + "TLS1.0"), set(min + "TLS1.1"), false},
		{min + "bogus", set(min + "0"), set(min + "bogus"), false},
		{min + "TLS1.1", set(min + "bogus"), set(min + "TLS1.1"), false},
		{"example.com/p.Config.Level=1", set("example.com/p.Config.Level=0"), set("example.com/p.Config.Level=1"), false},
		{"crypto/tls.Config.InsecureSkipVerify", set(), set("crypto/tls.Config.InsecureSkipVerify"), false},
	} {
		if got := raisesTLSVersion(c.s, c.old, c.cur); got != c.want {
			t.Errorf("raisesTLSVersion(%q, %v, %v) = %v; want %v", c.s, c.old, c.cur, got, c.want)
		}
	}
}

func TestPackageBase(t *testing.T) {
	for path, want := range map[string]string{
		"github.com/casbin/casbin/v2": "casbin", "gopkg.in/square/go-jose.v2": "go-jose", "github.com/go-jose/go-jose/v3": "go-jose",
		"example.com/p": "p", "v2": "v2", "example.com/x.v": "x.v", "example.com/vendor": "vendor", "": "",
	} {
		if got := packageBase(path); got != want {
			t.Errorf("packageBase(%q) = %q; want %q", path, got, want)
		}
	}
	for key, want := range map[string][3]string{
		"crypto/hmac.Equal": {"crypto/hmac", "", "Equal"}, "(crypto/x509.Certificate).Verify": {"crypto/x509", "Certificate", "Verify"},
		"(.error).Error": {"", "error", "Error"}, "Name": {"", "", "Name"},
		"(example.com/authz.Checker[example.com/model.User]).Allow": {"example.com/authz", "Checker[example.com/model.User]", "Allow"},
		"example.com/p.Check[example.com/q.T]":                      {"example.com/p", "", "Check[example.com/q.T]"},
	} {
		if pkg, recv, name := splitCheckKey(key); [3]string{pkg, recv, name} != want {
			t.Errorf("splitCheckKey(%q) = %q, %q, %q; want %q", key, pkg, recv, name, want)
		}
	}
}

func TestModuleTargets(t *testing.T) {
	for key, want := range map[string]string{
		"golang.org/x/sys/unix.Syscall6":        "golang.org/x/sys/unix",
		"(golang.org/x/sys/unix.Timespec).Unix": "golang.org/x/sys/unix",
		"(gopkg.in/yaml.v3.Node).Decode":        "gopkg.in/yaml.v3",
		"gopkg.in/yaml.v3.Unmarshal":            "gopkg.in/yaml.v3",
		"os.Remove":                             "os",
		"(example.com/a.b.T).M":                 "example.com/a.b",
		"(.error).Error":                        "",
		"Name":                                  "",
	} {
		if got, _, _ := splitCheckKey(key); got != want {
			t.Errorf("package of %q = %q; want %q", key, got, want)
		}
	}
	for _, c := range []struct {
		pkg, mod string
		in       bool
	}{
		{"golang.org/x/sys", "golang.org/x/sys", true},
		{"golang.org/x/sys/unix", "golang.org/x/sys", true},
		{"golang.org/x/sysfoo", "golang.org/x/sys", false},
		{"golang.org/x", "golang.org/x/sys", false},
	} {
		if got := inModule(c.pkg, c.mod); got != c.in {
			t.Errorf("inModule(%q, %q) = %v; want %v", c.pkg, c.mod, got, c.in)
		}
	}
}
