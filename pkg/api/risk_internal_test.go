package api

import (
	"reflect"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
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
	both := map[string]string{"os.Remove": topology.CapFilesystem, "net.Dial": topology.CapNetwork}
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

	r = assessTopologyDeltaFor(oldT, newT, riskProfile{})
	want = []string{"Capability+exec(golang.org/x/sys/unix.Exec)", "Unguarded(" + own + "," + near + ")", models.TopoDeltaGoroutine}
	if score := riskAdditionalCapability + 2*models.RiskScoreHigh; !reflect.DeepEqual(r.labels, want) || r.score(0) != score {
		t.Errorf("default profile: labels %q, score %d; want %q, %d", r.labels, r.score(0), want, score)
	}
}

func TestTargetPackage(t *testing.T) {
	for key, want := range map[string]string{
		"golang.org/x/sys/unix.Syscall6":        "golang.org/x/sys/unix",
		"(golang.org/x/sys/unix.Timespec).Unix": "golang.org/x/sys/unix",
		"(gopkg.in/yaml.v3.Node).Decode":        "gopkg.in/yaml.v3",
		"gopkg.in/yaml.v3.Unmarshal":            "gopkg.in/yaml.v3",
		"os.Remove":                             "os",
		"(example.com/a.b.T).M":                 "example.com/a.b",
	} {
		if got := targetPackage(key); got != want {
			t.Errorf("targetPackage(%q) = %q; want %q", key, got, want)
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
