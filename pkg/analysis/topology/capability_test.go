package topology_test

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
)

func TestClassifyCallTarget(t *testing.T) {
	cases := []struct {
		pkg, recv, name, want string
	}{
		{"os/exec", "", "Command", topology.CapExec},
		{"os/exec", "Cmd", "Run", topology.CapExec},
		{"os", "", "StartProcess", topology.CapExec},
		{"net/http/cgi", "Handler", "ServeHTTP", topology.CapExec},
		{"net/http/cgi", "", "Serve", ""},
		{"syscall", "", "Syscall", topology.CapSyscall},
		{"syscall", "Errno", "Error", ""},
		{"plugin", "", "Open", topology.CapPlugin},
		{"net", "", "Dial", topology.CapNetwork},
		{"net/http", "Client", "Do", topology.CapNetwork},
		{"net/http", "", "NewRequest", ""},
		{"log/syslog", "", "Dial", topology.CapNetwork},
		{"log/syslog", "", "New", ""},
		{"net/http/httptest", "", "NewServer", topology.CapNetwork},
		{"net/http/httptest", "", "NewUnstartedServer", topology.CapNetwork},
		{"net/http/httptest", "", "NewRecorder", ""},
		{"net/http/httputil", "ReverseProxy", "ServeHTTP", topology.CapNetwork},
		{"net/http/httputil", "", "NewSingleHostReverseProxy", ""},
		{"reflect", "Value", "Call", topology.CapReflection},
		{"os", "", "WriteFile", topology.CapFilesystem},
		{"os", "", "CopyFS", topology.CapFilesystem},
		{"os", "", "ReadFile", ""},
		{"os", "", "OpenRoot", ""},
		{"os", "Root", "WriteFile", topology.CapFilesystem},
		{"os", "Root", "RemoveAll", topology.CapFilesystem},
		{"os", "Root", "Open", ""},
		{"os", "File", "Write", ""},
	}
	for _, c := range cases {
		if got := topology.ClassifyCallTarget(c.pkg, c.recv, c.name); got != c.want {
			t.Errorf("ClassifyCallTarget(%q, %q, %q) = %q; want %q", c.pkg, c.recv, c.name, got, c.want)
		}
	}
}
