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
		{"os/exec", "", "LookPath", ""},
		{"os/exec", "Cmd", "String", topology.CapExec},
		{"os", "", "ForkExec", ""},
		{"syscall", "", "ForkExec", topology.CapExec},
		{"syscall", "", "Exec", topology.CapExec},
		{"golang.org/x/sys/unix", "", "Mmap", topology.CapSyscall},
		{"golang.org/x/sys/unix", "", "Exec", topology.CapExec},
		{"golang.org/x/sys/windows", "", "VirtualAlloc", topology.CapSyscall},
		{"golang.org/x/sys/windows", "Handle", "Close", ""},
		{"syscall", "", "Getpagesize", ""},
		{"syscall", "", "BytePtrFromString", ""},
		{"golang.org/x/sys/unix", "", "NsecToTimespec", ""},
		{"golang.org/x/sys/windows", "", "UTF16PtrFromString", ""},
		{"net", "", "LookupHost", topology.CapNetwork},
		{"net", "", "ResolveTCPAddr", topology.CapNetwork},
		{"net", "", "FileConn", topology.CapNetwork},
		{"net", "Dialer", "DialContext", topology.CapNetwork},
		{"net", "", "ParseIP", ""},
		{"net/http", "", "Get", topology.CapNetwork},
		{"net/http", "", "PostForm", topology.CapNetwork},
		{"net/http", "", "Head", topology.CapNetwork},
		{"net/http", "", "ListenAndServeTLS", topology.CapNetwork},
		{"net/http", "Server", "Serve", topology.CapNetwork},
		{"net/http", "Server", "ServeTLS", topology.CapNetwork},
		{"net/http", "Transport", "RoundTrip", topology.CapNetwork},
		{"net/http", "RoundTripper", "RoundTrip", topology.CapNetwork},
		{"net/http", "Request", "Do", ""},
		{"crypto/tls", "", "Dial", topology.CapNetwork},
		{"crypto/tls", "", "Listen", topology.CapNetwork},
		{"crypto/tls", "", "Client", ""},
		{"net/rpc", "", "DialHTTP", topology.CapNetwork},
		{"net/rpc/jsonrpc", "", "Dial", topology.CapNetwork},
		{"net/smtp", "", "SendMail", topology.CapNetwork},
		{"net/textproto", "", "Dial", topology.CapNetwork},
		{"net/http/httptest", "", "NewTLSServer", topology.CapNetwork},
		{"reflect", "Value", "CallSlice", topology.CapReflection},
		{"reflect", "Value", "MethodByName", topology.CapReflection},
		{"reflect", "Value", "Method", topology.CapReflection},
		{"reflect", "Value", "Elem", ""},
		{"io/ioutil", "", "WriteFile", topology.CapFilesystem},
		{"io/ioutil", "", "TempFile", topology.CapFilesystem},
		{"io/ioutil", "", "TempDir", topology.CapFilesystem},
		{"io/ioutil", "", "ReadFile", ""},
		{"os", "File", "Chmod", topology.CapFilesystem},
		{"os", "File", "Chown", topology.CapFilesystem},
		{"os", "File", "Truncate", topology.CapFilesystem},
		{"os", "File", "Stat", ""},
		{"os", "Root", "Chtimes", topology.CapFilesystem},
		{"os", "Root", "Mkdir", topology.CapFilesystem},
	}
	// Conversion helpers make no system call.
	for _, name := range []string{"BytePtrFromString", "ByteSliceFromString", "StringBytePtr", "StringByteSlice",
		"BytePtrToString", "ByteSliceToString", "UTF16FromString", "UTF16PtrFromString", "UTF16ToString",
		"UTF16PtrToString", "StringToUTF16", "StringToUTF16Ptr", "NsecToTimespec", "NsecToTimeval",
		"TimespecToNsec", "TimevalToNsec", "NsecToFiletime", "Getpagesize", "CmsgLen", "CmsgSpace"} {
		for _, pkg := range []string{"syscall", "golang.org/x/sys/unix", "golang.org/x/sys/windows"} {
			cases = append(cases, struct{ pkg, recv, name, want string }{pkg, "", name, ""})
		}
	}
	for _, name := range []string{"Create", "CreateTemp", "OpenFile", "Remove", "RemoveAll", "Rename",
		"Chmod", "Chown", "Lchown", "Chtimes", "Truncate", "Symlink", "Link", "Mkdir", "MkdirAll", "MkdirTemp"} {
		cases = append(cases, struct{ pkg, recv, name, want string }{"os", "", name, topology.CapFilesystem})
	}
	for _, c := range cases {
		if got := topology.ClassifyCallTarget(c.pkg, c.recv, c.name); got != c.want {
			t.Errorf("ClassifyCallTarget(%q, %q, %q) = %q; want %q", c.pkg, c.recv, c.name, got, c.want)
		}
	}
}

func TestIsVerificationCall(t *testing.T) {
	cases := []struct {
		pkg, recv, name string
		want            bool
	}{
		{"crypto/subtle", "", "ConstantTimeCompare", true},
		{"crypto/subtle", "", "ConstantTimeEq", true},
		{"crypto/subtle", "", "ConstantTimeByteEq", true},
		{"crypto/subtle", "", "ConstantTimeLessOrEq", true},
		{"crypto/subtle", "", "ConstantTimeCopy", false},
		{"crypto/subtle", "", "ConstantTimeSelect", false},
		{"crypto/subtle", "", "XORBytes", false},
		{"crypto/hmac", "", "Equal", true},
		{"crypto/hmac", "", "New", false},
		{"crypto/ed25519", "", "Verify", true},
		{"crypto/ed25519", "", "VerifyWithOptions", true},
		{"crypto/ed25519", "", "Sign", false},
		{"crypto/ecdsa", "", "VerifyASN1", true},
		{"crypto/rsa", "", "VerifyPSS", true},
		{"crypto/rsa", "", "VerifyPKCS1v15", true},
		{"crypto/rsa", "", "SignPSS", false},
		{"crypto/x509", "Certificate", "Verify", true},
		{"crypto/x509", "Certificate", "VerifyHostname", true},
		{"crypto/x509", "Certificate", "CheckSignature", true},
		{"crypto/x509", "Certificate", "CheckSignatureFrom", true},
		{"crypto/x509", "CertificateRequest", "CheckSignature", true},
		{"crypto/x509", "Certificate", "Equal", false},
		{"crypto/x509", "", "ParseCertificate", false},
		{"crypto/x509", "CertPool", "Verify", false},
		{"crypto/tls", "Conn", "VerifyHostname", true},
		{"crypto/tls", "Conn", "Handshake", false},
		{"crypto/tls", "Config", "VerifyHostname", false},
		{"golang.org/x/crypto/bcrypt", "", "CompareHashAndPassword", true},
		{"golang.org/x/crypto/bcrypt", "", "GenerateFromPassword", false},
		{"path/filepath", "", "IsLocal", true},
		{"path/filepath", "", "Clean", false},
		{"bytes", "", "Equal", false},
	}
	for _, c := range cases {
		if got := topology.IsVerificationCall(c.pkg, c.recv, c.name); got != c.want {
			t.Errorf("IsVerificationCall(%q, %q, %q) = %v; want %v", c.pkg, c.recv, c.name, got, c.want)
		}
	}
}
