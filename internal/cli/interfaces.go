// -- internal/cli/interfaces.go --
package cli

import (
	"context"
	"io"
	"io/fs"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v3/internal/sandbox"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"golang.org/x/tools/go/packages"
)

// FileSystem abstracts OS file operations to enable hermetic testing.
type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
	Open(name string) (fs.File, error)
	Getwd() (string, error)
	Abs(path string) (string, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
	ReadFile(name string) ([]byte, error)
}

// Sandboxer abstracts the process isolation mechanism.
type Sandboxer interface {
	IsSandboxed() bool
	Run(ctx context.Context, cfg sandbox.Config, stdout, stderr io.Writer) error
}

// SignatureScanner abstracts the underlying database backend (PebbleDB or JSON).
type SignatureScanner interface {
	ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error)
	ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error)
	Close() error
}

// PackageLoader abstracts the go/packages loading for dependency scanning.
type PackageLoader interface {
	Load(cfg *packages.Config, patterns ...string) ([]*packages.Package, error)
}
