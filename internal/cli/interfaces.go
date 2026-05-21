// -- internal/cli/interfaces.go --
package cli

import (
	"context"
	"io"

	"github.com/BlackVectorOps/semantic_firewall/v4/internal/sandbox"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/detection"
	"golang.org/x/tools/go/packages"
)

// FileSystem is re-exported from pkg/api so external integrations
// (e.g. the MCP server) and internal callers see the same type.
type FileSystem = api.FileSystem

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
