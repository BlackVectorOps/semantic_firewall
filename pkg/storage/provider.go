package storage

import (
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
)

// SignatureProvider defines the contract for signature persistence and retrieval.
// This abstraction allows the engine to remain agnostic of the underlying storage
// implementation while ensuring security and performance constraints are met.
type SignatureProvider interface {
	GetSignature(id string) (*detection.Signature, error)
	ScanCandidates(topo *topology.FunctionTopology) ([]*detection.Signature, error)
	// AddSignature accepts a pointer to allow ID propagation back to the caller.
	// This is vital for maintaining a single source of truth for auto generated IDs.
	AddSignature(sig *detection.Signature) error
}
