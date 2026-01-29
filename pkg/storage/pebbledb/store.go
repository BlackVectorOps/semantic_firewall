package pebbledb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"github.com/cockroachdb/pebble"
)

// Key prefixes simulate logical buckets in Pebble's flat key space.
// Keep these short to minimize storage overhead per key.
var (
	prefixSignatures = []byte("sig:")   // Master storage: sig:ID -> Gob/JSON blob
	prefixIdxTopo    = []byte("topo:")  // Index: topo:TopologyHash:ID -> PackedIndexValue
	prefixIdxFuzzy   = []byte("fuzzy:") // Index: fuzzy:FuzzyHash:ID -> PackedIndexValue
	prefixIdxEntropy = []byte("entr:")  // Index: entr:EntropyKey -> ID
	prefixMeta       = []byte("meta:")  // Metadata: meta:key -> value
)

const (
	packedIndexMagic byte = 0x01

	// CurrentDBVersion tracks the semantic version of the data format.
	CurrentDBVersion = "3.0.0"

	// CurrentSchemaVersion enforces binary compatibility.
	// Increment this only if the fundamental serialization format (e.g. Gob struct shape) changes.
	CurrentSchemaVersion = 3

	// BatchSizeLimitBytes limits the memory usage of a batch before commit (10MB).
	BatchSizeLimitBytes = 10 * 1024 * 1024
)

// PebbleScanner performs semantic malware detection using CockroachDB's Pebble.
// It leverages LSM trees for high write throughput and efficient range scans.
type PebbleScanner struct {
	db               *pebble.DB
	matchThreshold   float64
	entropyTolerance float64
	mu               sync.RWMutex
}

// PebbleScannerOptions configures the PebbleScanner initialization.
type PebbleScannerOptions struct {
	MatchThreshold   float64
	EntropyTolerance float64
	ReadOnly         bool
	CacheSize        int64
}

// DefaultPebbleScannerOptions returns sensible defaults for a standard deployment.
func DefaultPebbleScannerOptions() PebbleScannerOptions {
	return PebbleScannerOptions{
		MatchThreshold:   0.75,
		EntropyTolerance: 0.5,
		ReadOnly:         false,
		CacheSize:        8 << 20, // 8MB cache
	}
}

// NewPebbleScanner opens or creates a Pebble backed signature database.
// It includes retry logic to handle transient file locks common in containerized environments.
func NewPebbleScanner(dbPath string, opts PebbleScannerOptions) (*PebbleScanner, error) {
	// 1. Path Sanitization
	// We prevent the engine from initializing in sensitive system roots.
	// This captures cases where a misconfigured env var points the DB to /etc or /root.
	absPath, err := filepath.EvalSymlinks(dbPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to resolve absolute path for db: %w", err)
		}
		absPath, _ = filepath.Abs(dbPath)
	}
	// Restricts database operations to non critical directories.
	// Initializing a database in system roots could allow an attacker
	// to overwrite binaries or configurations if the process has elevated privileges.
	if runtime.GOOS == "linux" {
		sensitivePrefixes := []string{"/etc", "/root", "/usr", "/bin", "/sbin", "/boot"}
		for _, sp := range sensitivePrefixes {
			if strings.HasPrefix(absPath, sp) {
				return nil, fmt.Errorf("security violation: refusing to initialize database in system directory %q", absPath)
			}
		}
	}

	if opts.MatchThreshold == 0 {
		opts.MatchThreshold = 0.75
	}
	if opts.EntropyTolerance == 0 {
		opts.EntropyTolerance = 0.5
	}
	if opts.CacheSize == 0 {
		opts.CacheSize = 8 << 20
	}

	if opts.ReadOnly {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("database does not exist: %s", dbPath)
		}
	}

	pebbleOpts := &pebble.Options{
		Cache: pebble.NewCache(opts.CacheSize),
	}
	if opts.ReadOnly {
		pebbleOpts.ReadOnly = true
	}

	// Critical Fix: PebbleDB Locking and Concurrency
	// We implement a retry loop here because automated pipelines or rapid restarts
	// often leave the lock file explicitly held for a few milliseconds.
	var db *pebble.DB
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		db, err = pebble.Open(dbPath, pebbleOpts)
		if err == nil {
			break
		}

		// Check for Pebble lock error strings or general IO temporary errors
		if strings.Contains(err.Error(), "lock") || strings.Contains(err.Error(), "temporarily unavailable") {
			// Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1.6s
			time.Sleep(100 * time.Millisecond * time.Duration(1<<i))
			continue
		}

		// Fatal error (e.g. corruption, permission)
		return nil, fmt.Errorf("failed to open signature db %q: %w", dbPath, err)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to acquire db lock for %q after %d attempts: %w", dbPath, maxRetries, err)
	}

	scanner := &PebbleScanner{
		db:               db,
		matchThreshold:   opts.MatchThreshold,
		entropyTolerance: opts.EntropyTolerance,
	}

	// Schema Version Check
	// This prevents a newer binary from corrupting an older database format,
	// or an older binary from reading a newer format it doesn't understand.
	metaVerStr, err := scanner.GetMetadata("schema_version")
	if err == nil && metaVerStr != "" {
		var dbVer int
		if _, scanErr := fmt.Sscanf(metaVerStr, "%d", &dbVer); scanErr == nil {
			if dbVer > CurrentSchemaVersion {
				db.Close()
				return nil, fmt.Errorf("database schema version %d is newer than binary supported version %d; please upgrade sfw", dbVer, CurrentSchemaVersion)
			}
		}
	} else if !opts.ReadOnly {
		// Initialize schema version for new/legacy databases
		if err := scanner.SetMetadata("schema_version", fmt.Sprintf("%d", CurrentSchemaVersion)); err != nil {
			// Non-fatal, logging would happen in the caller
		}
	}

	return scanner, nil
}

func (s *PebbleScanner) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *PebbleScanner) SetThreshold(threshold float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matchThreshold = threshold
}

func (s *PebbleScanner) SetEntropyTolerance(tolerance float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entropyTolerance = tolerance
}

func generatePebbleRandomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// encodeIndexValue packs the score and tolerance into the value.
// This allows us to filter candidates *before* loading the full signature blob,
// saving massive amounts of IOPS during high volume scans.
func encodeIndexValue(id string, score, tol float64) []byte {
	buf := make([]byte, 17+len(id))
	buf[0] = packedIndexMagic
	binary.LittleEndian.PutUint64(buf[1:9], math.Float64bits(score))
	binary.LittleEndian.PutUint64(buf[9:17], math.Float64bits(tol))
	copy(buf[17:], id)
	return buf
}

func decodeIndexValue(data []byte) (string, float64, float64, bool) {
	if len(data) >= 17 && data[0] == packedIndexMagic {
		score := math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))
		tol := math.Float64frombits(binary.LittleEndian.Uint64(data[9:17]))
		id := string(data[17:])
		return id, score, tol, true
	}
	// Fallback for legacy non packed indexes
	return string(data), 0, 0, false
}

func decodeSignature(data []byte, sig *detection.Signature) error {
	if len(data) == 0 {
		return fmt.Errorf("empty signature data")
	}
	// Support both legacy JSON and new Gob format seamlessly
	if data[0] == '{' {
		return json.Unmarshal(data, sig)
	}

	buf := bytes.NewReader(data)
	return gob.NewDecoder(buf).Decode(sig)
}

func (s *PebbleScanner) createSafeIterator(opts *pebble.IterOptions) (*pebble.Iterator, error) {
	iter, err := s.db.NewIter(opts)
	if err != nil {
		return nil, fmt.Errorf("pebble iterator creation failed: %w", err)
	}
	return iter, nil
}

func buildSignatureKey(id string) []byte {
	return append(append([]byte(nil), prefixSignatures...), []byte(id)...)
}

func buildTopoIndexKey(topoHash, id string) []byte {
	return []byte(fmt.Sprintf("%s%s:%s", prefixIdxTopo, topoHash, id))
}

func buildFuzzyIndexKey(fuzzyHash, id string) []byte {
	return []byte(fmt.Sprintf("%s%s:%s", prefixIdxFuzzy, fuzzyHash, id))
}

func buildEntropyIndexKey(entropy float64, id string) []byte {
	return []byte(fmt.Sprintf("%s%s", prefixIdxEntropy, FormatEntropyKey(entropy, id)))
}

func FormatEntropyKey(entropy float64, id string) string {
	return fmt.Sprintf("%08.4f:%s", entropy, id)
}

// AddSignature atomically saves a signature and updates all indexes.
// It uses a pointer to update the ID if it was auto generated.
func (s *PebbleScanner) AddSignature(sig *detection.Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sig.ID == "" {
		id, err := generatePebbleRandomID()
		if err != nil {
			return err
		}
		sig.ID = fmt.Sprintf("SFW-AUTO-%s", id)
	}

	if sig.TopologyHash == "" {
		return fmt.Errorf("signature %q missing required TopologyHash", sig.ID)
	}

	sigKey := buildSignatureKey(sig.ID)

	// We need to check for an existing signature to clean up old index entries.
	// Failing to do this causes "index drift" where a signature is reachable
	// via multiple topology hashes.
	var oldSig detection.Signature
	hasOldSig := false

	if existingData, closer, err := s.db.Get(sigKey); err == nil {
		if err := decodeSignature(existingData, &oldSig); err == nil {
			hasOldSig = true
		}
		closer.Close()
	} else if err != pebble.ErrNotFound {
		return fmt.Errorf("failed to check existing signature %q: %w", sig.ID, err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	if hasOldSig {
		if oldSig.TopologyHash != sig.TopologyHash {
			batch.Delete(buildTopoIndexKey(oldSig.TopologyHash, oldSig.ID), nil)
		}
		if oldSig.FuzzyHash != sig.FuzzyHash && oldSig.FuzzyHash != "" {
			batch.Delete(buildFuzzyIndexKey(oldSig.FuzzyHash, oldSig.ID), nil)
		}
		if oldSig.EntropyScore != sig.EntropyScore {
			batch.Delete(buildEntropyIndexKey(oldSig.EntropyScore, oldSig.ID), nil)
		}
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(sig); err != nil {
		return fmt.Errorf("encode signature %q: %w", sig.ID, err)
	}

	if err := batch.Set(sigKey, buf.Bytes(), pebble.Sync); err != nil {
		return fmt.Errorf("store signature %q: %w", sig.ID, err)
	}

	packedValue := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)
	topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
	if err := batch.Set(topoKey, packedValue, pebble.Sync); err != nil {
		return fmt.Errorf("index topology for %q: %w", sig.ID, err)
	}

	if sig.FuzzyHash != "" {
		fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
		if err := batch.Set(fuzzyKey, packedValue, pebble.Sync); err != nil {
			return fmt.Errorf("index fuzzy hash for %q: %w", sig.ID, err)
		}
	}

	entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
	if err := batch.Set(entropyKey, []byte(sig.ID), pebble.Sync); err != nil {
		return fmt.Errorf("index entropy for %q: %w", sig.ID, err)
	}

	return batch.Commit(pebble.Sync)
}

// AddSignatures adds multiple signatures in a single batch.
// Takes pointers to allow ID propagation.
func (s *PebbleScanner) AddSignatures(sigs []*detection.Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Assign IDs and validate
	for _, sig := range sigs {
		if sig.ID == "" {
			id, err := generatePebbleRandomID()
			if err != nil {
				return err
			}
			sig.ID = fmt.Sprintf("SFW-AUTO-%s", id)
		}
		if sig.TopologyHash == "" {
			return fmt.Errorf("signature %q missing TopologyHash", sig.ID)
		}
	}

	// 2. Deduplicate: Identify the last index for each ID to prevent stale index corruption in the batch.
	lastIdx := make(map[string]int)
	for i, sig := range sigs {
		lastIdx[sig.ID] = i
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	for i, sig := range sigs {
		// Only process the final version of a specific ID in this batch
		if lastIdx[sig.ID] != i {
			continue
		}

		sigKey := buildSignatureKey(sig.ID)

		// Check DB for existing signature to clean up indexes (Pre-Batch state)
		if existingData, closer, err := s.db.Get(sigKey); err == nil {
			var oldSig detection.Signature
			if decodeSignature(existingData, &oldSig) == nil {
				if oldSig.TopologyHash != sig.TopologyHash {
					batch.Delete(buildTopoIndexKey(oldSig.TopologyHash, oldSig.ID), nil)
				}
				if oldSig.FuzzyHash != sig.FuzzyHash && oldSig.FuzzyHash != "" {
					batch.Delete(buildFuzzyIndexKey(oldSig.FuzzyHash, oldSig.ID), nil)
				}
				if oldSig.EntropyScore != sig.EntropyScore {
					batch.Delete(buildEntropyIndexKey(oldSig.EntropyScore, oldSig.ID), nil)
				}
			}
			closer.Close()
		}

		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(sig); err != nil {
			return fmt.Errorf("encode signature %q: %w", sig.ID, err)
		}

		if err := batch.Set(sigKey, buf.Bytes(), pebble.Sync); err != nil {
			return fmt.Errorf("store signature %q: %w", sig.ID, err)
		}

		packedValue := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)
		topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
		if err := batch.Set(topoKey, packedValue, pebble.Sync); err != nil {
			return fmt.Errorf("index topology %q: %w", sig.ID, err)
		}

		if sig.FuzzyHash != "" {
			fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
			if err := batch.Set(fuzzyKey, packedValue, pebble.Sync); err != nil {
				return fmt.Errorf("index fuzzy hash %q: %w", sig.ID, err)
			}
		}

		entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
		if err := batch.Set(entropyKey, []byte(sig.ID), pebble.Sync); err != nil {
			return fmt.Errorf("index entropy %q: %w", sig.ID, err)
		}
	}

	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) DeleteSignature(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sigKey := buildSignatureKey(id)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return fmt.Errorf("signature %q not found", id)
		}
		return fmt.Errorf("read signature %q: %w", id, err)
	}
	defer closer.Close()

	var sig detection.Signature
	if err := decodeSignature(data, &sig); err != nil {
		return fmt.Errorf("decode signature %q: %w", id, err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
	if err := batch.Delete(topoKey, pebble.Sync); err != nil {
		return fmt.Errorf("delete topology index %q: %w", id, err)
	}

	if sig.FuzzyHash != "" {
		fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
		if err := batch.Delete(fuzzyKey, pebble.Sync); err != nil {
			return fmt.Errorf("delete fuzzy index %q: %w", id, err)
		}
	}

	entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
	if err := batch.Delete(entropyKey, pebble.Sync); err != nil {
		return fmt.Errorf("delete entropy index %q: %w", id, err)
	}

	if err := batch.Delete(sigKey, pebble.Sync); err != nil {
		return fmt.Errorf("delete signature %q: %w", id, err)
	}

	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) MarkFalsePositive(id string, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sigKey := buildSignatureKey(id)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return fmt.Errorf("signature %q not found", id)
		}
		return fmt.Errorf("read signature %q: %w", id, err)
	}
	defer closer.Close()

	var sig detection.Signature
	if err := decodeSignature(data, &sig); err != nil {
		return fmt.Errorf("decode signature %q: %w", id, err)
	}

	fpNote := fmt.Sprintf("FP:%s:%s", time.Now().Format(time.RFC3339), notes)
	sig.Metadata.References = append(sig.Metadata.References, fpNote)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(sig); err != nil {
		return fmt.Errorf("encode updated signature %q: %w", id, err)
	}

	return s.db.Set(sigKey, buf.Bytes(), pebble.Sync)
}

// ScanCandidates implements the SignatureProvider interface.
// Uses a snapshot to ensure consistent view between Index Scan and Data Retrieval.
func (s *PebbleScanner) ScanCandidates(topo *topology.FunctionTopology) ([]*detection.Signature, error) {
	if topo == nil {
		return nil, nil
	}

	s.mu.RLock()
	entropyTolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := detection.GenerateTopologyHash(topo)
	fuzzyHash := topology.GenerateFuzzyHash(topo)

	var candidates []*detection.Signature
	seen := make(map[string]bool)

	// Create a consistent snapshot
	snap := s.db.NewSnapshot()
	defer snap.Close()

	// Helper to process index entries using the snapshot
	processCandidate := func(idxValue []byte) {
		sigID, sigScore, sigTol, isPacked := decodeIndexValue(idxValue)
		if seen[sigID] {
			return
		}

		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = entropyTolerance
			}
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				return
			}
		}

		seen[sigID] = true
		sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
		sigData, closer, err := snap.Get(sigKey)
		if err != nil {
			return // skip missing
		}
		defer closer.Close()

		var sig detection.Signature
		if err := decodeSignature(sigData, &sig); err == nil {
			cp := sig
			candidates = append(candidates, &cp)
		}
	}

	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	upperTopo := incrementLastByte(topoPrefix)
	// Safety check: if incrementLastByte returns nil (prefix was all 0xFF),
	// we fail to avoid an unbounded scan.
	if upperTopo == nil {
		return nil, fmt.Errorf("scan range overflow for topo prefix: %x", topoPrefix)
	}

	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: upperTopo,
	})
	if err != nil {
		return nil, err
	}
	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}
		processCandidate(iter.Value())
	}
	iter.Close()

	fuzzyPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxFuzzy, fuzzyHash))
	upperFuzzy := incrementLastByte(fuzzyPrefix)
	if upperFuzzy == nil {
		return candidates, fmt.Errorf("scan range overflow for fuzzy prefix: %x", fuzzyPrefix)
	}

	fuzzyIter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: fuzzyPrefix,
		UpperBound: upperFuzzy,
	})
	if err != nil {
		return candidates, err
	}
	for fuzzyIter.First(); fuzzyIter.Valid(); fuzzyIter.Next() {
		if !bytes.HasPrefix(fuzzyIter.Key(), fuzzyPrefix) {
			break
		}
		processCandidate(fuzzyIter.Value())
	}
	fuzzyIter.Close()

	return candidates, nil
}

// ScanTopology checks a function topology against the signature database.
// Refactored to wrapper around ScanTopologyWithSnapshot to centralize logic.
func (s *PebbleScanner) ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	snap := s.db.NewSnapshot()
	defer snap.Close()
	return s.ScanTopologyWithSnapshot(snap, topo, funcName)
}

// ScanTopologyExact performs a high speed lookup for exact topology hash matches.
// It bypasses the fuzzy index entirely for performance critical paths.
func (s *PebbleScanner) ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error) {
	if topo == nil {
		return nil, nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	tolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := detection.GenerateTopologyHash(topo)
	var bestResult *detection.ScanResult

	snap := s.db.NewSnapshot()
	defer snap.Close()

	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	upper := incrementLastByte(topoPrefix)
	if upper == nil {
		return nil, fmt.Errorf("scan range overflow for topo prefix: %x", topoPrefix)
	}

	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: upper,
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}

		sigID, sigScore, sigTol, isPacked := decodeIndexValue(iter.Value())

		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = tolerance
			}
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				continue
			}
		}

		sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
		sigData, closer, err := snap.Get(sigKey)
		if err != nil {
			continue
		}

		var sig detection.Signature
		if err := decodeSignature(sigData, &sig); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		res := detection.MatchSignature(topo, funcName, sig, tolerance)
		if res.Confidence >= threshold {
			if bestResult == nil || res.Confidence > bestResult.Confidence {
				r := res
				bestResult = &r
			}
		}
	}

	return bestResult, nil
}

func (s *PebbleScanner) GetSignature(id string) (*detection.Signature, error) {
	sigKey := buildSignatureKey(id)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, fmt.Errorf("signature %q not found", id)
		}
		return nil, fmt.Errorf("read signature %q: %w", id, err)
	}
	defer closer.Close()

	sig := &detection.Signature{}
	if err := decodeSignature(data, sig); err != nil {
		return nil, fmt.Errorf("decode signature %q: %w", id, err)
	}
	return sig, nil
}

func (s *PebbleScanner) GetSignatureByTopology(topoHash string) (*detection.Signature, error) {
	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	upper := incrementLastByte(topoPrefix)
	if upper == nil {
		return nil, fmt.Errorf("scan range overflow for topo prefix: %x", topoPrefix)
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: upper,
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if !iter.First() {
		return nil, fmt.Errorf("no signature with topology hash %q", topoHash)
	}
	if !bytes.HasPrefix(iter.Key(), topoPrefix) {
		return nil, fmt.Errorf("no signature with topology hash %q", topoHash)
	}

	sigID, _, _, _ := decodeIndexValue(iter.Value())
	sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		return nil, fmt.Errorf("signature %q not found", sigID)
	}
	defer closer.Close()

	sig := &detection.Signature{}
	if err := decodeSignature(data, sig); err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	return sig, nil
}

func (s *PebbleScanner) CountSignatures() (int, error) {
	count := 0
	upper := incrementLastByte(prefixSignatures)
	if upper == nil {
		return 0, fmt.Errorf("scan range overflow for signature prefix")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: upper,
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}
		count++
	}
	return count, nil
}

func (s *PebbleScanner) ListSignatureIDs() ([]string, error) {
	var ids []string
	upper := incrementLastByte(prefixSignatures)
	if upper == nil {
		return nil, fmt.Errorf("scan range overflow for signature prefix")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: upper,
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}
		key := iter.Key()
		if len(key) > len(prefixSignatures) {
			ids = append(ids, string(key[len(prefixSignatures):]))
		}
	}
	return ids, nil
}

func (s *PebbleScanner) MigrateFromJSON(jsonPath string) (int, error) {
	f, err := os.Open(jsonPath)
	if err != nil {
		return 0, fmt.Errorf("open json file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	t, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("invalid json start: %w", err)
	}

	processed := 0
	foundSigs := false

	for dec.More() {
		t, err = dec.Token()
		if err != nil {
			return processed, err
		}
		key, ok := t.(string)
		if !ok {
			continue
		}

		if key == "signatures" {
			foundSigs = true
			t, err = dec.Token() // [
			if err != nil {
				return processed, err
			}

			batchSize := 1000
			var batch []*detection.Signature

			for dec.More() {
				var sig detection.Signature
				if err := dec.Decode(&sig); err != nil {
					return processed, fmt.Errorf("decode signature error: %w", err)
				}
				batch = append(batch, &sig)

				if len(batch) >= batchSize {
					if err := s.AddSignatures(batch); err != nil {
						return processed, fmt.Errorf("batch import failed: %w", err)
					}
					processed += len(batch)
					batch = batch[:0]
				}
			}

			if len(batch) > 0 {
				if err := s.AddSignatures(batch); err != nil {
					return processed, fmt.Errorf("final batch import failed: %w", err)
				}
				processed += len(batch)
			}

			t, err = dec.Token() // ]
			// FIX: Check if we hit EOF unexpectedly (truncated file) or any other error.
			if err != nil {
				if err == io.EOF {
					return processed, fmt.Errorf("unexpected EOF; missing closing ']' for signatures array")
				}
				return processed, fmt.Errorf("error reading closing bracket for signatures: %w", err)
			}
		} else {
			var ignore interface{}
			dec.Decode(&ignore)
		}
	}

	if !foundSigs {
		return 0, fmt.Errorf("json file missing 'signatures' array")
	}

	return processed, nil
}

func (s *PebbleScanner) ExportToJSON(jsonPath string) error {
	var sigs []detection.Signature

	upper := incrementLastByte(prefixSignatures)
	if upper == nil {
		return fmt.Errorf("scan range overflow for signature prefix")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: upper,
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}
		var sig detection.Signature
		if err := decodeSignature(iter.Value(), &sig); err != nil {
			return fmt.Errorf("corrupt signature data: %w", err)
		}
		sigs = append(sigs, sig)
	}

	export := struct {
		Version    string                `json:"version"`
		Generated  time.Time             `json:"generated_at"`
		Signatures []detection.Signature `json:"signatures"`
	}{
		Version:    "2.1 (Pebble/Gob+PackedIdx)",
		Generated:  time.Now(),
		Signatures: sigs,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export data: %w", err)
	}

	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}

	return nil
}

func incrementLastByte(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	result := make([]byte, len(prefix))
	copy(result, prefix)
	for i := len(result) - 1; i >= 0; i-- {
		if result[i] < 0xff {
			result[i]++
			return result
		}
		result[i] = 0
	}
	// If the entire prefix is 0xFF, there is no upper bound.
	// The iterator will need to rely on the loop condition (bytes.HasPrefix).
	// Callers must check for nil to avoid scanning the entire subsequent keyspace unexpectedly.
	return nil
}

// RebuildIndexes clears and rebuilds all indexes.
// Optimized to stream signatures instead of loading all into memory.
func (s *PebbleScanner) RebuildIndexes() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Use a batch for deletions and updates to ensure atomicity where possible,
	// though for massive rebuilds we commit in chunks.
	batch := s.db.NewBatch()

	// Helper to batch commit operations
	commitBatch := func() error {
		if err := batch.Commit(pebble.Sync); err != nil {
			batch.Close()
			return err
		}
		batch.Close()
		batch = s.db.NewBatch()
		return nil
	}

	// Ensure the current batch is closed on exit if not committed
	defer func() {
		if batch != nil {
			batch.Close()
		}
	}()

	// Step 1: Clear existing indexes using Range Delete.
	// We use DeleteRange for O(1) metadata deletion of the entire index space.
	// This is vastly superior to iterating keys and inserting tombstones for each one.
	prefixes := [][]byte{prefixIdxTopo, prefixIdxFuzzy, prefixIdxEntropy}
	for _, prefix := range prefixes {
		// Calculate the upper bound for the prefix
		endKey := incrementLastByte(prefix)
		if endKey == nil {
			// This effectively shouldn't happen with our ascii prefixes, but if it does,
			// we can't use DeleteRange safely on the whole keyspace without a valid end.
			// Falling back to manual iteration would be the safe play here,
			// but we return an error to highlight the anomaly.
			return fmt.Errorf("unable to calculate range end for prefix %x", prefix)
		}

		if err := batch.DeleteRange(prefix, endKey, nil); err != nil {
			return fmt.Errorf("batch delete range failed: %w", err)
		}
	}

	// Commit the mass deletion before starting the rebuild
	if err := commitBatch(); err != nil {
		return err
	}

	// Step 2: Iterate Signatures and Re-Index.
	// Stream signatures to avoid loading everything into RAM (OOM Fix).
	upper := incrementLastByte(prefixSignatures)
	if upper == nil {
		return fmt.Errorf("rebuild failed: prefix overflow")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: upper,
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}

		var sig detection.Signature
		if err := decodeSignature(iter.Value(), &sig); err != nil {
			// Fail hard on corruption to prevent silent index loss.
			return fmt.Errorf("corrupt signature encountered during rebuild: %w", err)
		}

		packedValue := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)

		topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
		batch.Set(topoKey, packedValue, nil)

		if sig.FuzzyHash != "" {
			fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
			batch.Set(fuzzyKey, packedValue, nil)
		}

		entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
		batch.Set(entropyKey, []byte(sig.ID), nil)

		count++
		// Commit periodically to keep batch size manageable.
		// Added check for Batch length (approx 10MB) to prevent large allocations.
		if count >= 1000 || batch.Len() > BatchSizeLimitBytes {
			if err := commitBatch(); err != nil {
				return err
			}
			count = 0
		}
	}

	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) Compact() error {
	return s.db.Compact(nil, []byte{0xff}, true)
}

type PebbleScannerStats struct {
	SignatureCount    int
	TopoIndexCount    int
	FuzzyIndexCount   int
	EntropyIndexCount int
	DiskSpaceUsed     int64
}

func (s *PebbleScanner) Stats() (*PebbleScannerStats, error) {
	stats := &PebbleScannerStats{}

	countPrefix := func(prefix []byte) int {
		c := 0
		upper := incrementLastByte(prefix)
		if upper == nil {
			return 0
		}
		iter, err := s.createSafeIterator(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: upper,
		})
		if err != nil {
			return 0
		}
		for iter.First(); iter.Valid(); iter.Next() {
			if !bytes.HasPrefix(iter.Key(), prefix) {
				break
			}
			c++
		}
		iter.Close()
		return c
	}

	stats.SignatureCount = countPrefix(prefixSignatures)
	stats.TopoIndexCount = countPrefix(prefixIdxTopo)
	stats.FuzzyIndexCount = countPrefix(prefixIdxFuzzy)
	stats.EntropyIndexCount = countPrefix(prefixIdxEntropy)

	metrics := s.db.Metrics()
	stats.DiskSpaceUsed = int64(metrics.DiskSpaceUsage())

	return stats, nil
}

func (s *PebbleScanner) ScanByEntropyRange(minEntropy, maxEntropy float64) ([]detection.Signature, error) {
	var results []detection.Signature

	// We format the keys to match the layout in buildEntropyIndexKey: "entr:0.1234:ID"
	minKey := []byte(fmt.Sprintf("%s%08.4f", prefixIdxEntropy, minEntropy))

	// To establish a strict upper bound, we format the max entropy string and
	// then increment its last byte. This ensures we capture all IDs associated with
	// that specific entropy value (e.g. "entr:0.5000:zzzz") without spilling over
	// into 0.5001.
	maxKeyStr := fmt.Sprintf("%s%08.4f", prefixIdxEntropy, maxEntropy)
	maxKey := incrementLastByte([]byte(maxKeyStr))
	if maxKey == nil {
		return nil, fmt.Errorf("scan failed: entropy range upper bound overflow")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: minKey,
		UpperBound: maxKey,
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seen := make(map[string]bool)

	for iter.First(); iter.Valid(); iter.Next() {
		sigID := string(iter.Value())

		if seen[sigID] {
			continue
		}
		seen[sigID] = true

		sig, err := s.GetSignature(sigID)
		if err != nil {
			continue
		}

		// Double check entropy to ensure index consistency/precision safety
		if sig.EntropyScore < minEntropy || sig.EntropyScore > maxEntropy {
			continue
		}

		results = append(results, *sig)
	}

	return results, nil
}

func (s *PebbleScanner) Checkpoint() error {
	return s.db.Flush()
}

func (s *PebbleScanner) GetSnapshot() *pebble.Snapshot {
	return s.db.NewSnapshot()
}

// Allows scanning using an external snapshot for multi threaded consistency.
// This is used by batch processors to view the DB at a single point in time.
func (s *PebbleScanner) ScanTopologyWithSnapshot(snap *pebble.Snapshot, topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	if topo == nil || snap == nil {
		return nil, nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	tolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := detection.GenerateTopologyHash(topo)
	fuzzyHash := topology.GenerateFuzzyHash(topo)

	var results []detection.ScanResult
	seen := make(map[string]bool)

	// Define a closure to process index hits, keeping the
	// iteration logic clean and avoiding code duplication between Exact and Fuzzy scans.
	processHit := func(idxValue []byte) {
		sigID, sigScore, sigTol, isPacked := decodeIndexValue(idxValue)
		if seen[sigID] {
			return
		}

		// Check entropy score without loading the full signature
		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = tolerance
			}
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				return
			}
		}

		seen[sigID] = true
		sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
		sigData, closer, err := snap.Get(sigKey)
		if err != nil {
			return
		}
		defer closer.Close()

		var sig detection.Signature
		if err := decodeSignature(sigData, &sig); err != nil {
			return
		}

		res := detection.MatchSignature(topo, funcName, sig, tolerance)
		if res.Confidence >= threshold {
			results = append(results, res)
		}
	}

	// 1. Scan Exact Topology Matches
	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	upperTopo := incrementLastByte(topoPrefix)
	if upperTopo == nil {
		return nil, fmt.Errorf("scan failed: topology prefix overflow")
	}

	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: upperTopo,
	})
	if err != nil {
		return nil, err
	}
	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}
		processHit(iter.Value())
	}
	iter.Close()

	// 2. Scan Fuzzy Topology Matches
	fuzzyPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxFuzzy, fuzzyHash))
	upperFuzzy := incrementLastByte(fuzzyPrefix)
	if upperFuzzy == nil {
		// Just return what we have if fuzzy prefix is invalid
		return results, fmt.Errorf("scan failed: fuzzy prefix overflow")
	}

	fuzzyIter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: fuzzyPrefix,
		UpperBound: upperFuzzy,
	})
	if err != nil {
		return results, err
	}
	for fuzzyIter.First(); fuzzyIter.Valid(); fuzzyIter.Next() {
		if !bytes.HasPrefix(fuzzyIter.Key(), fuzzyPrefix) {
			break
		}
		processHit(fuzzyIter.Value())
	}
	fuzzyIter.Close()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results, nil
}

func (s *PebbleScanner) ScanBatch(topologies map[string]*topology.FunctionTopology) map[string][]detection.ScanResult {
	results := make(map[string][]detection.ScanResult)

	snap := s.db.NewSnapshot()
	defer snap.Close()

	for funcName, topo := range topologies {
		if topo == nil {
			continue
		}
		scanResults, err := s.ScanTopologyWithSnapshot(snap, topo, funcName)
		if err == nil && len(scanResults) > 0 {
			results[funcName] = scanResults
		}
	}

	return results
}

type DatabaseMetadata struct {
	Version        string            `json:"version"`
	Description    string            `json:"description"`
	CreatedAt      time.Time         `json:"created_at"`
	LastUpdatedAt  time.Time         `json:"last_updated_at"`
	SignatureCount int               `json:"signature_count"`
	SourceHash     string            `json:"source_hash"`
	Custom         map[string]string `json:"custom,omitempty"`
}

func buildMetaKey(key string) []byte {
	return append(append([]byte(nil), prefixMeta...), []byte(key)...)
}

func (s *PebbleScanner) SetMetadata(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	metaKey := buildMetaKey(key)
	return s.db.Set(metaKey, []byte(value), pebble.Sync)
}

func (s *PebbleScanner) GetMetadata(key string) (string, error) {
	metaKey := buildMetaKey(key)
	data, closer, err := s.db.Get(metaKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return "", fmt.Errorf("metadata key %q not found", key)
		}
		return "", fmt.Errorf("read metadata %q: %w", key, err)
	}
	defer closer.Close()
	return string(data), nil
}

func (s *PebbleScanner) DeleteMetadata(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	metaKey := buildMetaKey(key)
	return s.db.Delete(metaKey, pebble.Sync)
}

func (s *PebbleScanner) GetAllMetadata() (*DatabaseMetadata, error) {
	meta := &DatabaseMetadata{
		Custom: make(map[string]string),
	}

	upper := incrementLastByte(prefixMeta)
	if upper == nil {
		return nil, fmt.Errorf("metadata list failed: prefix overflow")
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixMeta,
		UpperBound: upper,
	})
	if err == nil {
		for iter.First(); iter.Valid(); iter.Next() {
			if !bytes.HasPrefix(iter.Key(), prefixMeta) {
				break
			}
			key := string(iter.Key()[len(prefixMeta):])
			value := string(iter.Value())

			switch key {
			case "version":
				meta.Version = value
			case "description":
				meta.Description = value
			case "created_at":
				if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
					meta.CreatedAt = t
				}
			case "last_updated_at":
				if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
					meta.LastUpdatedAt = t
				}
			case "source_hash":
				meta.SourceHash = value
			default:
				meta.Custom[key] = value
			}
		}
		iter.Close()
	}

	count, _ := s.CountSignatures()
	meta.SignatureCount = count
	return meta, nil
}

func (s *PebbleScanner) SetAllMetadata(meta *DatabaseMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch := s.db.NewBatch()
	defer batch.Close()

	if meta.Version != "" {
		batch.Set(buildMetaKey("version"), []byte(meta.Version), pebble.Sync)
	}
	if meta.Description != "" {
		batch.Set(buildMetaKey("description"), []byte(meta.Description), pebble.Sync)
	}
	if !meta.CreatedAt.IsZero() {
		batch.Set(buildMetaKey("created_at"), []byte(meta.CreatedAt.Format(time.RFC3339Nano)), pebble.Sync)
	}
	if !meta.LastUpdatedAt.IsZero() {
		batch.Set(buildMetaKey("last_updated_at"), []byte(meta.LastUpdatedAt.Format(time.RFC3339Nano)), pebble.Sync)
	}
	if meta.SourceHash != "" {
		batch.Set(buildMetaKey("source_hash"), []byte(meta.SourceHash), pebble.Sync)
	}

	if meta.Custom == nil {
		meta.Custom = make(map[string]string)
	}
	meta.Custom["version"] = CurrentDBVersion

	for k, v := range meta.Custom {
		batch.Set(buildMetaKey(k), []byte(v), pebble.Sync)
	}

	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) InitializeMetadata(version, description string) error {
	// Fix: Check existing metadata first to preserve CreatedAt
	existing, _ := s.GetAllMetadata()
	now := time.Now()

	createdAt := existing.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	meta := &DatabaseMetadata{
		Version:       version,
		Description:   description,
		CreatedAt:     createdAt,
		LastUpdatedAt: now,
	}

	// Set schema version if not present
	if meta.Custom == nil {
		meta.Custom = make(map[string]string)
	}
	meta.Custom["version"] = CurrentDBVersion

	return s.SetAllMetadata(meta)
}

func (s *PebbleScanner) TouchLastUpdated() error {
	return s.SetMetadata("last_updated_at", time.Now().Format(time.RFC3339Nano))
}
