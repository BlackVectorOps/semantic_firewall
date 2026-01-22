package semanticfw

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

// Key prefixes simulate logical buckets in Pebble's flat key space.
// Format: prefix:key -> value
// This design allows efficient prefix scans while maintaining logical separation.
var (
	prefixSignatures = []byte("sig:")   // Master storage: sig:ID -> Gob/JSON blob
	prefixIdxTopo    = []byte("topo:")  // Index: topo:TopologyHash:ID -> PackedIndexValue
	prefixIdxFuzzy   = []byte("fuzzy:") // Index: fuzzy:FuzzyHash:ID -> PackedIndexValue
	prefixIdxEntropy = []byte("entr:")  // Index: entr:EntropyKey -> ID
	prefixMeta       = []byte("meta:")  // Metadata: meta:key -> value
)

// packedIndexMagic is the prefix byte used to distinguish optimized index entries
// (containing entropy data) from legacy index entries (containing only ID strings).
// ASCII characters (legacy IDs) never start with 0x01.
const packedIndexMagic byte = 0x01

// PebbleScanner performs semantic malware detection using CockroachDB's Pebble
// for persistent storage. Pebble's LSM tree architecture provides:
//   - No CGO dependency (pure Go)
//   - No page level locking (high concurrency)
//   - Optimized for heavy read / high throughput workloads (CI/CD pipeline scale)
//   - Built in compression (LZ4/Snappy/ZSTD)
//
// Supports O(1) exact topology matching and O(M) fuzzy entropy range scans.
type PebbleScanner struct {
	db               *pebble.DB
	matchThreshold   float64
	entropyTolerance float64
	mu               sync.RWMutex // Protects threshold/tolerance updates and concurrent metadata writes
}

// PebbleScannerOptions configures the PebbleScanner initialization.
type PebbleScannerOptions struct {
	MatchThreshold   float64 // Minimum confidence for alerts (default: 0.75)
	EntropyTolerance float64 // Entropy fuzzy match window (default: 0.5)
	ReadOnly         bool    // Open DB in read-only mode for scanning only
	CacheSize        int64   // Block cache size in bytes (default: 8MB)
}

// DefaultPebbleScannerOptions returns sensible defaults for production use.
func DefaultPebbleScannerOptions() PebbleScannerOptions {
	return PebbleScannerOptions{
		MatchThreshold:   0.75,
		EntropyTolerance: 0.5,
		ReadOnly:         false,
		CacheSize:        8 << 20, // 8MB cache
	}
}

// NewPebbleScanner opens or creates a Pebble backed signature database.
// The database directory will be created if it doesn't exist.
func NewPebbleScanner(dbPath string, opts PebbleScannerOptions) (*PebbleScanner, error) {
	if opts.MatchThreshold == 0 {
		opts.MatchThreshold = 0.75
	}
	if opts.EntropyTolerance == 0 {
		opts.EntropyTolerance = 0.5
	}
	if opts.CacheSize == 0 {
		opts.CacheSize = 8 << 20
	}

	// Check for directory existence in ReadOnly mode
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

	db, err := pebble.Open(dbPath, pebbleOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to open signature db %q: %w", dbPath, err)
	}

	return &PebbleScanner{
		db:               db,
		matchThreshold:   opts.MatchThreshold,
		entropyTolerance: opts.EntropyTolerance,
	}, nil
}

// Close flushes all pending writes and closes the database.
// Always call this when done to prevent data loss.
func (s *PebbleScanner) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Updates the minimum confidence threshold for alerts.
func (s *PebbleScanner) SetThreshold(threshold float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matchThreshold = threshold
}

// Updates the entropy fuzzy match window.
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

// -- INDEX OPTIMIZATION HELPERS --

// encodeIndexValue packs the ID and entropy data into a byte slice.
// Format: [Magic(1b)] [Score(8b)] [Tol(8b)] [ID(bytes...)]
// This allows filtering by entropy directly from the index without loading the full signature.
func encodeIndexValue(id string, score, tol float64) []byte {
	// Size: 1 (Magic) + 8 (Score) + 8 (Tol) + len(ID)
	buf := make([]byte, 17+len(id))
	buf[0] = packedIndexMagic
	binary.LittleEndian.PutUint64(buf[1:9], math.Float64bits(score))
	binary.LittleEndian.PutUint64(buf[9:17], math.Float64bits(tol))
	copy(buf[17:], id)
	return buf
}

// decodeIndexValue unpacks the index.
// Returns: id, score, tol, validPacked (bool).
// If validPacked is false, the entry is legacy (just an ID string).
func decodeIndexValue(data []byte) (string, float64, float64, bool) {
	// Legacy IDs (strings) won't start with 0x01 (Start of Heading)
	if len(data) >= 17 && data[0] == packedIndexMagic {
		score := math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))
		tol := math.Float64frombits(binary.LittleEndian.Uint64(data[9:17]))
		id := string(data[17:])
		return id, score, tol, true
	}
	// Fallback for legacy data
	return string(data), 0, 0, false
}

// -- STORAGE HELPERS --

// decodeSignature transparently handles both legacy JSON and optimized Gob formats.
// This ensures backward compatibility without downtime.
func decodeSignature(data []byte, sig *Signature) error {
	if len(data) == 0 {
		return fmt.Errorf("empty signature data")
	}
	// Check for JSON start character '{'
	if data[0] == '{' {
		return json.Unmarshal(data, sig)
	}
	// Default to Gob (faster, binary)
	buf := bytes.NewReader(data)
	return gob.NewDecoder(buf).Decode(sig)
}

// -- ITERATOR HELPER --

// createSafeIterator wraps s.db.NewIter to provide error handling and enforce safe usage patterns.
func (s *PebbleScanner) createSafeIterator(opts *pebble.IterOptions) (*pebble.Iterator, error) {
	iter, err := s.db.NewIter(opts)
	if err != nil {
		return nil, fmt.Errorf("pebble iterator creation failed: %w", err)
	}
	return iter, nil
}

// -- KEY CONSTRUCTION HELPERS --

// Returns the key for a signature record.
func buildSignatureKey(id string) []byte {
	return append(append([]byte(nil), prefixSignatures...), []byte(id)...)
}

// Returns the composite key for topology index.
func buildTopoIndexKey(topoHash, id string) []byte {
	return []byte(fmt.Sprintf("%s%s:%s", prefixIdxTopo, topoHash, id))
}

// Returns the composite key for fuzzy hash index.
func buildFuzzyIndexKey(fuzzyHash, id string) []byte {
	return []byte(fmt.Sprintf("%s%s:%s", prefixIdxFuzzy, fuzzyHash, id))
}

// Returns the key for entropy index.
func buildEntropyIndexKey(entropy float64, id string) []byte {
	return []byte(fmt.Sprintf("%s%s", prefixIdxEntropy, formatEntropyKey(entropy, id)))
}

// Formats entropy and ID into a sortable key string
func formatEntropyKey(entropy float64, id string) string {
	return fmt.Sprintf("%08.4f:%s", entropy, id)
}

// WRITE PATH: Indexing (Learning Phase)

// Atomically saves a signature and updates all indexes.
// Safe for concurrent use. Uses Pebble's WriteBatch for atomic writes.
// OPTIMIZATION: Writes Gob (faster storage) and Packed Index (faster lookups).
func (s *PebbleScanner) AddSignature(sig Signature) error {
	// Generate ID if not provided
	if sig.ID == "" {
		id, err := generatePebbleRandomID()
		if err != nil {
			return err
		}
		sig.ID = fmt.Sprintf("SFW-AUTO-%s", id)
	}

	// Validate required fields
	if sig.TopologyHash == "" {
		return fmt.Errorf("signature %q missing required TopologyHash", sig.ID)
	}

	sigKey := buildSignatureKey(sig.ID)

	// Check for existing signature to clean up stale indexes
	var oldSig Signature
	hasOldSig := false
	if existingData, closer, err := s.db.Get(sigKey); err == nil {
		// Use dual-mode decoder to safely read existing data (JSON or Gob)
		if err := decodeSignature(existingData, &oldSig); err == nil {
			hasOldSig = true
		}
		closer.Close()
	} else if err != pebble.ErrNotFound {
		return fmt.Errorf("failed to check existing signature %q: %w", sig.ID, err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	// 0. Cleanup old indexes if they differ
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

	// 1. Serialize and save master record using Gob (Optimization)
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(sig); err != nil {
		return fmt.Errorf("encode signature %q: %w", sig.ID, err)
	}
	if err := batch.Set(sigKey, buf.Bytes(), pebble.Sync); err != nil {
		return fmt.Errorf("store signature %q: %w", sig.ID, err)
	}

	// Prepare packed index value [Magic|Score|Tol|ID] (Optimization)
	packedValue := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)

	// 2. Update topology index
	topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
	if err := batch.Set(topoKey, packedValue, pebble.Sync); err != nil {
		return fmt.Errorf("index topology for %q: %w", sig.ID, err)
	}

	// 3. Index using Fuzzy Hash
	if sig.FuzzyHash != "" {
		fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
		if err := batch.Set(fuzzyKey, packedValue, pebble.Sync); err != nil {
			return fmt.Errorf("index fuzzy hash for %q: %w", sig.ID, err)
		}
	}

	// 4. Update entropy index (Range scan, just ID is sufficient usually)
	entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
	if err := batch.Set(entropyKey, []byte(sig.ID), pebble.Sync); err != nil {
		return fmt.Errorf("index entropy for %q: %w", sig.ID, err)
	}

	return batch.Commit(pebble.Sync)
}

// Atomically adds multiple signatures in a single batch.
func (s *PebbleScanner) AddSignatures(sigs []Signature) error {
	batch := s.db.NewBatch()
	defer batch.Close()

	for i := range sigs {
		sig := &sigs[i]

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

		sigKey := buildSignatureKey(sig.ID)

		// Check for existing signature
		if existingData, closer, err := s.db.Get(sigKey); err == nil {
			var oldSig Signature
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

		// Encode with Gob
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

// Removes a signature and its index entries atomically.
func (s *PebbleScanner) DeleteSignature(id string) error {
	sigKey := buildSignatureKey(id)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return fmt.Errorf("signature %q not found", id)
		}
		return fmt.Errorf("read signature %q: %w", id, err)
	}
	defer closer.Close()

	var sig Signature
	if err := decodeSignature(data, &sig); err != nil {
		return fmt.Errorf("decode signature %q: %w", id, err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	// Delete from indexes
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

	// Delete master record
	if err := batch.Delete(sigKey, pebble.Sync); err != nil {
		return fmt.Errorf("delete signature %q: %w", id, err)
	}

	return batch.Commit(pebble.Sync)
}

// Updates a signature to record that it caused a false positive.
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

	var sig Signature
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

// READ PATH: Scanning (Hunter Phase)

// Checks a function topology against the signature database using two phases:
//   - Phase A (O(K)): Exact topology hash lookup (iterating collisions)
//   - Phase B (O(K)): Fuzzy bucket index lookup (LSH lite)
//
// OPTIMIZED:
// 1. Reads packed index values to perform lightweight entropy filtering.
// 2. Skips expensive database reads and decoding for candidates outside entropy tolerance.
func (s *PebbleScanner) ScanTopology(topo *FunctionTopology, funcName string) ([]ScanResult, error) {
	if topo == nil {
		return nil, nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	entropyTolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := generateTopologyHash(topo)
	fuzzyHash := GenerateFuzzyHash(topo)

	var results []ScanResult
	seen := make(map[string]bool)

	// Helper to reduce code duplication in loop
	processCandidate := func(idxValue []byte) {
		sigID, sigScore, sigTol, isPacked := decodeIndexValue(idxValue)
		if seen[sigID] {
			return
		}

		// FAST FILTER: Check entropy distance before loading signature
		// Only possible if index was packed (new format).
		// If legacy, we must load to be safe.
		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = entropyTolerance
			}
			// Safe O(1) pruning without disk I/O
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				// Skip expensive DB load and decode
				return
			}
		}

		seen[sigID] = true
		if res := s.loadAndMatchPebble([]byte(sigID), topo, funcName, threshold, entropyTolerance); res != nil {
			results = append(results, *res)
		}
	}

	// --- PHASE 1: EXACT TOPOLOGY MATCH (O(K)) ---
	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: incrementLastByte(topoPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}
		processCandidate(iter.Value())
	}

	// --- PHASE 2: FUZZY BUCKET INDEX (LSH lite) ---
	fuzzyPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxFuzzy, fuzzyHash))
	fuzzyIter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: fuzzyPrefix,
		UpperBound: incrementLastByte(fuzzyPrefix),
	})
	if err != nil {
		return results, err
	}
	defer fuzzyIter.Close()

	for fuzzyIter.First(); fuzzyIter.Valid(); fuzzyIter.Next() {
		if !bytes.HasPrefix(fuzzyIter.Key(), fuzzyPrefix) {
			break
		}
		processCandidate(fuzzyIter.Value())
	}

	// Sort by confidence (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results, nil
}

// Loads a signature and matches it against the topology.
// OPTIMIZED: Uses dual-mode decoder (Gob/JSON).
func (s *PebbleScanner) loadAndMatchPebble(sigID []byte, topo *FunctionTopology, funcName string, threshold, tolerance float64) *ScanResult {
	sigKey := append(append([]byte(nil), prefixSignatures...), sigID...)
	sigData, closer, err := s.db.Get(sigKey)
	if err != nil {
		return nil
	}
	defer closer.Close()

	var sig Signature
	if err := decodeSignature(sigData, &sig); err != nil {
		return nil
	}

	res := s.matchSignaturePebble(topo, funcName, sig, tolerance)
	if res.Confidence >= threshold {
		return &res
	}
	return nil
}

// Performs only exact topology hash matching (fastest).
func (s *PebbleScanner) ScanTopologyExact(topo *FunctionTopology, funcName string) (*ScanResult, error) {
	if topo == nil {
		return nil, nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	tolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := generateTopologyHash(topo)
	var bestResult *ScanResult

	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: incrementLastByte(topoPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}

		// Fast Filter Logic
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
		sigData, closer, err := s.db.Get(sigKey)
		if err != nil {
			continue
		}

		var sig Signature
		if err := decodeSignature(sigData, &sig); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		res := s.matchSignaturePebble(topo, funcName, sig, tolerance)
		if res.Confidence >= threshold {
			if bestResult == nil || res.Confidence > bestResult.Confidence {
				r := res
				bestResult = &r
			}
		}
	}

	return bestResult, nil
}

// Retrieves a signature by ID.
func (s *PebbleScanner) GetSignature(id string) (*Signature, error) {
	sigKey := buildSignatureKey(id)
	data, closer, err := s.db.Get(sigKey)
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, fmt.Errorf("signature %q not found", id)
		}
		return nil, fmt.Errorf("read signature %q: %w", id, err)
	}
	defer closer.Close()

	sig := &Signature{}
	if err := decodeSignature(data, sig); err != nil {
		return nil, fmt.Errorf("decode signature %q: %w", id, err)
	}
	return sig, nil
}

// Retrieves the first signature matching a topology hash.
func (s *PebbleScanner) GetSignatureByTopology(topoHash string) (*Signature, error) {
	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: incrementLastByte(topoPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if !iter.First() {
		return nil, fmt.Errorf("no signature with topology hash %q", topoHash)
	}
	// Bound check
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

	sig := &Signature{}
	if err := decodeSignature(data, sig); err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return sig, nil
}

// Returns the number of signatures in the database.
func (s *PebbleScanner) CountSignatures() (int, error) {
	count := 0
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: incrementLastByte(prefixSignatures),
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

// ListSignatureIDs returns all signature IDs.
func (s *PebbleScanner) ListSignatureIDs() ([]string, error) {
	var ids []string
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: incrementLastByte(prefixSignatures),
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

// -- IMPORT / EXPORT --

// MigrateFromJSON imports signatures directly from a JSON file.
// FIX: Uses streaming decoder to prevent OOM on large datasets.
// NOTE: Reads JSON (external), Writes Gob (internal).
func (s *PebbleScanner) MigrateFromJSON(jsonPath string) (int, error) {
	f, err := os.Open(jsonPath)
	if err != nil {
		return 0, fmt.Errorf("open json file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)

	// Navigate to the "signatures" array in the JSON object
	t, err := dec.Token() // {
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
			var batch []Signature

			for dec.More() {
				var sig Signature
				if err := dec.Decode(&sig); err != nil {
					return processed, fmt.Errorf("decode signature error: %w", err)
				}
				batch = append(batch, sig)

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
			if err != nil {
				// Non-fatal
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

// ExportToJSON exports all signatures to a JSON file.
// NOTE: Reads Gob (internal), Writes JSON (external).
func (s *PebbleScanner) ExportToJSON(jsonPath string) error {
	var sigs []Signature
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: incrementLastByte(prefixSignatures),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}
		var sig Signature
		if err := decodeSignature(iter.Value(), &sig); err != nil {
			return fmt.Errorf("corrupt signature data: %w", err)
		}
		sigs = append(sigs, sig)
	}

	export := struct {
		Version    string      `json:"version"`
		Generated  time.Time   `json:"generated_at"`
		Signatures []Signature `json:"signatures"`
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

// -- HELPER FUNCTIONS --

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
	return nil
}

func (s *PebbleScanner) matchSignaturePebble(topo *FunctionTopology, funcName string, sig Signature, tolerance float64) ScanResult {
	result := ScanResult{
		SignatureID:     sig.ID,
		SignatureName:   sig.Name,
		Severity:        sig.Severity,
		MatchedFunction: funcName,
	}
	var scores []float64
	details := MatchDetails{}

	currentHash := generateTopologyHash(topo)
	if currentHash == sig.TopologyHash {
		details.TopologyMatch = true
		details.TopologySimilarity = 1.0
		scores = append(scores, 1.0)
	} else {
		similarity := computeTopologySimilarity(topo, sig)
		details.TopologySimilarity = similarity
		details.TopologyMatch = similarity > 0.8
		scores = append(scores, similarity)
	}

	sigTol := sig.EntropyTolerance
	if sigTol == 0 {
		sigTol = tolerance
	}

	entropyDist := EntropyDistance(topo.EntropyScore, sig.EntropyScore)
	details.EntropyDistance = entropyDist
	details.EntropyMatch = entropyDist <= sigTol
	if details.EntropyMatch {
		entropyScore := 1.0 - (entropyDist / sigTol)
		scores = append(scores, entropyScore)
	} else {
		scores = append(scores, 0.5)
	}

	if len(sig.IdentifyingFeatures.RequiredCalls) > 0 {
		callScore, matched, missing := matchCalls(topo, sig.IdentifyingFeatures.RequiredCalls)
		details.CallsMatched = matched
		details.CallsMissing = missing
		if len(missing) > 0 {
			result.Confidence = 0.0
			result.MatchDetails = details
			return result
		}
		scores = append(scores, callScore)
	}

	if len(sig.IdentifyingFeatures.StringPatterns) > 0 {
		stringScore, matched := matchStrings(topo, sig.IdentifyingFeatures.StringPatterns)
		details.StringsMatched = matched
		if stringScore > 0 {
			scores = append(scores, stringScore)
		}
	}

	if len(scores) > 0 {
		var total float64
		for _, sc := range scores {
			total += sc
		}
		result.Confidence = total / float64(len(scores))
	}
	result.MatchDetails = details
	return result
}

// -- DATABASE MAINTENANCE --

// Recreates all indexes from master signature records.
// IMPORTANT: Reads legacy or Gob records and writes Packed index values.
func (s *PebbleScanner) RebuildIndexes() error {
	var sigs []Signature
	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixSignatures,
		UpperBound: incrementLastByte(prefixSignatures),
	})
	if err != nil {
		return err
	}

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), prefixSignatures) {
			break
		}
		var sig Signature
		if err := decodeSignature(iter.Value(), &sig); err != nil {
			iter.Close()
			return fmt.Errorf("decode signature: %w", err)
		}
		sigs = append(sigs, sig)
	}
	iter.Close()

	// Delete all existing index entries
	batch := s.db.NewBatch()
	defer batch.Close()

	cleanupPrefix := func(prefix []byte) {
		it, err := s.createSafeIterator(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: incrementLastByte(prefix),
		})
		if err == nil {
			for it.First(); it.Valid(); it.Next() {
				if !bytes.HasPrefix(it.Key(), prefix) {
					break
				}
				batch.Delete(it.Key(), pebble.Sync)
			}
			it.Close()
		}
	}

	cleanupPrefix(prefixIdxTopo)
	cleanupPrefix(prefixIdxFuzzy)
	cleanupPrefix(prefixIdxEntropy)

	// Rebuild indexes
	for _, sig := range sigs {
		packedValue := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)

		topoKey := buildTopoIndexKey(sig.TopologyHash, sig.ID)
		if err := batch.Set(topoKey, packedValue, pebble.Sync); err != nil {
			return err
		}

		if sig.FuzzyHash != "" {
			fuzzyKey := buildFuzzyIndexKey(sig.FuzzyHash, sig.ID)
			if err := batch.Set(fuzzyKey, packedValue, pebble.Sync); err != nil {
				return err
			}
		}

		entropyKey := buildEntropyIndexKey(sig.EntropyScore, sig.ID)
		if err := batch.Set(entropyKey, []byte(sig.ID), pebble.Sync); err != nil {
			return err
		}
	}

	return batch.Commit(pebble.Sync)
}

// Triggers a manual compaction to reclaim space.
func (s *PebbleScanner) Compact() error {
	return s.db.Compact(nil, []byte{0xff}, true)
}

// PebbleScannerStats contains database statistics.
type PebbleScannerStats struct {
	SignatureCount    int
	TopoIndexCount    int
	FuzzyIndexCount   int
	EntropyIndexCount int
	DiskSpaceUsed     int64
}

// Returns database statistics.
func (s *PebbleScanner) Stats() (*PebbleScannerStats, error) {
	stats := &PebbleScannerStats{}

	countPrefix := func(prefix []byte) int {
		c := 0
		iter, err := s.createSafeIterator(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: incrementLastByte(prefix),
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

// -- ENTROPY RANGE SCANNING -- (Advanced Feature)

// Finds signatures within an entropy score range.
func (s *PebbleScanner) ScanByEntropyRange(minEntropy, maxEntropy float64) ([]Signature, error) {
	var results []Signature

	minKey := []byte(fmt.Sprintf("%s%08.4f:", prefixIdxEntropy, minEntropy))
	maxKey := []byte(fmt.Sprintf("%s%08.4f:", prefixIdxEntropy, maxEntropy+0.0001))

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
		results = append(results, *sig)
	}

	return results, nil
}

// -- SNAPSHOT & CHECKPOINT -- (For CI/CD Integration)

// Creates a durable snapshot of the database.
func (s *PebbleScanner) Checkpoint() error {
	return s.db.Flush()
}

// Returns a read only snapshot of the database at a point in time.
func (s *PebbleScanner) GetSnapshot() *pebble.Snapshot {
	return s.db.NewSnapshot()
}

// Scans using a specific snapshot (for consistent reads).
func (s *PebbleScanner) ScanTopologyWithSnapshot(snap *pebble.Snapshot, topo *FunctionTopology, funcName string) ([]ScanResult, error) {
	if topo == nil || snap == nil {
		return nil, nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	tolerance := s.entropyTolerance
	s.mu.RUnlock()

	topoHash := generateTopologyHash(topo)
	fuzzyHash := GenerateFuzzyHash(topo)

	var results []ScanResult
	seen := make(map[string]bool)

	// Phase 1: Exact topology match
	topoPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxTopo, topoHash))
	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: topoPrefix,
		UpperBound: incrementLastByte(topoPrefix),
	})
	if err != nil {
		return nil, err
	}

	for iter.First(); iter.Valid(); iter.Next() {
		if !bytes.HasPrefix(iter.Key(), topoPrefix) {
			break
		}

		// Decode packed index
		sigID, sigScore, sigTol, isPacked := decodeIndexValue(iter.Value())
		if seen[sigID] {
			continue
		}

		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = tolerance
			}
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				continue
			}
		}

		seen[sigID] = true
		sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
		sigData, closer, err := snap.Get(sigKey)
		if err != nil {
			continue
		}

		var sig Signature
		if err := decodeSignature(sigData, &sig); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		res := s.matchSignaturePebble(topo, funcName, sig, tolerance)
		if res.Confidence >= threshold {
			results = append(results, res)
		}
	}
	iter.Close()

	// Phase 2: Fuzzy bucket match
	fuzzyPrefix := []byte(fmt.Sprintf("%s%s:", prefixIdxFuzzy, fuzzyHash))
	fuzzyIter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: fuzzyPrefix,
		UpperBound: incrementLastByte(fuzzyPrefix),
	})
	if err != nil {
		return results, err
	}

	for fuzzyIter.First(); fuzzyIter.Valid(); fuzzyIter.Next() {
		if !bytes.HasPrefix(fuzzyIter.Key(), fuzzyPrefix) {
			break
		}
		sigID, sigScore, sigTol, isPacked := decodeIndexValue(fuzzyIter.Value())
		if seen[sigID] {
			continue
		}

		if isPacked {
			effectiveTol := sigTol
			if effectiveTol == 0 {
				effectiveTol = tolerance
			}
			if math.Abs(sigScore-topo.EntropyScore) > effectiveTol {
				continue
			}
		}

		seen[sigID] = true
		sigKey := append(append([]byte(nil), prefixSignatures...), []byte(sigID)...)
		sigData, closer, err := snap.Get(sigKey)
		if err != nil {
			continue
		}

		var sig Signature
		if err := decodeSignature(sigData, &sig); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		res := s.matchSignaturePebble(topo, funcName, sig, tolerance)
		if res.Confidence >= threshold {
			results = append(results, res)
		}
	}
	fuzzyIter.Close()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results, nil
}

// -- BATCH SCANNING -- (Optimized for CI/CD Pipelines)

// Scans multiple topologies efficiently using parallel lookups.
func (s *PebbleScanner) ScanBatch(topologies map[string]*FunctionTopology) map[string][]ScanResult {
	results := make(map[string][]ScanResult)

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

// -- METADATA STORAGE -- (Database versioning and provenance)

// DatabaseMetadata contains information about the signature database.
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
	metaKey := buildMetaKey(key)
	return s.db.Delete(metaKey, pebble.Sync)
}

func (s *PebbleScanner) GetAllMetadata() (*DatabaseMetadata, error) {
	meta := &DatabaseMetadata{
		Custom: make(map[string]string),
	}

	iter, err := s.createSafeIterator(&pebble.IterOptions{
		LowerBound: prefixMeta,
		UpperBound: incrementLastByte(prefixMeta),
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
				if t, err := time.Parse(time.RFC3339, value); err == nil {
					meta.CreatedAt = t
				}
			case "last_updated_at":
				if t, err := time.Parse(time.RFC3339, value); err == nil {
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
	batch := s.db.NewBatch()
	defer batch.Close()

	if meta.Version != "" {
		batch.Set(buildMetaKey("version"), []byte(meta.Version), pebble.Sync)
	}
	if meta.Description != "" {
		batch.Set(buildMetaKey("description"), []byte(meta.Description), pebble.Sync)
	}
	if !meta.CreatedAt.IsZero() {
		batch.Set(buildMetaKey("created_at"), []byte(meta.CreatedAt.Format(time.RFC3339)), pebble.Sync)
	}
	if !meta.LastUpdatedAt.IsZero() {
		batch.Set(buildMetaKey("last_updated_at"), []byte(meta.LastUpdatedAt.Format(time.RFC3339)), pebble.Sync)
	}
	if meta.SourceHash != "" {
		batch.Set(buildMetaKey("source_hash"), []byte(meta.SourceHash), pebble.Sync)
	}
	for k, v := range meta.Custom {
		batch.Set(buildMetaKey(k), []byte(v), pebble.Sync)
	}

	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) InitializeMetadata(version, description string) error {
	now := time.Now()
	meta := &DatabaseMetadata{
		Version:       version,
		Description:   description,
		CreatedAt:     now,
		LastUpdatedAt: now,
	}
	return s.SetAllMetadata(meta)
}

func (s *PebbleScanner) TouchLastUpdated() error {
	return s.SetMetadata("last_updated_at", time.Now().Format(time.RFC3339))
}
