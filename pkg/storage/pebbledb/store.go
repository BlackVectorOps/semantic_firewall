package pebbledb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pathguard"
	"github.com/cockroachdb/pebble"
)

// Key prefixes divide Pebble's flat key space into logical buckets.
var (
	prefixSignatures = []byte("sig:")   // sig:ID -> gob (or legacy JSON) signature
	prefixIdxTopo    = []byte("topo:")  // topo:TopologyHash:ID -> packed index value
	prefixIdxFuzzy   = []byte("fuzzy:") // fuzzy:FuzzyHash:ID -> packed index value
	prefixIdxEntropy = []byte("entr:")  // entr:%08.4f:ID -> ID
	prefixMeta       = []byte("meta:")  // meta:key -> value
)

const (
	packedIndexMagic byte = 0x01

	// CurrentSchemaVersion enforces database compatibility. A database whose
	// stored version differs from this constant is rejected: a newer version
	// cannot be understood, and an older version holds fingerprints produced by
	// an incompatible algorithm. Increment this whenever the serialization
	// format (Gob struct shape) OR the fingerprint/canonicalization algorithm
	// changes, since either makes previously stored signatures unmatchable.
	CurrentSchemaVersion = 4

	// rebuildBatchBytes bounds a RebuildIndexes batch before it is committed.
	rebuildBatchBytes = 10 * 1024 * 1024
)

// PebbleScanner is a signature store in a Pebble (LSM-tree) database:
// signatures keyed by ID, plus topology, fuzzy-hash and entropy indexes.
type PebbleScanner struct {
	db               *pebble.DB
	matchThreshold   float64
	entropyTolerance float64
	// mu serializes writers, whose index updates read the stored signature
	// first, and guards the two settings above.
	mu sync.RWMutex
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

// openRetries is how many times NewPebbleScanner tries to take the
// database's lock, waiting 100ms, 200ms, ... before each retry: a process
// that just closed the database may hold the lock file briefly.
const openRetries = 5

// NewPebbleScanner opens or creates a Pebble backed signature database.
func NewPebbleScanner(dbPath string, opts PebbleScannerOptions) (*PebbleScanner, error) {
	// Writable opens are refused inside system directories. Read-only opens
	// are exempt: reading a shared database from a system location is a
	// supported install layout.
	if !opts.ReadOnly {
		if err := pathguard.CheckWritable(dbPath); err != nil {
			return nil, err
		}
	}

	if opts.MatchThreshold == 0 {
		opts.MatchThreshold = 0.75
	}
	// NaN would fail every comparison and suppress every alert.
	if math.IsNaN(opts.MatchThreshold) || opts.MatchThreshold < 0 || opts.MatchThreshold > 1 {
		return nil, fmt.Errorf("match threshold must be between 0.0 and 1.0, got: %v", opts.MatchThreshold)
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

	// The cache starts with one reference, which Open adds to and Close
	// drops; release the creator's so Close frees it.
	cache := pebble.NewCache(opts.CacheSize)
	defer cache.Unref()
	pebbleOpts := &pebble.Options{Cache: cache, ReadOnly: opts.ReadOnly}

	var db *pebble.DB
	var err error
	for i := 0; i < openRetries; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond << (i - 1))
		}
		db, err = pebble.Open(dbPath, pebbleOpts)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "lock") && !strings.Contains(err.Error(), "temporarily unavailable") {
			return nil, fmt.Errorf("failed to open signature db %q: %w", dbPath, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to acquire db lock for %q after %d attempts: %w", dbPath, openRetries, err)
	}

	scanner := &PebbleScanner{
		db:               db,
		matchThreshold:   opts.MatchThreshold,
		entropyTolerance: opts.EntropyTolerance,
	}
	if err := scanner.checkSchema(opts.ReadOnly); err != nil {
		db.Close()
		return nil, err
	}
	return scanner, nil
}

// checkSchema refuses a database written under another schema version and
// records the current version in a writable database that has none (a new
// or legacy one).
func (s *PebbleScanner) checkSchema(readOnly bool) error {
	data, closer, err := s.db.Get(buildMetaKey("schema_version"))
	var stored string
	switch {
	case err == nil:
		stored = string(data)
		closer.Close()
	case !errors.Is(err, pebble.ErrNotFound):
		return fmt.Errorf("read schema version: %w", err)
	}
	if stored == "" {
		if readOnly {
			return nil
		}
		return s.SetMetadata("schema_version", strconv.Itoa(CurrentSchemaVersion))
	}
	dbVer, err := strconv.Atoi(stored)
	switch {
	case err != nil:
		return fmt.Errorf("database schema version %q is not a number", stored)
	case dbVer > CurrentSchemaVersion:
		return fmt.Errorf("database schema version %d is newer than binary supported version %d; please upgrade sfw", dbVer, CurrentSchemaVersion)
	case dbVer < CurrentSchemaVersion:
		// Signatures stored under an older schema were fingerprinted by a
		// prior canonicalization algorithm and would silently fail to match.
		// Rebuilding the indexes cannot fix this -- the stored TopologyHash
		// values themselves are stale -- so the database must be regenerated.
		return fmt.Errorf("database schema version %d is older than binary version %d; "+
			"its fingerprints are incompatible -- rebuild the database by re-indexing your samples with this version of sfw", dbVer, CurrentSchemaVersion)
	}
	return nil
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

func (s *PebbleScanner) settings() (threshold, tolerance float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchThreshold, s.entropyTolerance
}

func generatePebbleRandomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// encodeIndexValue packs the signature's entropy score and tolerance with
// its ID, so a scan can reject a candidate on entropy before loading it.
func encodeIndexValue(id string, score, tol float64) []byte {
	buf := make([]byte, 17+len(id))
	buf[0] = packedIndexMagic
	binary.LittleEndian.PutUint64(buf[1:9], math.Float64bits(score))
	binary.LittleEndian.PutUint64(buf[9:17], math.Float64bits(tol))
	copy(buf[17:], id)
	return buf
}

// decodeIndexValue unpacks an index value; a legacy value is the bare ID,
// with no entropy (packed false).
func decodeIndexValue(data []byte) (id string, score, tol float64, packed bool) {
	if len(data) >= 17 && data[0] == packedIndexMagic {
		score := math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))
		tol := math.Float64frombits(binary.LittleEndian.Uint64(data[9:17]))
		return string(data[17:]), score, tol, true
	}
	return string(data), 0, 0, false
}

// decodeSignature decodes a stored signature: gob, or JSON for a value
// written by an older release (one starting with '{').
func decodeSignature(data []byte, sig *detection.Signature) error {
	if len(data) == 0 {
		return fmt.Errorf("empty signature data")
	}
	if data[0] == '{' {
		return json.Unmarshal(data, sig)
	}
	return gob.NewDecoder(bytes.NewReader(data)).Decode(sig)
}

func encodeSignature(sig *detection.Signature) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(sig); err != nil {
		return nil, fmt.Errorf("encode signature %q: %w", sig.ID, err)
	}
	return buf.Bytes(), nil
}

func buildSignatureKey(id string) []byte {
	return append(append([]byte(nil), prefixSignatures...), id...)
}

func buildTopoIndexKey(topoHash, id string) []byte {
	return []byte(string(prefixIdxTopo) + topoHash + ":" + id)
}

func buildFuzzyIndexKey(fuzzyHash, id string) []byte {
	return []byte(string(prefixIdxFuzzy) + fuzzyHash + ":" + id)
}

// buildEntropyIndexKey formats the entropy with fixed width ("%08.4f"), so
// keys sort lexicographically in numeric order.
func buildEntropyIndexKey(entropy float64, id string) []byte {
	return []byte(fmt.Sprintf("%s%08.4f:%s", prefixIdxEntropy, entropy, id))
}

// withinTolerance reports whether a signature's entropy is close enough to
// the function's: within the signature's tolerance, or the scanner's when
// the signature sets none.
func withinTolerance(sigScore, sigTol, fnScore, defaultTol float64) bool {
	if sigTol == 0 {
		sigTol = defaultTol
	}
	// Written as "not beyond" so a NaN score or tolerance is admitted, as
	// the JSON store, which has no such gate, admits it.
	return !(math.Abs(sigScore-fnScore) > sigTol)
}

// prefixRange returns the iterator bounds covering every key with prefix.
// No prefix this package uses ends in 0xff, so the upper bound exists.
func prefixRange(prefix []byte) *pebble.IterOptions {
	upper := append([]byte(nil), prefix...)
	upper[len(upper)-1]++
	return &pebble.IterOptions{LowerBound: prefix, UpperBound: upper}
}

// reader is what scans read from: the database or a snapshot of it.
type reader interface {
	Get(key []byte) ([]byte, io.Closer, error)
	NewIter(o *pebble.IterOptions) (*pebble.Iterator, error)
}

// eachInPrefix calls fn with the key and value of every entry under prefix.
// fn must not retain them.
func eachInPrefix(r reader, prefix []byte, fn func(key, value []byte) error) error {
	iter, err := r.NewIter(prefixRange(prefix))
	if err != nil {
		return fmt.Errorf("pebble iterator creation failed: %w", err)
	}
	for iter.First(); iter.Valid(); iter.Next() {
		if err := fn(iter.Key(), iter.Value()); err != nil {
			iter.Close()
			return err
		}
	}
	return iter.Close()
}

// AddSignature saves sig and its index entries in one batch, first giving
// it an ID (SFW-AUTO-<16 hex>) when it has none.
func (s *PebbleScanner) AddSignature(sig *detection.Signature) error {
	return s.AddSignatures([]*detection.Signature{sig})
}

// AddSignatures saves sigs and their index entries in one batch, first
// giving each signature without an ID one. Of several signatures with one
// ID, the last is saved. Replacing a stored signature removes the index
// entries its old hashes and entropy left.
func (s *PebbleScanner) AddSignatures(sigs []*detection.Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sig := range sigs {
		if sig.ID == "" {
			id, err := generatePebbleRandomID()
			if err != nil {
				return err
			}
			sig.ID = "SFW-AUTO-" + id
		}
		if sig.TopologyHash == "" {
			return fmt.Errorf("signature %q missing required TopologyHash", sig.ID)
		}
	}

	last := make(map[string]int, len(sigs))
	for i, sig := range sigs {
		last[sig.ID] = i
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	for i, sig := range sigs {
		if last[sig.ID] != i {
			continue
		}
		sigKey := buildSignatureKey(sig.ID)

		existing, closer, err := s.db.Get(sigKey)
		switch {
		case err == nil:
			var old detection.Signature
			if decodeSignature(existing, &old) == nil {
				deleteStaleIndexes(batch, &old, sig)
			}
			closer.Close()
		case !errors.Is(err, pebble.ErrNotFound):
			return fmt.Errorf("failed to check existing signature %q: %w", sig.ID, err)
		}

		data, err := encodeSignature(sig)
		if err != nil {
			return err
		}
		if err := batch.Set(sigKey, data, nil); err != nil {
			return fmt.Errorf("store signature %q: %w", sig.ID, err)
		}
		if err := setIndexes(batch, sig); err != nil {
			return err
		}
	}

	return batch.Commit(pebble.Sync)
}

// deleteStaleIndexes deletes the index entries of old that sig, replacing
// it under the same ID, does not overwrite.
func deleteStaleIndexes(batch *pebble.Batch, old, sig *detection.Signature) {
	if old.TopologyHash != sig.TopologyHash {
		batch.Delete(buildTopoIndexKey(old.TopologyHash, old.ID), nil)
	}
	if old.FuzzyHash != sig.FuzzyHash && old.FuzzyHash != "" {
		batch.Delete(buildFuzzyIndexKey(old.FuzzyHash, old.ID), nil)
	}
	if old.EntropyScore != sig.EntropyScore {
		batch.Delete(buildEntropyIndexKey(old.EntropyScore, old.ID), nil)
	}
}

// setIndexes writes sig's topology, fuzzy-hash and entropy index entries.
func setIndexes(batch *pebble.Batch, sig *detection.Signature) error {
	packed := encodeIndexValue(sig.ID, sig.EntropyScore, sig.EntropyTolerance)
	if err := batch.Set(buildTopoIndexKey(sig.TopologyHash, sig.ID), packed, nil); err != nil {
		return fmt.Errorf("index topology for %q: %w", sig.ID, err)
	}
	if sig.FuzzyHash != "" {
		if err := batch.Set(buildFuzzyIndexKey(sig.FuzzyHash, sig.ID), packed, nil); err != nil {
			return fmt.Errorf("index fuzzy hash for %q: %w", sig.ID, err)
		}
	}
	if err := batch.Set(buildEntropyIndexKey(sig.EntropyScore, sig.ID), []byte(sig.ID), nil); err != nil {
		return fmt.Errorf("index entropy for %q: %w", sig.ID, err)
	}
	return nil
}

// readSignature loads the signature stored under id.
func readSignature(r reader, id string) (*detection.Signature, error) {
	data, closer, err := r.Get(buildSignatureKey(id))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
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

func (s *PebbleScanner) DeleteSignature(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig, err := readSignature(s.db, id)
	if err != nil {
		return err
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	batch.Delete(buildTopoIndexKey(sig.TopologyHash, sig.ID), nil)
	if sig.FuzzyHash != "" {
		batch.Delete(buildFuzzyIndexKey(sig.FuzzyHash, sig.ID), nil)
	}
	batch.Delete(buildEntropyIndexKey(sig.EntropyScore, sig.ID), nil)
	batch.Delete(buildSignatureKey(id), nil)
	return batch.Commit(pebble.Sync)
}

func (s *PebbleScanner) MarkFalsePositive(id string, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig, err := readSignature(s.db, id)
	if err != nil {
		return err
	}
	sig.Metadata.References = append(sig.Metadata.References,
		fmt.Sprintf("FP:%s:%s", time.Now().Format(time.RFC3339), notes))

	data, err := encodeSignature(sig)
	if err != nil {
		return err
	}
	return s.db.Set(buildSignatureKey(id), data, pebble.Sync)
}

// candidates calls fn with each signature indexed under the given prefixes,
// in index order and once per ID, whose entropy is within tolerance of
// topo's. A packed index entry is rejected on entropy before its signature
// is loaded; a legacy entry, after.
func candidates(r reader, topo *topology.FunctionTopology, tolerance float64, prefixes [][]byte, fn func(detection.Signature)) error {
	seen := make(map[string]bool)
	for _, prefix := range prefixes {
		err := eachInPrefix(r, prefix, func(_, value []byte) error {
			id, score, tol, packed := decodeIndexValue(value)
			if seen[id] {
				return nil
			}
			if packed && !withinTolerance(score, tol, topo.EntropyScore, tolerance) {
				return nil
			}
			seen[id] = true
			sig, err := readSignature(r, id)
			if err != nil {
				// Skip a candidate that cannot be loaded: a dangling index
				// entry, an undecodable record, or a failed read.
				return nil
			}
			if !packed && !withinTolerance(sig.EntropyScore, sig.EntropyTolerance, topo.EntropyScore, tolerance) {
				return nil
			}
			fn(*sig)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func topoPrefix(m detection.Matcher) []byte {
	return []byte(string(prefixIdxTopo) + m.Hash() + ":")
}

// ScanTopology returns the signatures in topo's topology and fuzzy-hash
// buckets that it matches at or above the threshold, most confident first.
// It reads one snapshot.
func (s *PebbleScanner) ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	if topo == nil {
		return nil, nil
	}
	threshold, tolerance := s.settings()
	snap := s.db.NewSnapshot()
	defer snap.Close()

	m := detection.NewMatcher(topo, funcName)
	fuzzyPrefix := []byte(string(prefixIdxFuzzy) + topology.GenerateFuzzyHash(topo) + ":")
	var results []detection.ScanResult
	err := candidates(snap, topo, tolerance, [][]byte{topoPrefix(m), fuzzyPrefix}, func(sig detection.Signature) {
		if res := m.Match(sig, tolerance); res.Confidence >= threshold {
			results = append(results, res)
		}
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})
	return results, nil
}

// ScanTopologyExact returns the most confident match at or above the
// threshold among the signatures in topo's topology bucket only, or nil.
func (s *PebbleScanner) ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error) {
	if topo == nil {
		return nil, nil
	}
	threshold, tolerance := s.settings()
	snap := s.db.NewSnapshot()
	defer snap.Close()

	m := detection.NewMatcher(topo, funcName)
	var best *detection.ScanResult
	err := candidates(snap, topo, tolerance, [][]byte{topoPrefix(m)}, func(sig detection.Signature) {
		res := m.Match(sig, tolerance)
		if res.Confidence >= threshold && (best == nil || res.Confidence > best.Confidence) {
			best = &res
		}
	})
	if err != nil {
		return nil, err
	}
	return best, nil
}

func (s *PebbleScanner) GetSignature(id string) (*detection.Signature, error) {
	return readSignature(s.db, id)
}

// GetSignatureByTopology returns the first signature in the topology
// bucket of topoHash.
func (s *PebbleScanner) GetSignatureByTopology(topoHash string) (*detection.Signature, error) {
	iter, err := s.db.NewIter(prefixRange([]byte(string(prefixIdxTopo) + topoHash + ":")))
	if err != nil {
		return nil, fmt.Errorf("pebble iterator creation failed: %w", err)
	}
	defer iter.Close()
	if !iter.First() {
		return nil, fmt.Errorf("no signature with topology hash %q", topoHash)
	}
	id, _, _, _ := decodeIndexValue(iter.Value())
	return readSignature(s.db, id)
}

func (s *PebbleScanner) CountSignatures() (int, error) {
	return countPrefix(s.db, prefixSignatures)
}

func countPrefix(r reader, prefix []byte) (int, error) {
	n := 0
	err := eachInPrefix(r, prefix, func(_, _ []byte) error {
		n++
		return nil
	})
	return n, err
}

func (s *PebbleScanner) ListSignatureIDs() ([]string, error) {
	var ids []string
	err := eachInPrefix(s.db, prefixSignatures, func(key, _ []byte) error {
		if len(key) > len(prefixSignatures) {
			ids = append(ids, string(key[len(prefixSignatures):]))
		}
		return nil
	})
	return ids, err
}

// MigrateFromJSON streams the signatures array of a JSON signature
// database into the store in batches of 1000, returning how many it saved.
func (s *PebbleScanner) MigrateFromJSON(jsonPath string) (int, error) {
	f, err := os.Open(jsonPath)
	if err != nil {
		return 0, fmt.Errorf("open json file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if _, err := dec.Token(); err != nil { // {
		return 0, fmt.Errorf("invalid json start: %w", err)
	}

	const batchSize = 1000
	processed := 0
	foundSigs := false

	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return processed, err
		}
		key, ok := t.(string)
		if !ok {
			continue
		}
		if key != "signatures" {
			var ignore any
			if err := dec.Decode(&ignore); err != nil {
				return processed, fmt.Errorf("decode %q: %w", key, err)
			}
			continue
		}

		foundSigs = true
		if _, err := dec.Token(); err != nil { // [
			return processed, err
		}
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
		if _, err := dec.Token(); err != nil { // ]
			if errors.Is(err, io.EOF) {
				return processed, fmt.Errorf("unexpected EOF; missing closing ']' for signatures array")
			}
			return processed, fmt.Errorf("error reading closing bracket for signatures: %w", err)
		}
	}

	if !foundSigs {
		return 0, fmt.Errorf("json file missing 'signatures' array")
	}
	return processed, nil
}

// ExportToJSON writes every signature in the JSON backend's format, so the
// export can be opened with --db <file>.json as well as re-imported with
// sfw migrate.
func (s *PebbleScanner) ExportToJSON(jsonPath string) error {
	if err := pathguard.CheckWritable(jsonPath); err != nil {
		return err
	}

	var sigs []detection.Signature
	err := eachInPrefix(s.db, prefixSignatures, func(_, value []byte) error {
		var sig detection.Signature
		if err := decodeSignature(value, &sig); err != nil {
			return fmt.Errorf("corrupt signature data: %w", err)
		}
		sigs = append(sigs, sig)
		return nil
	})
	if err != nil {
		return err
	}

	export := detection.SignatureDatabase{
		Version:     "1.0", // the JSON format's version, as jsondb writes it
		Description: "Exported from PebbleDB at " + time.Now().UTC().Format(time.RFC3339),
		Signatures:  sigs,
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

// RebuildIndexes deletes every index entry and rewrites them from the
// stored signatures, streaming the signatures and committing every 1000 or
// rebuildBatchBytes. It does not recompute hashes, and a failure partway
// leaves the indexes incomplete.
func (s *PebbleScanner) RebuildIndexes() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch := s.db.NewBatch()
	defer func() { batch.Close() }()
	commit := func() error {
		if err := batch.Commit(pebble.Sync); err != nil {
			return err
		}
		batch.Close()
		batch = s.db.NewBatch()
		return nil
	}

	for _, prefix := range [][]byte{prefixIdxTopo, prefixIdxFuzzy, prefixIdxEntropy} {
		r := prefixRange(prefix)
		if err := batch.DeleteRange(r.LowerBound, r.UpperBound, nil); err != nil {
			return fmt.Errorf("batch delete range failed: %w", err)
		}
	}
	if err := commit(); err != nil {
		return err
	}

	count := 0
	err := eachInPrefix(s.db, prefixSignatures, func(_, value []byte) error {
		var sig detection.Signature
		if err := decodeSignature(value, &sig); err != nil {
			// Fail hard on corruption rather than silently drop its entries.
			return fmt.Errorf("corrupt signature encountered during rebuild: %w", err)
		}
		if err := setIndexes(batch, &sig); err != nil {
			return err
		}
		count++
		if count >= 1000 || batch.Len() > rebuildBatchBytes {
			count = 0
			return commit()
		}
		return nil
	})
	if err != nil {
		return err
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
	for _, c := range []struct {
		prefix []byte
		n      *int
	}{
		{prefixSignatures, &stats.SignatureCount},
		{prefixIdxTopo, &stats.TopoIndexCount},
		{prefixIdxFuzzy, &stats.FuzzyIndexCount},
		{prefixIdxEntropy, &stats.EntropyIndexCount},
	} {
		n, err := countPrefix(s.db, c.prefix)
		if err != nil {
			return nil, err
		}
		*c.n = n
	}
	stats.DiskSpaceUsed = int64(s.db.Metrics().DiskSpaceUsage())
	return stats, nil
}

// ScanByEntropyRange returns the signatures whose entropy score is within
// [minEntropy, maxEntropy], read through the entropy index.
func (s *PebbleScanner) ScanByEntropyRange(minEntropy, maxEntropy float64) ([]detection.Signature, error) {
	// The upper bound is the formatted maximum with its last byte
	// incremented: every ID at that exact entropy ("entr:000.5000:zzzz")
	// sorts below it, and the next value (000.5001) does not.
	lower := []byte(fmt.Sprintf("%s%08.4f", prefixIdxEntropy, minEntropy))
	upper := []byte(fmt.Sprintf("%s%08.4f", prefixIdxEntropy, maxEntropy))
	upper[len(upper)-1]++

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, fmt.Errorf("pebble iterator creation failed: %w", err)
	}

	var results []detection.Signature
	seen := make(map[string]bool)
	for iter.First(); iter.Valid(); iter.Next() {
		id := string(iter.Value())
		if seen[id] {
			continue
		}
		seen[id] = true
		sig, err := readSignature(s.db, id)
		if err != nil {
			continue
		}
		// The index rounds to four decimals; check the exact score.
		if sig.EntropyScore < minEntropy || sig.EntropyScore > maxEntropy {
			continue
		}
		results = append(results, *sig)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return results, nil
}

func buildMetaKey(key string) []byte {
	return append(append([]byte(nil), prefixMeta...), key...)
}

func (s *PebbleScanner) SetMetadata(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Set(buildMetaKey(key), []byte(value), pebble.Sync)
}

func (s *PebbleScanner) GetMetadata(key string) (string, error) {
	data, closer, err := s.db.Get(buildMetaKey(key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return "", fmt.Errorf("metadata key %q not found", key)
		}
		return "", fmt.Errorf("read metadata %q: %w", key, err)
	}
	defer closer.Close()
	return string(data), nil
}
