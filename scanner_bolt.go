package semanticfw

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// Bucket names for the indexed BoltDB storage
var (
	bucketSignatures = []byte("signatures")   // Master storage: ID -> JSON blob
	bucketIdxTopo    = []byte("idx_topology") // Index: TopologyHash -> ID (Exact Match)
	bucketIdxFuzzy   = []byte("idx_fuzzy")    // REMEDIATION: Index: FuzzyHash -> ID (LSH)
	bucketIdxEntropy = []byte("idx_entropy")  // Index: EntropyKey -> ID
	bucketMeta       = []byte("meta")         // Metadata: version, stats, etc.
)

// Performs semantic malware detection using BoltDB for persistent storage.
// Supports O(1) exact topology matching and O(M) fuzzy entropy range scans.
type BoltScanner struct {
	db               *bbolt.DB
	matchThreshold   float64
	entropyTolerance float64
	mu               sync.RWMutex // Protects concurrent access patterns
}

// Configures the BoltScanner initialization.
type BoltScannerOptions struct {
	MatchThreshold   float64       // Minimum confidence for alerts (default: 0.75)
	EntropyTolerance float64       // Entropy fuzzy match window (default: 0.5)
	Timeout          time.Duration // DB open timeout (default: 5s)
	ReadOnly         bool          // Open DB in read-only mode for scanning only
}

// Returns sensible defaults for production use.
func DefaultBoltScannerOptions() BoltScannerOptions {
	return BoltScannerOptions{
		MatchThreshold:   0.75,
		EntropyTolerance: 0.5,
		Timeout:          5 * time.Second,
		ReadOnly:         false,
	}
}

// Opens or creates a BoltDB backed signature database.
// The database file will be created if it doesn't exist.
func NewBoltScanner(dbPath string, opts BoltScannerOptions) (*BoltScanner, error) {
	if opts.MatchThreshold == 0 {
		opts.MatchThreshold = 0.75
	}
	if opts.EntropyTolerance == 0 {
		opts.EntropyTolerance = 0.5
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{
		Timeout:  opts.Timeout,
		ReadOnly: opts.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open signature db %q: %w", dbPath, err)
	}

	// Create buckets if not in read-only mode
	if !opts.ReadOnly {
		if err := initBuckets(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize buckets: %w", err)
		}
	}

	return &BoltScanner{
		db:               db,
		matchThreshold:   opts.MatchThreshold,
		entropyTolerance: opts.EntropyTolerance,
	}, nil
}

// Creates all required buckets in a single transaction.
func initBuckets(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		buckets := [][]byte{bucketSignatures, bucketIdxTopo, bucketIdxFuzzy, bucketIdxEntropy, bucketMeta}
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %q: %w", name, err)
			}
		}
		return nil
	})
}

// Flushes all pending writes and closes the database.
// Always call this when done to prevent data loss.
func (s *BoltScanner) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Updates the minimum confidence threshold for alerts.
func (s *BoltScanner) SetThreshold(threshold float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matchThreshold = threshold
}

// Updates the entropy fuzzy match window.
func (s *BoltScanner) SetEntropyTolerance(tolerance float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entropyTolerance = tolerance
}

// =============================================================================
// WRITE PATH: Indexing (Learning Phase)
// =============================================================================

// Atomically saves a signature and updates all indexes.
// Safe for concurrent use.
func (s *BoltScanner) AddSignature(sig Signature) error {
	// Generate ID if not provided
	if sig.ID == "" {
		sig.ID = fmt.Sprintf("SFW-AUTO-%d", time.Now().UnixNano())
	}

	// Validate required fields
	if sig.TopologyHash == "" {
		return fmt.Errorf("signature %q missing required TopologyHash", sig.ID)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)
		bFuzzy := tx.Bucket(bucketIdxFuzzy)
		bEntr := tx.Bucket(bucketIdxEntropy)

		// 1. Serialize and save master record
		data, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("marshal signature %q: %w", sig.ID, err)
		}
		if err := bSigs.Put([]byte(sig.ID), data); err != nil {
			return fmt.Errorf("store signature %q: %w", sig.ID, err)
		}

		// 2. Update topology index (Hash -> ID)
		// Multiple signatures can share the same topology hash (variants).
		if err := bTopo.Put([]byte(sig.TopologyHash), []byte(sig.ID)); err != nil {
			return fmt.Errorf("index topology for %q: %w", sig.ID, err)
		}

		// REMEDIATION: O(1) Topology Trap Fix
		// 3. Index using Fuzzy Hash (LSH-lite) for robust lookups
		if sig.FuzzyHash != "" {
			// Bucket key: Hash:ID -> Value: ID
			// This allows multiple signatures per fuzzy bucket via unique keys
			key := fmt.Sprintf("%s:%s", sig.FuzzyHash, sig.ID)
			if err := bFuzzy.Put([]byte(key), []byte(sig.ID)); err != nil {
				return fmt.Errorf("index fuzzy hash for %q: %w", sig.ID, err)
			}
		}

		// 4. Update entropy index (Score:ID -> ID)
		// Format: %08.4f:%s ensures lexicographic ordering matches numeric ordering.
		// The ID suffix ensures uniqueness for signatures with identical entropy.
		entropyKey := formatEntropyKey(sig.EntropyScore, sig.ID)
		if err := bEntr.Put([]byte(entropyKey), []byte(sig.ID)); err != nil {
			return fmt.Errorf("index entropy for %q: %w", sig.ID, err)
		}

		return nil
	})
}

// Atomically adds multiple signatures in a single transaction.
// Much faster than calling AddSignature in a loop for bulk imports.
func (s *BoltScanner) AddSignatures(sigs []Signature) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)
		bFuzzy := tx.Bucket(bucketIdxFuzzy)
		bEntr := tx.Bucket(bucketIdxEntropy)

		for i := range sigs {
			sig := &sigs[i]

			// Generate ID if not provided
			if sig.ID == "" {
				sig.ID = fmt.Sprintf("SFW-AUTO-%d-%d", time.Now().UnixNano(), i)
			}

			// Validate
			if sig.TopologyHash == "" {
				return fmt.Errorf("signature %q missing TopologyHash", sig.ID)
			}

			// Marshal
			data, err := json.Marshal(sig)
			if err != nil {
				return fmt.Errorf("marshal signature %q: %w", sig.ID, err)
			}

			// Store master
			if err := bSigs.Put([]byte(sig.ID), data); err != nil {
				return fmt.Errorf("store signature %q: %w", sig.ID, err)
			}

			// Index topology
			if err := bTopo.Put([]byte(sig.TopologyHash), []byte(sig.ID)); err != nil {
				return fmt.Errorf("index topology %q: %w", sig.ID, err)
			}

			// Index fuzzy hash
			if sig.FuzzyHash != "" {
				key := fmt.Sprintf("%s:%s", sig.FuzzyHash, sig.ID)
				if err := bFuzzy.Put([]byte(key), []byte(sig.ID)); err != nil {
					return fmt.Errorf("index fuzzy hash %q: %w", sig.ID, err)
				}
			}

			// Index entropy
			entropyKey := formatEntropyKey(sig.EntropyScore, sig.ID)
			if err := bEntr.Put([]byte(entropyKey), []byte(sig.ID)); err != nil {
				return fmt.Errorf("index entropy %q: %w", sig.ID, err)
			}
		}
		return nil
	})
}

// Removes a signature and its index entries.
func (s *BoltScanner) DeleteSignature(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)
		bEntr := tx.Bucket(bucketIdxEntropy)

		// Load existing signature to get index keys
		data := bSigs.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("signature %q not found", id)
		}

		var sig Signature
		if err := json.Unmarshal(data, &sig); err != nil {
			return fmt.Errorf("unmarshal signature %q: %w", id, err)
		}

		// Delete from indexes first
		if err := bTopo.Delete([]byte(sig.TopologyHash)); err != nil {
			return fmt.Errorf("delete topology index %q: %w", id, err)
		}

		entropyKey := formatEntropyKey(sig.EntropyScore, sig.ID)
		if err := bEntr.Delete([]byte(entropyKey)); err != nil {
			return fmt.Errorf("delete entropy index %q: %w", id, err)
		}

		// Delete master record
		if err := bSigs.Delete([]byte(id)); err != nil {
			return fmt.Errorf("delete signature %q: %w", id, err)
		}

		return nil
	})
}

// Updates a signature to record that it caused a false positive.
// Enables learning feedback loops without rewriting the entire database.
func (s *BoltScanner) MarkFalsePositive(id string, notes string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)

		data := bSigs.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("signature %q not found", id)
		}

		var sig Signature
		if err := json.Unmarshal(data, &sig); err != nil {
			return fmt.Errorf("unmarshal signature %q: %w", id, err)
		}

		// Append false positive note to references
		fpNote := fmt.Sprintf("FP:%s:%s", time.Now().Format(time.RFC3339), notes)
		sig.Metadata.References = append(sig.Metadata.References, fpNote)

		// Re-serialize and save
		updated, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("marshal updated signature %q: %w", id, err)
		}

		return bSigs.Put([]byte(id), updated)
	})
}

// =============================================================================
// READ PATH: Scanning (Hunter Phase)
// =============================================================================

// Checks a function topology against the signature database using two phases:
//   - Phase A (O(1)): Exact topology hash lookup
//   - Phase B (O(1)): Fuzzy bucket index lookup (LSH-lite)
func (s *BoltScanner) ScanTopology(topo *FunctionTopology, funcName string) []ScanResult {
	if topo == nil {
		return nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	s.mu.RUnlock()

	topoHash := generateTopologyHash(topo)
	fuzzyHash := GenerateFuzzyHash(topo)

	var results []ScanResult
	seen := make(map[string]bool) // Track signature IDs to avoid duplicates

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)
		bFuzzy := tx.Bucket(bucketIdxFuzzy)

		if bSigs == nil {
			return nil // Empty database
		}

		// --- PHASE 1: EXACT TOPOLOGY MATCH (O(1)) ---
		if sigID := bTopo.Get([]byte(topoHash)); sigID != nil {
			seen[string(sigID)] = true
			if res := s.loadAndMatch(bSigs, sigID, topo, funcName, threshold); res != nil {
				results = append(results, *res)
			}
		}

		// --- PHASE 2: FUZZY BUCKET INDEX (LSH-lite) ---
		// Scan only the bucket corresponding to the fuzzy hash
		c := bFuzzy.Cursor()
		// Pre-allocate prefix to avoid string concatenation allocation
		prefix := make([]byte, len(fuzzyHash)+1)
		copy(prefix, fuzzyHash)
		prefix[len(fuzzyHash)] = ':'
		
		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			sigID := string(v)
			if seen[sigID] {
				continue
			}
			seen[sigID] = true
			if res := s.loadAndMatch(bSigs, []byte(sigID), topo, funcName, threshold); res != nil {
				results = append(results, *res)
			}
		}

		return nil
	})

	if err != nil {
		return nil
	}

	// Sort by confidence (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}

// loadAndMatch loads a signature by ID and attempts to match it against a topology.
func (s *BoltScanner) loadAndMatch(bSigs *bbolt.Bucket, sigID []byte, topo *FunctionTopology, funcName string, threshold float64) *ScanResult {
	sigData := bSigs.Get(sigID)
	if sigData == nil {
		return nil
	}
	var sig Signature
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return nil
	}
	res := s.matchSignature(topo, funcName, sig)
	if res.Confidence >= threshold {
		return &res
	}
	return nil
}

// Performs only exact topology hash matching (fastest).
// Use this when you only want exact matches without fuzzy entropy scanning.
func (s *BoltScanner) ScanTopologyExact(topo *FunctionTopology, funcName string) *ScanResult {
	if topo == nil {
		return nil
	}

	s.mu.RLock()
	threshold := s.matchThreshold
	s.mu.RUnlock()

	topoHash := generateTopologyHash(topo)
	var result *ScanResult

	s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)

		if bSigs == nil || bTopo == nil {
			return nil
		}

		sigID := bTopo.Get([]byte(topoHash))
		if sigID == nil {
			return nil
		}

		sigData := bSigs.Get(sigID)
		if sigData == nil {
			return nil
		}

		var sig Signature
		if err := json.Unmarshal(sigData, &sig); err != nil {
			return nil
		}

		res := s.matchSignature(topo, funcName, sig)
		if res.Confidence >= threshold {
			result = &res
		}
		return nil
	})

	return result
}

// Retrieves a single signature by ID.
func (s *BoltScanner) GetSignature(id string) (*Signature, error) {
	var sig *Signature

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		if bSigs == nil {
			return fmt.Errorf("database not initialized")
		}

		data := bSigs.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("signature %q not found", id)
		}

		sig = &Signature{}
		return json.Unmarshal(data, sig)
	})

	return sig, err
}

// Retrieves a signature by its topology hash.
func (s *BoltScanner) GetSignatureByTopology(topoHash string) (*Signature, error) {
	var sig *Signature

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		bTopo := tx.Bucket(bucketIdxTopo)
		if bSigs == nil || bTopo == nil {
			return fmt.Errorf("database not initialized")
		}

		sigID := bTopo.Get([]byte(topoHash))
		if sigID == nil {
			return fmt.Errorf("no signature with topology hash %q", topoHash)
		}

		data := bSigs.Get(sigID)
		if data == nil {
			return fmt.Errorf("signature %q not found", string(sigID))
		}

		sig = &Signature{}
		return json.Unmarshal(data, sig)
	})

	return sig, err
}

// Returns the total number of signatures in the database.
func (s *BoltScanner) CountSignatures() (int, error) {
	var count int

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		if bSigs == nil {
			return nil
		}
		stats := bSigs.Stats()
		count = stats.KeyN
		return nil
	})

	return count, err
}

// Returns all signature IDs in the database.
func (s *BoltScanner) ListSignatureIDs() ([]string, error) {
	var ids []string

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		if bSigs == nil {
			return nil
		}

		return bSigs.ForEach(func(k, v []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})

	return ids, err
}

// =============================================================================
// MIGRATION: JSON to BoltDB
// =============================================================================

// Imports signatures from a legacy JSON database file.
// One time migration utility.
func (s *BoltScanner) MigrateFromJSON(jsonPath string) (int, error) {
	// Load the old JSON scanner to read signatures
	oldScanner := NewScanner()
	if err := oldScanner.LoadDatabase(jsonPath); err != nil {
		return 0, fmt.Errorf("load legacy database: %w", err)
	}

	db := oldScanner.GetDatabase()
	if db == nil || len(db.Signatures) == 0 {
		return 0, nil
	}

	// Bulk import all signatures
	if err := s.AddSignatures(db.Signatures); err != nil {
		return 0, fmt.Errorf("bulk import signatures: %w", err)
	}

	return len(db.Signatures), nil
}

// Exports all signatures to a JSON file (backup/compatibility).
func (s *BoltScanner) ExportToJSON(jsonPath string) error {
	var sigs []Signature

	err := s.db.View(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)
		if bSigs == nil {
			return nil
		}

		return bSigs.ForEach(func(k, v []byte) error {
			var sig Signature
			if err := json.Unmarshal(v, &sig); err != nil {
				return err
			}
			sigs = append(sigs, sig)
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Use the old scanner to maintain JSON format compatibility
	oldScanner := NewScanner()
	for _, sig := range sigs {
		oldScanner.AddSignature(sig)
	}

	return oldScanner.SaveDatabase(jsonPath)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// Creates a sortable key for the entropy index.
// Format: "05.1234:SFW-MAL-001" where:
//   - First 8 chars are zero padded entropy with 4 decimal places
//   - Colon separator
//   - Signature ID suffix ensures uniqueness
func formatEntropyKey(entropy float64, id string) string {
	// Clamp entropy to valid range to prevent formatting issues
	if entropy < 0 {
		entropy = 0
	}
	if entropy > 99.9999 {
		entropy = 99.9999
	}
	return fmt.Sprintf("%08.4f:%s", entropy, id)
}

// Computes how well a topology matches a signature.
// Shared logic with the original scanner.
func (s *BoltScanner) matchSignature(topo *FunctionTopology, funcName string, sig Signature) ScanResult {
	result := ScanResult{
		SignatureID:     sig.ID,
		SignatureName:   sig.Name,
		Severity:        sig.Severity,
		MatchedFunction: funcName,
	}

	var scores []float64
	details := MatchDetails{}

	// 1. Topology Hash Match
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

	// 2. Entropy Match
	s.mu.RLock()
	defaultTol := s.entropyTolerance
	s.mu.RUnlock()

	entropyDist := EntropyDistance(topo.EntropyScore, sig.EntropyScore)
	tolerance := sig.EntropyTolerance
	if tolerance == 0 {
		tolerance = defaultTol
	}
	details.EntropyDistance = entropyDist
	details.EntropyMatch = entropyDist <= tolerance
	if details.EntropyMatch {
		entropyScore := 1.0 - (entropyDist / tolerance)
		scores = append(scores, entropyScore)
	} else {
		scores = append(scores, 0.5)
	}

	// 3. Call Signature Match
	if len(sig.IdentifyingFeatures.RequiredCalls) > 0 {
		callScore, matched, missing := matchCalls(topo, sig.IdentifyingFeatures.RequiredCalls)
		details.CallsMatched = matched
		details.CallsMissing = missing

		// VETO POWER: Security Standard
		// If required calls are missing, fail match
		if len(missing) > 0 {
			result.Confidence = 0.0
			result.MatchDetails = details
			return result
		}

		scores = append(scores, callScore)
	}

	// 4. String Pattern Match (bonus)
	if len(sig.IdentifyingFeatures.StringPatterns) > 0 {
		stringScore, matched := matchStrings(topo, sig.IdentifyingFeatures.StringPatterns)
		details.StringsMatched = matched
		if stringScore > 0 {
			scores = append(scores, stringScore)
		}
	}

	// Calculate overall confidence
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

// =============================================================================
// DATABASE MAINTENANCE
// =============================================================================

// Rebuilds all secondary indexes from the master signatures bucket.
// Use this to recover from index corruption or after manual edits.
func (s *BoltScanner) RebuildIndexes() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bSigs := tx.Bucket(bucketSignatures)

		// Clear and recreate index buckets
		if err := tx.DeleteBucket(bucketIdxTopo); err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		if err := tx.DeleteBucket(bucketIdxFuzzy); err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		if err := tx.DeleteBucket(bucketIdxEntropy); err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}

		bTopo, err := tx.CreateBucket(bucketIdxTopo)
		if err != nil {
			return err
		}
		bFuzzy, err := tx.CreateBucket(bucketIdxFuzzy)
		if err != nil {
			return err
		}
		bEntr, err := tx.CreateBucket(bucketIdxEntropy)
		if err != nil {
			return err
		}

		// Rebuild indexes from master data
		return bSigs.ForEach(func(k, v []byte) error {
			var sig Signature
			if err := json.Unmarshal(v, &sig); err != nil {
				return fmt.Errorf("unmarshal %s: %w", string(k), err)
			}

			if err := bTopo.Put([]byte(sig.TopologyHash), []byte(sig.ID)); err != nil {
				return err
			}

			// Index fuzzy hash
			if sig.FuzzyHash != "" {
				key := fmt.Sprintf("%s:%s", sig.FuzzyHash, sig.ID)
				if err := bFuzzy.Put([]byte(key), []byte(sig.ID)); err != nil {
					return err
				}
			}

			entropyKey := formatEntropyKey(sig.EntropyScore, sig.ID)
			return bEntr.Put([]byte(entropyKey), []byte(sig.ID))
		})
	})
}

// Forces a compaction of the database file to reclaim space.
// BoltDB doesn't automatically shrink, so call this after large deletions.
func (s *BoltScanner) Compact(destPath string) error {
	return s.db.View(func(tx *bbolt.Tx) error {
		return tx.CopyFile(destPath, 0600)
	})
}

// Returns database statistics for monitoring.
type BoltScannerStats struct {
	SignatureCount   int
	TopoIndexCount   int
	EntropyIndexSize int64
	FileSize         int64
}

func (s *BoltScanner) Stats() (*BoltScannerStats, error) {
	stats := &BoltScannerStats{}

	err := s.db.View(func(tx *bbolt.Tx) error {
		if b := tx.Bucket(bucketSignatures); b != nil {
			stats.SignatureCount = b.Stats().KeyN
		}
		if b := tx.Bucket(bucketIdxTopo); b != nil {
			stats.TopoIndexCount = b.Stats().KeyN
		}
		if b := tx.Bucket(bucketIdxEntropy); b != nil {
			stats.EntropyIndexSize = int64(b.Stats().LeafInuse)
		}
		return nil
	})

	return stats, err
}
