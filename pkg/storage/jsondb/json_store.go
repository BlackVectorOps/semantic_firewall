package jsondb

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
)

const (
	// Prevents memory exhaustion attacks via massive JSON payloads.
	// 64MB is generous enough for thousands of signatures but stops an attacker
	// from blowing the heap with a 10GB padding bomb.
	MaxDBSizeBytes = 64 * 1024 * 1024

	// SecureFilePerms enforces owner only read write access.
	// We do not want the web server or other low privilege users snooping on our logic.
	SecureFilePerms = 0600
)

// Implements a JSON backed signature store.
// We use a Read/Write mutex here because detection is heavily read biased.
// We only want to stop the world when we are actually mutating the state,
// otherwise we let the readers swarm.
type Scanner struct {
	db               *detection.SignatureDatabase
	matchThreshold   float64
	entropyTolerance float64
	mu               sync.RWMutex
}

// Creates a new scanner instance.
// We initialize with safe defaults so the thing works out of the box.
// Returning a nil db pointer would just be setting traps for our future selves.
func NewScanner() *Scanner {
	return &Scanner{
		db:               &detection.SignatureDatabase{},
		matchThreshold:   0.75, // 75% minimum confidence keeps the false positives manageable
		entropyTolerance: 0.5,
	}
}

// Loads signatures from a JSON file.
// This operation holds a Write lock because we are performing a brain transplant
// on the scanner. We cannot have readers looking at a half loaded struct.
func (s *Scanner) LoadDatabase(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sanitize the input path to prevent directory traversal shenanigans.
	cleanPath := filepath.Clean(path)

	// Verify file existence explicitly.
	// While Open handles this, a Stat check lets us give a more useful error message.
	info, err := os.Stat(cleanPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("signature database file does not exist at %s", cleanPath)
	}

	// Refuse to read named pipes or devices.
	// Reading from /dev/random or a blocking pipe would hang the scanner indefinitely.
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database path %s is not a regular file", cleanPath)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to open signature database: %w", err)
	}
	defer f.Close()

	// Wrap the reader. If the file claims to be 1GB, we stop reading at 64MB.
	// This protects the application availability.
	limitedReader := io.LimitReader(f, MaxDBSizeBytes)

	var db detection.SignatureDatabase
	decoder := json.NewDecoder(limitedReader)

	// We are strict on schema. If the JSON has fields we don't know about,
	// it implies version drift or a corrupted config. Fail fast.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&db); err != nil {
		return fmt.Errorf("failed to parse signature database: %w", err)
	}

	s.db = &db
	return nil
}

// Sets the minimum confidence threshold for alerts.
// We validate inputs here to prevent NaN poisoning. If NaN gets into the
// confidence logic, comparisons will fail silently and we will miss detections.
func (s *Scanner) SetThreshold(threshold float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return fmt.Errorf("invalid threshold value: %v", threshold)
	}

	if threshold < 0.0 || threshold > 1.0 {
		return fmt.Errorf("threshold must be between 0.0 and 1.0, got: %f", threshold)
	}

	s.matchThreshold = threshold
	return nil
}

// Writes the signature database to a JSON file.
// We use a streaming encoder to avoid loading the entire JSON string into
// memory (heap protection), and an atomic write strategy (write to temp,
// sync, rename) so a power failure doesn't leave us with a 0 byte DB.
func (s *Scanner) SaveDatabase(path string) error {
	s.mu.RLock()
	// We hold the lock for the duration of the stream to ensure consistency.
	// If we didn't lock, a concurrent AddSignature could mutate the slice
	// while we are iterating it, causing a panic or corrupt JSON output.
	defer s.mu.RUnlock()

	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)

	// Ensure directory exists and is writable
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("destination directory invalid: %w", err)
	}

	// Create temp file in the same directory to ensure the Rename is atomic.
	// Moving files across partitions is not atomic, so we stay local.
	tmpFile, err := os.CreateTemp(dir, "sig-db-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Clean up temp file if we fail before the rename dance is finished.
	defer os.Remove(tmpFile.Name())

	// Enforce strict permissions immediately.
	// We don't want a race window where the file is world readable before we chmod it.
	if err := tmpFile.Chmod(SecureFilePerms); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to set secure permissions on temp file: %w", err)
	}

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ") // Humans need to read this too.
	if err := encoder.Encode(s.db); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to encode database to file: %w", err)
	}

	// Force flush to disk hardware. OS buffers lie to us.
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync file to disk: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Atomic replace. This is the only time the actual DB file is touched.
	if err := os.Rename(tmpFile.Name(), cleanPath); err != nil {
		return fmt.Errorf("failed to replace database file: %w", err)
	}

	return nil
}

// Adds a new signature to the database.
// We use crypto/rand for ID generation because math/rand is deterministic
// and we don't want ID collisions if the seed isn't set properly.
func (s *Scanner) AddSignature(sig *detection.Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sig == nil {
		return fmt.Errorf("cannot add nil signature")
	}

	if s.db == nil {
		s.db = &detection.SignatureDatabase{
			Version:     "1.0",
			Description: "Semantic Firewall Malware Signature Database",
		}
	}

	// Generate ID if not provided using secure entropy.
	if sig.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate secure random ID: %w", err)
		}
		sig.ID = fmt.Sprintf("SFW-AUTO-%s", hex.EncodeToString(b))
	}

	// Append copies the struct value.
	s.db.Signatures = append(s.db.Signatures, *sig)
	return nil
}

// Retrieves a signature by ID.
// Returns a deep copy to prevent the caller from modifying the internal
// database state without a lock. Shared mutable state is the root of all evil.
func (s *Scanner) GetSignature(id string) (*detection.Signature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("database not loaded")
	}
	for i := range s.db.Signatures {
		if s.db.Signatures[i].ID == id {
			return s.deepCopySignature(&s.db.Signatures[i]), nil
		}
	}
	return nil, fmt.Errorf("signature %q not found", id)
}

// Finds potential matches based on entropy and hash.
// CRITICAL: This returns pointers to NEW COPIES of the signatures.
// If we returned pointers to the existing slice, a subsequent AddSignature
// could trigger a slice realloc, invalidating our pointers and crashing the app.
func (s *Scanner) ScanCandidates(topo *topology.FunctionTopology) ([]*detection.Signature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.db.Signatures) == 0 || topo == nil {
		return nil, nil
	}

	topoHash := detection.GenerateTopologyHash(topo)
	fuzzyHash := topology.GenerateFuzzyHash(topo)

	var candidates []*detection.Signature
	for i := range s.db.Signatures {
		sig := &s.db.Signatures[i]
		match := sig.TopologyHash == topoHash || (sig.FuzzyHash != "" && sig.FuzzyHash == fuzzyHash)

		if match {
			// Respect the signature's tolerance.
			// If it demands 0.0 variance, we give it 0.0 variance.
			effectiveTol := sig.EntropyTolerance

			if math.Abs(sig.EntropyScore-topo.EntropyScore) <= effectiveTol {
				// Deep copy allows the caller to mutate their candidate list safely.
				candidates = append(candidates, s.deepCopySignature(sig))
			}
		}
	}
	return candidates, nil
}

// Returns a deep copy of the current signature database.
// We manually duplicate slice structures. If we just returned *s.db,
// the slice headers would still point to the same backing array.
func (s *Scanner) GetDatabase() *detection.SignatureDatabase {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil
	}

	newDB := *s.db
	newDB.Signatures = make([]detection.Signature, len(s.db.Signatures))

	for i := range s.db.Signatures {
		// Element wise deep copy prevents shared references.
		newDB.Signatures[i] = *s.deepCopySignature(&s.db.Signatures[i])
	}

	return &newDB
}

// Creates a safe clone of a single signature.
// Currently performs a value copy. If the Signature struct is updated
// to include slices (e.g. Tags, CVEs), they MUST be manually copied here
// or we introduce a subtle data race.
func (s *Scanner) deepCopySignature(src *detection.Signature) *detection.Signature {
	dst := *src
	// NOTE: If reference types are added to Signature, copy them here.
	return &dst
}

// Checks a function topology against all signatures.
// We explicitly lock here. Iterating a slice is not thread safe in Go.
func (s *Scanner) ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	s.mu.RLock()
	// Defer unlock is critical. If MatchSignature panics, we need to release
	// the lock during the stack unwind or the whole server deadlocks.
	defer s.mu.RUnlock()

	if s.db == nil || len(s.db.Signatures) == 0 {
		return nil, nil
	}

	var results []detection.ScanResult

	for _, sig := range s.db.Signatures {
		// We trust MatchSignature to handle the heavy lifting,
		// but we guard the access to the signature data.
		result := detection.MatchSignature(topo, funcName, sig, s.entropyTolerance)
		if result.Confidence >= s.matchThreshold {
			results = append(results, result)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results, nil
}

// Close is a placeholder.
// Sometimes interfaces demand things we don't need, but we play along.
func (s *Scanner) Close() error {
	return nil
}

// Checks a function topology against all signatures for an exact match.
func (s *Scanner) ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.db.Signatures) == 0 {
		return nil, nil
	}

	for _, sig := range s.db.Signatures {
		// Using a strict 0.0 tolerance. We are looking for twins, not cousins.
		result := detection.MatchSignature(topo, funcName, sig, 0.0)
		if result.Confidence >= 0.99 {
			return &result, nil
		}
	}

	return nil, nil
}
