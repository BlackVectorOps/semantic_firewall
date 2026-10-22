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

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pathguard"
)

const (
	// MaxDBSizeBytes bounds how much of a database file LoadDatabase reads,
	// so an oversized or padded file cannot exhaust memory.
	MaxDBSizeBytes = 64 * 1024 * 1024

	// SecureFilePerms is the mode SaveDatabase writes the database with:
	// owner read and write only.
	SecureFilePerms = 0600
)

// Scanner is a signature store held in memory and persisted as one JSON
// file. Scans take a read lock; loads and additions take the write lock.
type Scanner struct {
	db               *detection.SignatureDatabase
	sigMap           map[string]int
	matchThreshold   float64
	entropyTolerance float64
	mu               sync.RWMutex
}

// NewScanner returns an empty store with the default match threshold
// (0.75) and entropy tolerance (0.5).
func NewScanner() *Scanner {
	return &Scanner{
		db:               &detection.SignatureDatabase{},
		sigMap:           make(map[string]int),
		matchThreshold:   0.75,
		entropyTolerance: 0.5,
	}
}

// LoadDatabase replaces the store's contents with the database at path. The
// file must be a regular file (a FIFO or device could block the read) and
// may contain no fields the database format does not define.
func (s *Scanner) LoadDatabase(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanPath := filepath.Clean(path)

	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("signature database file does not exist at %s", cleanPath)
		}
		return fmt.Errorf("failed to stat %s: %w", cleanPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database path %s is not a regular file", cleanPath)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to open signature database: %w", err)
	}
	defer f.Close()

	var db detection.SignatureDatabase
	decoder := json.NewDecoder(io.LimitReader(f, MaxDBSizeBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&db); err != nil {
		return fmt.Errorf("failed to parse signature database: %w", err)
	}

	s.db = &db
	s.sigMap = make(map[string]int, len(s.db.Signatures))
	for i, sig := range s.db.Signatures {
		s.sigMap[sig.ID] = i
	}
	return nil
}

// SetMatchThreshold is SetThreshold, under the name PebbleScanner uses.
func (s *Scanner) SetMatchThreshold(threshold float64) error {
	return s.SetThreshold(threshold)
}

// SetThreshold sets the minimum confidence ScanTopology reports. NaN, an
// infinity, or a value outside [0, 1] is refused: NaN in particular would
// fail every comparison and silently suppress all alerts.
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

// SaveDatabase writes the database to path atomically: it encodes into a
// temporary file in the same directory with SecureFilePerms, syncs it, and
// renames it over path, so a crash never leaves a truncated database.
func (s *Scanner) SaveDatabase(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)

	if err := pathguard.CheckWritable(cleanPath); err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("destination directory invalid: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "sig-db-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := tmpFile.Chmod(SecureFilePerms); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to set secure permissions on temp file: %w", err)
	}

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(s.db); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to encode database to file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync file to disk: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	if err := os.Rename(tmpFile.Name(), cleanPath); err != nil {
		return fmt.Errorf("failed to replace database file: %w", err)
	}
	return nil
}

// ensureID gives sig a random ID from crypto/rand when it has none.
func (s *Scanner) ensureID(sig *detection.Signature) error {
	if sig.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate secure random ID: %w", err)
		}
		sig.ID = fmt.Sprintf("SFW-AUTO-%s", hex.EncodeToString(b))
	}
	return nil
}

// AddSignature appends a copy of sig, first giving sig an ID if it has none.
func (s *Scanner) AddSignature(sig *detection.Signature) error {
	if sig == nil {
		return fmt.Errorf("cannot add nil signature")
	}
	batch := []detection.Signature{*sig}
	if err := s.AddSignatures(batch); err != nil {
		return err
	}
	sig.ID = batch[0].ID
	return nil
}

// AddSignatures appends copies of sigs under one lock, first giving each
// signature without an ID one, in place.
func (s *Scanner) AddSignatures(sigs []detection.Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(sigs) == 0 {
		return nil
	}
	if s.db == nil {
		s.db = &detection.SignatureDatabase{
			Version:     "1.0",
			Description: "Semantic Firewall Malware Signature Database",
		}
	}
	if s.sigMap == nil {
		s.sigMap = make(map[string]int, len(sigs))
	}
	for i := range sigs {
		sig := &sigs[i]
		if err := s.ensureID(sig); err != nil {
			return err
		}
		s.db.Signatures = append(s.db.Signatures, sig.Clone())
		s.sigMap[sig.ID] = len(s.db.Signatures) - 1
	}
	return nil
}

// GetSignature returns a copy of the signature with the given ID.
func (s *Scanner) GetSignature(id string) (*detection.Signature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("database not loaded")
	}
	if idx, ok := s.sigMap[id]; ok && idx >= 0 && idx < len(s.db.Signatures) {
		sig := s.db.Signatures[idx].Clone()
		return &sig, nil
	}
	return nil, fmt.Errorf("signature %q not found", id)
}

// CountSignatures returns the number of signatures in the store.
func (s *Scanner) CountSignatures() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return 0, nil
	}
	return len(s.db.Signatures), nil
}

// GetDatabase returns a copy of the database that shares nothing with the
// store.
func (s *Scanner) GetDatabase() *detection.SignatureDatabase {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil
	}
	newDB := *s.db
	newDB.Signatures = make([]detection.Signature, len(s.db.Signatures))
	for i := range s.db.Signatures {
		newDB.Signatures[i] = s.db.Signatures[i].Clone()
	}
	return &newDB
}

// ScanTopology checks topo against every signature and returns the matches
// at or above the threshold, most confident first.
func (s *Scanner) ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.db.Signatures) == 0 {
		return nil, nil
	}

	var results []detection.ScanResult
	m := detection.NewMatcher(topo, funcName)
	for _, sig := range s.db.Signatures {
		result := m.Match(sig, s.entropyTolerance)
		if result.Confidence >= s.matchThreshold {
			results = append(results, result)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})
	return results, nil
}

// Close releases nothing; it lets Scanner stand in for the PebbleDB store.
func (s *Scanner) Close() error {
	return nil
}

// ScanTopologyExact returns the first signature topo matches with a
// confidence of at least 0.99, or nil. It ignores the scanner's entropy
// tolerance and passes no fallback (0), so only a signature's own tolerance
// admits an entropy difference; a signature that sets none can never match:
// at equal entropy its entropy score is 0/0 (NaN), and otherwise 0.5, which
// keeps confidence below 0.99.
func (s *Scanner) ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.db.Signatures) == 0 {
		return nil, nil
	}

	m := detection.NewMatcher(topo, funcName)
	for _, sig := range s.db.Signatures {
		result := m.Match(sig, 0.0)
		if result.Confidence >= 0.99 {
			return &result, nil
		}
	}
	return nil, nil
}
