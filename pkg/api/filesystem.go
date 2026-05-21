package api

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// FileSystem abstracts the OS file operations the analysis pipeline
// needs. Production code uses RealFileSystem; tests can substitute a
// mock to drive the pipeline without touching disk.
type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
	Open(name string) (fs.File, error)
	Getwd() (string, error)
	Abs(path string) (string, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
	ReadFile(name string) ([]byte, error)
}

// RealFileSystem is the production FileSystem implementation backed
// by the os and filepath packages. ReadFile bounds the read at
// models.MaxSourceFileSize so a hostile/oversize input cannot exhaust
// memory.
type RealFileSystem struct{}

func (RealFileSystem) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }
func (RealFileSystem) Open(name string) (fs.File, error)     { return os.Open(name) }
func (RealFileSystem) Getwd() (string, error)                { return os.Getwd() }
func (RealFileSystem) Abs(path string) (string, error)       { return filepath.Abs(path) }
func (RealFileSystem) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}

func (RealFileSystem) ReadFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", name)
	}
	if info.Size() > models.MaxSourceFileSize {
		return nil, fmt.Errorf("file exceeds maximum supported size of %d bytes", models.MaxSourceFileSize)
	}

	// Read one byte past the cap so an under-reported size can still be
	// detected and rejected, rather than silently truncated.
	limit := int64(models.MaxSourceFileSize + 1)
	content, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if len(content) > models.MaxSourceFileSize {
		return nil, fmt.Errorf("file exceeds maximum supported size of %d bytes", models.MaxSourceFileSize)
	}
	return content, nil
}
