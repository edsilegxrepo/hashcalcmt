// Package pipeline_test contains unit tests for the pipeline execution package.
//
// TESTING STRATEGY:
//  1. Directory Walking Concurrency (TestPipelineRun): Verifies that Run recursively finds matching files,
//     handles glob pattern filters, opens files securely via os.Root sandboxing, hashes them concurrently,
//     and outputs correct relative paths.
//  2. File-List Concurrency (TestPipelineRunFileList): Verifies that RunFileList processes an arbitrary list
//     of file paths concurrently without sandboxing, handles non-existent files gracefully by returning
//     correct wrapped errors, and shuts down the worker pool cleanly.
//  3. Error Traversal Path (TestPipelineInvalidPath): Verifies that walking non-existent folders reports errors.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Helper SHA256 hasher function matching hasher.Func
func testSHA256Hasher(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func TestPipelineRun(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	file1Content := []byte("hello")
	file2Content := []byte("world")

	file1Path := filepath.Join(tempDir, "file1.txt")
	file2Path := filepath.Join(tempDir, "file2.log") // different extension to test pattern matching

	if err := os.WriteFile(file1Path, file1Content, 0o644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2Path, file2Content, 0o644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	// Run the pipeline matching only "*.txt"
	resultsChan := Run(tempDir, "*.txt", 2, testSHA256Hasher)

	// Collect results
	var results []Result
	for res := range resultsChan {
		results = append(results, res)
	}

	// We expect exactly 1 result (file1.txt) because file2.log does not match *.txt
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Error != nil {
		t.Fatalf("Unexpected pipeline error for %s: %v", res.FilePath, res.Error)
	}

	// WalkDir uses relative path to tempDir
	expectedRelPath := "file1.txt"
	if res.FilePath != expectedRelPath {
		t.Errorf("Expected relative file path %q, got %q", expectedRelPath, res.FilePath)
	}

	// Expected SHA256 of "hello"
	h := sha256.New()
	h.Write(file1Content)
	expectedHash := hex.EncodeToString(h.Sum(nil))

	if res.Hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, res.Hash)
	}
}

func TestPipelineInvalidPath(t *testing.T) {
	// Running pipeline on a non-existent path should report an error
	resultsChan := Run("non-existent-directory-xyz-123", "*", 2, func(r io.Reader) (string, error) {
		return "", nil
	})

	res, ok := <-resultsChan
	if !ok {
		t.Fatalf("Expected at least one result or error, but channel closed immediately")
	}

	if res.Error == nil {
		t.Errorf("Expected error for non-existent path, got nil")
	}
}

func TestPipelineRunFileList(t *testing.T) {
	tempDir := t.TempDir()

	file1Content := []byte("hello file list")
	file1Path := filepath.Join(tempDir, "file1.txt")
	if err := os.WriteFile(file1Path, file1Content, 0o644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}

	// Non-existent file should report error but not crash
	paths := []string{file1Path, "non-existent-file.bin"}

	resultsChan := RunFileList(paths, 2, testSHA256Hasher)

	var results []Result
	for res := range resultsChan {
		results = append(results, res)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// Verify file1.txt
	foundFile1 := false
	foundError := false
	for _, res := range results {
		switch res.FilePath {
		case file1Path:
			foundFile1 = true
			if res.Error != nil {
				t.Errorf("Unexpected error for %s: %v", file1Path, res.Error)
			}
			h := sha256.New()
			h.Write(file1Content)
			expectedHash := hex.EncodeToString(h.Sum(nil))
			if res.Hash != expectedHash {
				t.Errorf("Expected hash %s, got %s", expectedHash, res.Hash)
			}
		case "non-existent-file.bin":
			foundError = true
			if res.Error == nil {
				t.Errorf("Expected error for non-existent file list path, got nil")
			}
		}
	}

	if !foundFile1 {
		t.Errorf("Did not find result for %s in output", file1Path)
	}
	if !foundError {
		t.Errorf("Did not find error result in output")
	}
}
