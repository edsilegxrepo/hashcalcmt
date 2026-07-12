// Package main_test contains integration and unit tests for the main application coordinator.
//
// TESTING STRATEGY:
//  1. End-to-End Integration Testing: Employs `runMain()` directly with mock arguments, stdout, and stderr
//     buffers to verify successful executions, version printing, output file creation, and exit status codes.
//  2. Validation Testing: Evaluates `validateConfig()` with all combinations of valid and invalid modes,
//     mode-exclusive flags (like path-exclusive checks in directory mode), and rename constraints.
//  3. Stdin/Piping Verification: Uses `bytes.Reader` to mock standard input streams, confirming correct parsing
//     and hashing of stdin strings and files.
//  4. File-List Parsing Integrity: Tests parsing logic including comments (lines starting with '#') and blank lines.
//  5. Windows sharing lock protection: Validates that files can be renamed in place during file modes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"criticalsys.net/hashcalcmt/pipeline"
)

// Helper SHA256 hasher function matching hasher.Func
func testSHA256Hasher(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// errorHasher returns an error during hashing to test error paths
func errorHasher(r io.Reader) (string, error) {
	return "", fmt.Errorf("hash computation failed")
}

// errorReader returns an error when Read is called
type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("read error")
}

func TestParseFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"hashcalcmt", "--mode=file", "--hash=SHA256"}

	// Reset flag CommandLine to avoid panicking due to redefining flags in tests
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	cfg := parseFlags()
	if cfg.Mode != "file" {
		t.Errorf("Expected mode 'file', got '%s'", cfg.Mode)
	}
	if cfg.HashType != "SHA256" {
		t.Errorf("Expected hash 'SHA256', got '%s'", cfg.HashType)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *Config
		expectError bool
	}{
		{
			name: "Valid directory mode",
			cfg: &Config{
				Mode:        "directory",
				Path:        ".",
				FilePattern: "*",
			},
			expectError: false,
		},
		{
			name: "Invalid mode value",
			cfg: &Config{
				Mode: "invalid-mode",
			},
			expectError: true,
		},
		{
			name: "Path set in string mode",
			cfg: &Config{
				Mode: "string",
				Path: "some/path",
			},
			expectError: true,
		},
		{
			name: "Filepattern set in string mode",
			cfg: &Config{
				Mode:        "string",
				FilePattern: "*.txt",
			},
			expectError: true,
		},
		{
			name: "Rename flag set in string mode",
			cfg: &Config{
				Mode:   "string",
				Rename: true,
			},
			expectError: true,
		},
		{
			name: "Rename flag set in environment mode",
			cfg: &Config{
				Mode:   "environment",
				Rename: true,
			},
			expectError: true,
		},
		{
			name: "Unsupported input encoding",
			cfg: &Config{
				Mode:          "string",
				InputEncoding: "ebcdic",
			},
			expectError: true,
		},
		{
			name: "Unsupported output format",
			cfg: &Config{
				Mode:         "string",
				OutputFormat: "yaml",
			},
			expectError: true,
		},
		{
			name: "Input encoding used in directory mode",
			cfg: &Config{
				Mode:          "directory",
				Path:          ".",
				FilePattern:   "*",
				InputEncoding: "utf16le",
			},
			expectError: true,
		},
		{
			name: "Input encoding used in file mode",
			cfg: &Config{
				Mode:          "file",
				Path:          ".",
				FilePattern:   "*",
				InputEncoding: "utf16le",
			},
			expectError: true,
		},
		{
			name: "Valid input encoding and output format",
			cfg: &Config{
				Mode:          "string",
				Path:          ".",
				FilePattern:   "*",
				InputEncoding: "utf16le",
				OutputFormat:  "base64url",
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.cfg)
			if (err != nil) != tc.expectError {
				t.Errorf("Expected error: %v, got: %v", tc.expectError, err)
			}
		})
	}
}

func TestProcessResults_ErrorsAndRenames(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "original.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// 1. Test processResults with error channel
	resultsChan := make(chan pipeline.Result, 1)
	resultsChan <- pipeline.Result{
		FilePath: "failed-path.txt",
		Error:    fmt.Errorf("read failed"),
	}
	close(resultsChan)

	cfg := &Config{Display: false}
	errs := processResults(resultsChan, cfg, NewStructuredWriter(io.Discard, cfg.Format, cfg.OutputFormat))
	if len(errs) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errs))
	}

	// 2. Test processResults with renaming
	resultsChan2 := make(chan pipeline.Result, 1)
	resultsChan2 <- pipeline.Result{
		FilePath: filePath,
		Hash:     "12345",
	}
	close(resultsChan2)

	cfgRename := &Config{Rename: true, Display: false}
	errs2 := processResults(resultsChan2, cfgRename, NewStructuredWriter(io.Discard, cfgRename.Format, cfgRename.OutputFormat))
	if len(errs2) > 0 {
		t.Errorf("Unexpected errors during rename process: %v", errs2)
	}

	expectedNewPath := filepath.Join(tempDir, "12345.txt")
	if _, err := os.Stat(expectedNewPath); os.IsNotExist(err) {
		t.Errorf("File was not renamed correctly to: %s", expectedNewPath)
	}

	// 3. Test processResults rename conflict
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	resultsChan3 := make(chan pipeline.Result, 1)
	resultsChan3 <- pipeline.Result{
		FilePath: filePath,
		Hash:     "12345", // Already exists
	}
	close(resultsChan3)

	errs3 := processResults(resultsChan3, cfgRename, NewStructuredWriter(io.Discard, cfgRename.Format, cfgRename.OutputFormat))
	if len(errs3) != 1 || !strings.Contains(errs3[0].Error(), "file already exists") {
		t.Errorf("Expected file already exists error, got: %v", errs3)
	}

	// 4. Test processResults rename non-existent file error
	resultsChan4 := make(chan pipeline.Result, 1)
	resultsChan4 <- pipeline.Result{
		FilePath: "non-existent-original.txt",
		Hash:     "99999",
	}
	close(resultsChan4)

	errs4 := processResults(resultsChan4, cfgRename, NewStructuredWriter(io.Discard, cfgRename.Format, cfgRename.OutputFormat))
	if len(errs4) != 1 {
		t.Errorf("Expected rename failure error, got: %v", errs4)
	}
}

func TestExecuteMode_Directory(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "testfile.txt")
	if err := os.WriteFile(filePath, []byte("directory-mode-data"), 0o644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	cfg := &Config{
		Mode:        "directory",
		Path:        tempDir,
		FilePattern: "*.txt",
		NumWorkers:  2,
		Display:     false,
	}

	var buf bytes.Buffer
	errs, err := executeMode(cfg, "", testSHA256Hasher, &buf, nil, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h := sha256.New()
	h.Write([]byte("directory-mode-data"))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	expectedOut := fmt.Sprintf("testfile.txt: %s\n", expectedHash)
	if buf.String() != expectedOut {
		t.Errorf("Expected output %q, got %q", expectedOut, buf.String())
	}
}

func TestExecuteMode_String(t *testing.T) {
	cfg := &Config{
		Mode:    "string",
		Display: false,
	}

	input := "hello world string"
	var buf bytes.Buffer
	errs, err := executeMode(cfg, input, testSHA256Hasher, &buf, nil, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h := sha256.New()
	h.Write([]byte(input))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	expectedOut := fmt.Sprintf("%s: %s\n", input, expectedHash)
	if buf.String() != expectedOut {
		t.Errorf("Expected output %q, got %q", expectedOut, buf.String())
	}
}

func TestExecuteMode_StringStdin(t *testing.T) {
	cfg := &Config{
		Mode:    "string",
		Display: false,
	}

	input := "piped stdin content"
	stdinReader := bytes.NewReader([]byte(input))

	var buf bytes.Buffer
	errs, err := executeMode(cfg, "-", testSHA256Hasher, &buf, stdinReader, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h := sha256.New()
	h.Write([]byte(input))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	expectedOut := fmt.Sprintf("stdin: %s\n", expectedHash)
	if buf.String() != expectedOut {
		t.Errorf("Expected output %q, got %q", expectedOut, buf.String())
	}
}

func TestExecuteMode_StringErrorPaths(t *testing.T) {
	cfg := &Config{
		Mode:    "string",
		Display: false,
	}

	// 1. ReadAll failure on Stdin
	_, err := executeMode(cfg, "-", testSHA256Hasher, nil, errorReader{}, io.Discard)
	if err == nil {
		t.Error("Expected error from reading failed stdin, got nil")
	}

	// 2. Hashing failure
	_, err2 := executeMode(cfg, "some-string", errorHasher, nil, nil, io.Discard)
	if err2 == nil {
		t.Error("Expected hashing error, got nil")
	}
}

func TestExecuteMode_Environment(t *testing.T) {
	envVar := "HASHCALCMT_TEST_ENV"
	envVal := "env variable value"
	_ = os.Setenv(envVar, envVal)
	defer func() { _ = os.Unsetenv(envVar) }()

	cfg := &Config{
		Mode:    "environment",
		Display: false,
	}

	var buf bytes.Buffer
	errs, err := executeMode(cfg, envVar, testSHA256Hasher, &buf, nil, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h := sha256.New()
	h.Write([]byte(envVal))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	expectedOut := fmt.Sprintf("%s: %s\n", envVar, expectedHash)
	if buf.String() != expectedOut {
		t.Errorf("Expected output %q, got %q", expectedOut, buf.String())
	}
}

func TestExecuteMode_EnvironmentErrors(t *testing.T) {
	cfg := &Config{
		Mode:    "environment",
		Display: false,
	}

	// 1. Missing arg
	_, err := executeMode(cfg, "", testSHA256Hasher, nil, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "missing environment variable") {
		t.Errorf("Expected missing env var error, got: %v", err)
	}

	// 2. Unset variable
	_, err2 := executeMode(cfg, "UNSET_VARIABLE_xyz", testSHA256Hasher, nil, nil, io.Discard)
	if err2 == nil || !strings.Contains(err2.Error(), "not set") {
		t.Errorf("Expected environment variable not set error, got: %v", err2)
	}

	// 3. Hashing error
	_ = os.Setenv("TEMP_TEST_VAR", "test")
	defer func() { _ = os.Unsetenv("TEMP_TEST_VAR") }()
	_, err3 := executeMode(cfg, "TEMP_TEST_VAR", errorHasher, nil, nil, io.Discard)
	if err3 == nil {
		t.Error("Expected hashing error in environment mode, got nil")
	}
}

func TestExecuteMode_File(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "file.bin")
	content := []byte("file mode hashing contents")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// 1. File hashing
	cfg := &Config{
		Mode:    "file",
		Display: false,
	}

	var buf bytes.Buffer
	errs, err := executeMode(cfg, filePath, testSHA256Hasher, &buf, nil, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h := sha256.New()
	h.Write(content)
	expectedHash := hex.EncodeToString(h.Sum(nil))

	expectedOut := fmt.Sprintf("%s: %s\n", filePath, expectedHash)
	if buf.String() != expectedOut {
		t.Errorf("Expected output %q, got %q", expectedOut, buf.String())
	}

	// 2. Stdin file hashing
	var bufStdin bytes.Buffer
	errs2, err2 := executeMode(cfg, "-", testSHA256Hasher, &bufStdin, bytes.NewReader(content), io.Discard)
	if err2 != nil {
		t.Fatalf("Unexpected fatal error: %v", err2)
	}
	if len(errs2) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs2)
	}
	expectedStdinOut := fmt.Sprintf("stdin: %s\n", expectedHash)
	if bufStdin.String() != expectedStdinOut {
		t.Errorf("Expected stdin output %q, got %q", expectedStdinOut, bufStdin.String())
	}

	// 3. File rename verification
	cfgRename := &Config{
		Mode:    "file",
		Rename:  true,
		Display: false,
	}

	filePathToRename := filepath.Join(tempDir, "rename-me.bin")
	_ = os.WriteFile(filePathToRename, content, 0o644)

	_, err3 := executeMode(cfgRename, filePathToRename, testSHA256Hasher, nil, nil, io.Discard)
	if err3 != nil {
		t.Fatalf("Unexpected fatal error: %v", err3)
	}

	expectedNewPath := filepath.Join(tempDir, expectedHash+".bin")
	if _, err := os.Stat(expectedNewPath); os.IsNotExist(err) {
		t.Errorf("File was not renamed directly in file mode: %s", expectedNewPath)
	}
}

func TestExecuteMode_FileErrors(t *testing.T) {
	cfg := &Config{
		Mode:    "file",
		Display: false,
	}

	// 1. File open failure
	_, err := executeMode(cfg, "non-existent-file-path-xyz.bin", testSHA256Hasher, nil, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "error opening file") {
		t.Errorf("Expected file open error, got: %v", err)
	}

	// 2. Hashing failure
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.bin")
	_ = os.WriteFile(filePath, []byte("data"), 0o644)
	_, err2 := executeMode(cfg, filePath, errorHasher, nil, nil, io.Discard)
	if err2 == nil {
		t.Error("Expected hashing error on file, got nil")
	}

	// 3. Rename conflict failure
	cfgRename := &Config{
		Mode:    "file",
		Rename:  true,
		Display: false,
	}
	hashVal := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // SHA256 of "abc"
	filePathConflict := filepath.Join(tempDir, hashVal+".txt")
	_ = os.WriteFile(filePathConflict, []byte("conflict"), 0o644)

	filePathOrig := filepath.Join(tempDir, "hello.txt")
	_ = os.WriteFile(filePathOrig, []byte("abc"), 0o644)

	_, err3 := executeMode(cfgRename, filePathOrig, testSHA256Hasher, nil, nil, io.Discard)
	if err3 == nil || !strings.Contains(err3.Error(), "file already exists") {
		t.Errorf("Expected rename conflict error, got: %v", err3)
	}
}

func TestExecuteMode_FileList(t *testing.T) {
	tempDir := t.TempDir()
	file1Path := filepath.Join(tempDir, "file1.bin")
	file2Path := filepath.Join(tempDir, "file2.bin")

	content1 := []byte("content one")
	content2 := []byte("content two")

	_ = os.WriteFile(file1Path, content1, 0o644)
	_ = os.WriteFile(file2Path, content2, 0o644)

	// Write file list with blank lines and comments
	fileListContent := fmt.Sprintf("%s\n\n# This is a comment\n%s\n", file1Path, file2Path)
	fileListPath := filepath.Join(tempDir, "list.txt")
	_ = os.WriteFile(fileListPath, []byte(fileListContent), 0o644)

	cfg := &Config{
		Mode:       "file-list",
		Display:    false,
		NumWorkers: 2,
	}

	var buf bytes.Buffer
	errs, err := executeMode(cfg, fileListPath, testSHA256Hasher, &buf, nil, io.Discard)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("Unexpected processing errors: %v", errs)
	}

	h1 := sha256.New()
	h1.Write(content1)
	hash1 := hex.EncodeToString(h1.Sum(nil))

	h2 := sha256.New()
	h2.Write(content2)
	hash2 := hex.EncodeToString(h2.Sum(nil))

	outStr := buf.String()
	expectedString1 := fmt.Sprintf("%s: %s\n", file1Path, hash1)
	expectedString2 := fmt.Sprintf("%s: %s\n", file2Path, hash2)

	if !strings.Contains(outStr, expectedString1) {
		t.Errorf("Expected output to contain %q", expectedString1)
	}
	if !strings.Contains(outStr, expectedString2) {
		t.Errorf("Expected output to contain %q", expectedString2)
	}
}

func TestExecuteMode_FileListErrors(t *testing.T) {
	cfg := &Config{
		Mode:    "file-list",
		Display: false,
	}

	// 1. File list file open failure
	_, err := executeMode(cfg, "non-existent-list.txt", testSHA256Hasher, nil, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "error opening file list") {
		t.Errorf("Expected list file open error, got: %v", err)
	}
}

func TestRunMain_Integration(t *testing.T) {
	// 1. Version check
	cfg := &Config{
		Version: true,
	}
	var stdout, stderr bytes.Buffer
	code := runMain(cfg, nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Errorf("Expected exit code 0 for version check, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Hash MT Generator") {
		t.Errorf("Expected version printout, got %q", stdout.String())
	}

	// 2. Validation error check
	stdout.Reset()
	stderr.Reset()
	cfgInvalid := &Config{
		Mode: "invalid-mode",
	}
	code2 := runMain(cfgInvalid, nil, nil, &stdout, &stderr)
	if code2 != 2 {
		t.Errorf("Expected exit code 2 for validation error, got %d", code2)
	}

	// 3. Invalid Hasher
	stdout.Reset()
	stderr.Reset()
	cfgHasherErr := &Config{
		Mode:     "directory",
		HashType: "INVALID_HASH_ALGO_xyz",
	}
	code3 := runMain(cfgHasherErr, nil, nil, &stdout, &stderr)
	if code3 != 2 {
		t.Errorf("Expected exit code 2 for invalid hasher, got %d", code3)
	}

	// 4. Output File Creation Success & Error paths
	stdout.Reset()
	stderr.Reset()
	tempDir := t.TempDir()
	cfgOutFile := &Config{
		Mode:        "string",
		HashType:    "MD5",
		Path:        ".",
		FilePattern: "*",
		OutFile:     filepath.Join(tempDir, "out.txt"),
		Display:     false,
	}
	code4 := runMain(cfgOutFile, []string{"hello"}, nil, &stdout, &stderr)
	if code4 != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", code4, stderr.String())
	}

	// Verify out.txt contents
	outBytes, err := os.ReadFile(cfgOutFile.OutFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	if !strings.Contains(string(outBytes), "hello:") {
		t.Errorf("Expected output file content to contain result, got %q", string(outBytes))
	}

	// 5. Output File Creation failure path (e.g. invalid directory path)
	stdout.Reset()
	stderr.Reset()
	cfgOutFileErr := &Config{
		Mode:        "string",
		HashType:    "MD5",
		Path:        ".",
		FilePattern: "*",
		OutFile:     filepath.Join(tempDir, "non-existent-folder-abc", "out.txt"),
	}
	code5 := runMain(cfgOutFileErr, []string{"hello"}, nil, &stdout, &stderr)
	if code5 != 4 {
		t.Errorf("Expected exit code 4 for output file creation error, got %d", code5)
	}
}

func TestInputDecodingAndOutputFormatting(t *testing.T) {
	// 1. Test decodeInputString
	testsDecode := []struct {
		name     string
		input    string
		encoding string
		expected []byte
		err      bool
	}{
		{
			name:     "utf8 decoding",
			input:    "hello",
			encoding: "utf8",
			expected: []byte("hello"),
		},
		{
			name:     "utf16le decoding",
			input:    "ab",
			encoding: "utf16le",
			expected: []byte{'a', 0, 'b', 0},
		},
		{
			name:     "utf16be decoding",
			input:    "ab",
			encoding: "utf16be",
			expected: []byte{0, 'a', 0, 'b'},
		},
		{
			name:     "hex decoding",
			input:    "6162",
			encoding: "hex",
			expected: []byte("ab"),
		},
		{
			name:     "invalid hex decoding",
			input:    "invalidhex",
			encoding: "hex",
			err:      true,
		},
		{
			name:     "base64 decoding",
			input:    "YWJj",
			encoding: "base64",
			expected: []byte("abc"),
		},
		{
			name:     "invalid base64 decoding",
			input:    "invalid@@base64",
			encoding: "base64",
			err:      true,
		},
		{
			name:     "base64url decoding",
			input:    "YWJj",
			encoding: "base64url",
			expected: []byte("abc"),
		},
	}

	for _, tc := range testsDecode {
		t.Run(tc.name, func(t *testing.T) {
			res, err := decodeInputString(tc.input, tc.encoding)
			if (err != nil) != tc.err {
				t.Fatalf("Expected error: %v, got: %v", tc.err, err)
			}
			if !tc.err && !bytes.Equal(res, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, res)
			}
		})
	}

	// 2. Test StructuredWriter WriteSingle
	testsSingle := []struct {
		name            string
		filePath        string
		hashHex         string
		format          string
		hashFormat      string
		displayOnlyHash bool
		expected        string
	}{
		{
			name:            "text-hex displayOnlyHash",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "6162\n",
		},
		{
			name:            "text-hex with filepath",
			filePath:        "test.txt",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "hex",
			displayOnlyHash: false,
			expected:        "test.txt: 6162\n",
		},
		{
			name:            "json single",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "json",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "{\n  \"source\": \"stdin\",\n  \"hash\": \"6162\"\n}\n",
		},
		{
			name:            "yaml single",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "yaml",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "source: \"stdin\"\nhash: \"6162\"\n",
		},
		{
			name:            "csv single",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "csv",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "source,hash\nstdin,6162\n",
		},
		{
			name:            "tsv single",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "tsv",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "source\thash\nstdin\t6162\n",
		},
		{
			name:            "text-hex-upper",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "hex-upper",
			displayOnlyHash: true,
			expected:        "6162\n",
		},
		{
			name:            "text-base64",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "base64",
			displayOnlyHash: true,
			expected:        "YWI=\n",
		},
		{
			name:            "text-base64url",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "base64url",
			displayOnlyHash: true,
			expected:        "YWI\n",
		},
		{
			name:            "text-raw displayOnlyHash",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "raw",
			displayOnlyHash: true,
			expected:        "ab",
		},
		{
			name:            "text-raw no-displayOnlyHash",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "text",
			hashFormat:      "raw",
			displayOnlyHash: false,
			expected:        "stdin: ab\n",
		},
		{
			name:            "csv escaping",
			filePath:        "a,b\"c",
			hashHex:         "6162",
			format:          "csv",
			hashFormat:      "hex",
			displayOnlyHash: false,
			expected:        "source,hash\n\"a,b\"\"c\",6162\n",
		},
		{
			name:            "tsv escaping",
			filePath:        "a\tb\"c",
			hashHex:         "6162",
			format:          "tsv",
			hashFormat:      "hex",
			displayOnlyHash: false,
			expected:        "source\thash\n\"a\tb\"\"c\"\t6162\n",
		},
		{
			name:            "sql single",
			filePath:        "stdin",
			hashHex:         "6162",
			format:          "sql",
			hashFormat:      "hex",
			displayOnlyHash: true,
			expected:        "CREATE TABLE IF NOT EXISTS hashes (source TEXT, hash TEXT);\nINSERT INTO hashes (source, hash) VALUES ('stdin', '6162');\n",
		},
	}

	for _, tc := range testsSingle {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			sw := NewStructuredWriter(&out, tc.format, tc.hashFormat)
			err := sw.WriteSingle(tc.filePath, tc.hashHex, tc.displayOnlyHash)
			if err != nil {
				t.Fatalf("Unexpected format error: %v", err)
			}
			if out.String() != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, out.String())
			}
		})
	}

	t.Run("StructuredWriter error paths", func(t *testing.T) {
		var out bytes.Buffer
		sw := NewStructuredWriter(&out, "text", "base64")
		err := sw.WriteSingle("stdin", "invalidhex", true)
		if err == nil {
			t.Errorf("Expected error for invalid hex hash, got nil")
		}

		err = sw.WriteRecord("file.txt", "invalidhex")
		if err == nil {
			t.Errorf("Expected error for invalid hex hash record, got nil")
		}

		swRaw := NewStructuredWriter(&out, "text", "raw")
		err = swRaw.WriteSingle("stdin", "invalidhex", true)
		if err == nil {
			t.Errorf("Expected error for raw invalid hex hash, got nil")
		}

		err = swRaw.WriteRecord("file.txt", "invalidhex")
		if err == nil {
			t.Errorf("Expected error for raw invalid hex hash record, got nil")
		}
	})

	// 3. Test StructuredWriter WriteRecord & Header/Footer
	t.Run("structured sequence tests", func(t *testing.T) {
		// JSON Sequence
		var outJson bytes.Buffer
		swJson := NewStructuredWriter(&outJson, "json", "hex")
		_ = swJson.WriteHeader()
		_ = swJson.WriteRecord("file1.txt", "abc1")
		_ = swJson.WriteRecord("file2.txt", "abc2")
		_ = swJson.WriteFooter()
		expectedJson := "[\n  {\n    \"file_path\": \"file1.txt\",\n    \"hash\": \"abc1\"\n  },\n  {\n    \"file_path\": \"file2.txt\",\n    \"hash\": \"abc2\"\n  }\n]\n"
		if outJson.String() != expectedJson {
			t.Errorf("Expected JSON sequence %q, got %q", expectedJson, outJson.String())
		}

		// YAML Sequence
		var outYaml bytes.Buffer
		swYaml := NewStructuredWriter(&outYaml, "yaml", "hex")
		_ = swYaml.WriteHeader()
		_ = swYaml.WriteRecord("file1.txt", "abc1")
		_ = swYaml.WriteRecord("file2.txt", "abc2")
		_ = swYaml.WriteFooter()
		expectedYaml := "- file_path: \"file1.txt\"\n  hash: \"abc1\"\n- file_path: \"file2.txt\"\n  hash: \"abc2\"\n"
		if outYaml.String() != expectedYaml {
			t.Errorf("Expected YAML sequence %q, got %q", expectedYaml, outYaml.String())
		}

		// CSV Sequence
		var outCsv bytes.Buffer
		swCsv := NewStructuredWriter(&outCsv, "csv", "hex")
		_ = swCsv.WriteHeader()
		_ = swCsv.WriteRecord("file1.txt", "abc1")
		_ = swCsv.WriteRecord("file2.txt", "abc2")
		expectedCsv := "file_path,hash\nfile1.txt,abc1\nfile2.txt,abc2\n"
		if outCsv.String() != expectedCsv {
			t.Errorf("Expected CSV sequence %q, got %q", expectedCsv, outCsv.String())
		}

		// TSV Sequence
		var outTsv bytes.Buffer
		swTsv := NewStructuredWriter(&outTsv, "tsv", "hex")
		_ = swTsv.WriteHeader()
		_ = swTsv.WriteRecord("file1.txt", "abc1")
		_ = swTsv.WriteRecord("file2.txt", "abc2")
		expectedTsv := "file_path\thash\nfile1.txt\tabc1\nfile2.txt\tabc2\n"
		if outTsv.String() != expectedTsv {
			t.Errorf("Expected TSV sequence %q, got %q", expectedTsv, outTsv.String())
		}

		// SQL Sequence
		var outSql bytes.Buffer
		swSql := NewStructuredWriter(&outSql, "sql", "hex")
		_ = swSql.WriteHeader()
		_ = swSql.WriteRecord("file'1.txt", "abc1")
		_ = swSql.WriteRecord("file2.txt", "abc2")
		_ = swSql.WriteFooter()
		expectedSql := "CREATE TABLE IF NOT EXISTS hashes (file_path TEXT, hash TEXT);\nBEGIN TRANSACTION;\nINSERT INTO hashes (file_path, hash) VALUES ('file''1.txt', 'abc1');\nINSERT INTO hashes (file_path, hash) VALUES ('file2.txt', 'abc2');\nCOMMIT;\n"
		if outSql.String() != expectedSql {
			t.Errorf("Expected SQL sequence %q, got %q", expectedSql, outSql.String())
		}
	})
}

func TestEncodingIntegration(t *testing.T) {
	// Test string mode with base64 input decoding and base64url output format
	var stdout, stderr bytes.Buffer
	cfg := &Config{
		Mode:          "string",
		HashType:      "SHA256",
		Path:          ".",
		FilePattern:   "*",
		InputEncoding: "base64",
		OutputFormat:  "base64url",
		Display:       true,
	}

	// Input is "YWJj" (which decodes to "abc")
	// SHA256 of "abc" is ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// Base64Url (no padding) of that SHA256 bytes is:
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad -> bytes
	// encoded: ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0
	code := runMain(cfg, []string{"YWJj"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Expected runMain to return 0, got %d, stderr: %s", code, stderr.String())
	}

	expectedOutput := "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0\n"
	if stdout.String() != expectedOutput {
		t.Errorf("Expected output %q, got %q", expectedOutput, stdout.String())
	}
}
