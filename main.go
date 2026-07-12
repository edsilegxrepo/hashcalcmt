// Package main serves as the primary CLI entrypoint and orchestrator for the Hash MT Generator.
//
// OBJECTIVES:
// 1. Parse and validate CLI flags according to a strict flag validation matrix.
// 2. Select the requested hashing algorithm and configure concurrency settings.
// 3. Coordinate input source routing (directory walk, stdin string/stream, env var, single file, or file-list).
// 4. Stream computed hashes to the designated outputs (stdout, result file) and handle file renaming.
// 5. Provide diagnostic exit codes for CLI script integration.
//
// CORE COMPONENTS & DATA FLOWS:
//   - Flag Parser (parseFlags): Translates command-line flags into a structured Config.
//   - Config Validator (validateConfig): Checks for disallowed flags based on the active mode of operation.
//   - Main Coordinator (runMain): Orchestrates execution paths, file descriptors, and handles exit codes.
//   - Results Processor (processResults): Collects asynchronous hashing results via channels, streams them to
//     the designated output writer, renames files if requested, and catches/accumulates failures.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"

	"criticalsys.net/hashcalcmt/hasher"
	"criticalsys.net/hashcalcmt/pipeline"
)

var version string

const (
	ExitSuccess        = 0
	ExitExecutionError = 1
	ExitConfigError    = 2
	ExitPartialFailure = 3
	ExitWriteFailure   = 4
	ExitRenameConflict = 5
)

// Config holds the application configuration.
type Config struct {
	Mode        string
	FilePattern string
	Path        string
	HashType    string
	OutFile     string
	Rename      bool
	Display     bool
	Version     bool
	NumWorkers  int
	// InputEncoding specifies the string transcoding/decoding format (e.g., utf16le, base64) for string and env modes.
	InputEncoding string
	// OutputFormat specifies the final hash representation format (e.g., hex, base64, raw).
	OutputFormat string
	// Format specifies the structured layout format (e.g., text, json, yaml, csv, tsv) for outputting results.
	Format string
}

// main is the entry point of the Hash MT Generator tool.
func main() {
	cfg := parseFlags()
	os.Exit(runMain(cfg, flag.Args(), os.Stdin, os.Stdout, os.Stderr))
}

// runMain executes the application coordinator and returns the status code (0 for success, non-zero for error).
// Data Flow:
// 1. Checks if version flag is requested, prints version and exits with ExitSuccess.
// 2. Validates flag configurations to prevent incompatible flag sets.
// 3. Obtains the target hashing algorithm implementation.
// 4. Configures output streaming writer (bufio buffered to file).
// 5. Triggers executeMode and collects processing errors.
// 6. Inspects collected errors to return granular exit codes.
func runMain(cfg *Config, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if cfg.Version {
		_, _ = fmt.Fprintf(stdout, "Hash MT Generator - Version: %s\n", version)
		return ExitSuccess
	}

	// Validate config constraints (e.g. mode-exclusive flags)
	if err := validateConfig(cfg); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitConfigError
	}

	// Extract the primary positional argument (the target string, file path, list path, or env var)
	var input string
	if cfg.Mode != "directory" {
		if len(args) > 0 {
			input = args[0]
		}
	}

	// Retrieve hasher function based on config string
	hf, err := hasher.GetHasher(cfg.HashType)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitConfigError
	}

	// Prepare results file output writer if requested
	var outWriter io.Writer
	var outFile *os.File
	if cfg.OutFile != "" {
		cfg.OutFile = filepath.Clean(cfg.OutFile)
		f, err := os.Create(cfg.OutFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error creating output file: %v\n", err)
			return ExitWriteFailure
		}
		outFile = f
		bufWriter := bufio.NewWriter(outFile)
		outWriter = bufWriter
		defer func() {
			// Ensure all buffers are flushed to disk on return to prevent data loss
			_ = bufWriter.Flush()
			_ = outFile.Close()
		}()
	}

	// Route execution to the correct mode-handler
	errs, err := executeMode(cfg, input, hf, outWriter, stdin, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitExecutionError
	}

	// Inspect errors to choose the correct diagnostic exit code
	if len(errs) > 0 {
		_, _ = fmt.Fprintln(stderr, "\nErrors encountered:")
		hasRenameConflict := false
		hasReadFailure := false
		for _, err := range errs {
			_, _ = fmt.Fprintln(stderr, "-", err)
			if strings.Contains(err.Error(), "already exists") {
				hasRenameConflict = true
			} else {
				hasReadFailure = true
			}
		}
		if hasReadFailure {
			return ExitPartialFailure
		}
		if hasRenameConflict {
			return ExitRenameConflict
		}
		return ExitExecutionError
	}

	return ExitSuccess
}

// parseFlags defines and parses CLI flags into a Config struct.
func parseFlags() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.Mode, "mode", "directory", "Mode of operation: string, environment, file, file-list, directory")
	flag.StringVar(&cfg.FilePattern, "file-pattern", "*", "File pattern to search")
	flag.StringVar(&cfg.Path, "path", ".", "Directory to search")
	flag.StringVar(&cfg.HashType, "hash", hasher.HashMD5, "Hash type: MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512, SHA512-224, SHA512-256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2S, BLAKE2B, BLAKE2SP, BLAKE3, CRC32, CRC64, XXH32, XXH64, XXH3-64, XXH3-128, HIGHWAYHASH, WYHASH, ADLER32, FNV32A, FNV64A, FNV128A, SM3, RIPEMD160")
	flag.StringVar(&cfg.OutFile, "out-file", "", "File to store the results")
	flag.BoolVar(&cfg.Rename, "rename", false, "Rename files to their hash value")
	flag.BoolVar(&cfg.Display, "display", true, "Display hash values to the user")
	flag.BoolVar(&cfg.Version, "version", false, "Display version information")
	flag.IntVar(&cfg.NumWorkers, "workers", runtime.NumCPU(), "Number of worker goroutines")
	flag.StringVar(&cfg.InputEncoding, "input-encoding", "utf8", "Input encoding for string/env modes: utf8, utf16le, utf16be, hex, base64, base64url")
	flag.StringVar(&cfg.OutputFormat, "output-format", "hex", "Output format: hex, hex-upper, base64, base64url, raw")
	flag.StringVar(&cfg.Format, "format", "text", "Output format structure: text, json, yaml, csv, tsv")
	flag.Parse()
	return cfg
}

// validateConfig checks if the configurations violate flag restrictions.
// Validates:
// 1. Mode is supported.
// 2. Directory flags (--path, --file-pattern) are only allowed in "directory" mode.
// 3. Rename (--rename) is only allowed in file/directory modes.
// 4. Input encoding is supported.
// 5. Output format is supported.
// 6. Input encoding is restricted to string or environment modes.
// 7. Output structure format is supported.
func validateConfig(cfg *Config) error {
	switch cfg.Mode {
	case "string", "environment", "file", "file-list", "directory":
		// OK
	default:
		return fmt.Errorf("invalid mode: %s. Supported: string, environment, file, file-list, directory", cfg.Mode)
	}

	if cfg.Mode != "directory" {
		if cfg.Path != "." || cfg.FilePattern != "*" {
			return fmt.Errorf("error: flags --path and --file-pattern can only be used in 'directory' mode")
		}
	}
	if cfg.Mode == "string" || cfg.Mode == "environment" {
		if cfg.Rename {
			return fmt.Errorf("error: flag --rename cannot be used in string or environment modes")
		}
	}

	switch strings.ToLower(cfg.InputEncoding) {
	case "utf8", "utf16le", "utf16be", "hex", "base64", "base64url", "":
		// OK
	default:
		return fmt.Errorf("error: unsupported input encoding: %s", cfg.InputEncoding)
	}

	switch strings.ToLower(cfg.OutputFormat) {
	case "hex", "hex-upper", "base64", "base64url", "raw", "":
		// OK
	default:
		return fmt.Errorf("error: unsupported output format: %s", cfg.OutputFormat)
	}

	switch strings.ToLower(cfg.Format) {
	case "text", "json", "yaml", "csv", "tsv", "sql", "":
		// OK
	default:
		return fmt.Errorf("error: unsupported format: %s", cfg.Format)
	}

	if cfg.Mode != "string" && cfg.Mode != "environment" {
		if cfg.InputEncoding != "utf8" && cfg.InputEncoding != "" {
			return fmt.Errorf("error: flag --input-encoding can only be used in string or environment modes")
		}
	}

	return nil
}

// executeMode executes the appropriate logic based on config Mode.
// Streams data into hashing functions and processes output results.
func executeMode(cfg *Config, input string, hf hasher.Func, outWriter io.Writer, stdin io.Reader, stdout io.Writer) ([]error, error) {
	var errs []error

	// Create StructuredWriter helper for the active destination
	var sw *StructuredWriter
	if outWriter != nil {
		sw = NewStructuredWriter(outWriter, cfg.Format, cfg.OutputFormat)
	} else if cfg.Display && cfg.OutFile == "" {
		sw = NewStructuredWriter(stdout, cfg.Format, cfg.OutputFormat)
	}

	switch cfg.Mode {
	case "directory":
		// Multi-threaded directory scanner mode (utilizes os.Root sandboxing)
		if sw != nil {
			if err := sw.WriteHeader(); err != nil {
				return nil, fmt.Errorf("error writing header: %w", err)
			}
		}
		results := pipeline.Run(cfg.Path, cfg.FilePattern, cfg.NumWorkers, hf)
		errs = processResults(results, cfg, sw)
		if sw != nil {
			if err := sw.WriteFooter(); err != nil {
				errs = append(errs, fmt.Errorf("error writing footer: %w", err))
			}
		}

	case "string":
		// Hash raw string mode
		var data string
		if input == "" || input == "-" {
			// Read text content from standard input (stdin)
			bytesData, err := io.ReadAll(stdin)
			if err != nil {
				return nil, fmt.Errorf("error reading from stdin: %w", err)
			}
			data = string(bytesData)
		} else {
			data = input
		}

		decodedInput, err := decodeInputString(data, cfg.InputEncoding)
		if err != nil {
			return nil, fmt.Errorf("error decoding string: %w", err)
		}

		hashVal, err := hf(bytes.NewReader(decodedInput))
		if err != nil {
			return nil, fmt.Errorf("error hashing: %w", err)
		}

		sourceLabel := "stdin"
		if input != "" && input != "-" {
			sourceLabel = input
		}

		if sw != nil {
			displayOnlyHash := (cfg.OutFile == "" && cfg.Display)
			if err := sw.WriteSingle(sourceLabel, hashVal, displayOnlyHash); err != nil {
				return nil, fmt.Errorf("error writing result: %w", err)
			}
		}

	case "environment":
		// Environment variable hashing mode
		if input == "" {
			return nil, fmt.Errorf("error: missing environment variable name argument")
		}
		val, exists := os.LookupEnv(input)
		if !exists {
			return nil, fmt.Errorf("error: environment variable %s is not set", input)
		}

		decodedInput, err := decodeInputString(val, cfg.InputEncoding)
		if err != nil {
			return nil, fmt.Errorf("error decoding environment variable: %w", err)
		}

		hashVal, err := hf(bytes.NewReader(decodedInput))
		if err != nil {
			return nil, fmt.Errorf("error hashing: %w", err)
		}

		if sw != nil {
			displayOnlyHash := (cfg.OutFile == "" && cfg.Display)
			if err := sw.WriteSingle(input, hashVal, displayOnlyHash); err != nil {
				return nil, fmt.Errorf("error writing result: %w", err)
			}
		}

	case "file":
		// Single file hashing mode (supports stdin stream piping)
		var r io.Reader
		var filePath string
		var file *os.File

		if input == "" || input == "-" {
			r = stdin
			filePath = "stdin"
		} else {
			filePath = filepath.Clean(input)
			f, err := os.Open(filePath)
			if err != nil {
				return nil, fmt.Errorf("error opening file: %w", err)
			}
			file = f
			r = file
		}

		hashVal, err := hf(r)
		if file != nil {
			// Explicitly close the file handle BEFORE rename checking (avoids sharing locks on Windows)
			_ = file.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("error hashing file: %w", err)
		}

		if cfg.Rename && filePath != "stdin" {
			newPath := filepath.Join(filepath.Dir(filePath), hashVal+filepath.Ext(filePath))
			// Verify destination does not already exist to prevent data overwrites
			if _, err := os.Stat(newPath); err == nil {
				return nil, fmt.Errorf("error: could not rename %s to %s: file already exists", filePath, newPath)
			}
			if err := os.Rename(filePath, newPath); err != nil {
				return nil, fmt.Errorf("error renaming file %s: %w", filePath, err)
			}
			filePath = newPath
		}

		if sw != nil {
			if err := sw.WriteSingle(filePath, hashVal, false); err != nil {
				return nil, fmt.Errorf("error writing result: %w", err)
			}
		}

	case "file-list":
		// Predefined file list hashing mode (concurrently hashes files listed in a text file or stdin)
		var r io.Reader
		if input == "" || input == "-" {
			r = stdin
		} else {
			f, err := os.Open(filepath.Clean(input))
			if err != nil {
				return nil, fmt.Errorf("error opening file list: %w", err)
			}
			defer func() { _ = f.Close() }()
			r = f
		}

		var paths []string
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Ignore blank lines and lines starting with '#' (comments)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			paths = append(paths, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading file list: %w", err)
		}

		if sw != nil {
			if err := sw.WriteHeader(); err != nil {
				return nil, fmt.Errorf("error writing header: %w", err)
			}
		}
		results := pipeline.RunFileList(paths, cfg.NumWorkers, hf)
		errs = processResults(results, cfg, sw)
		if sw != nil {
			if err := sw.WriteFooter(); err != nil {
				errs = append(errs, fmt.Errorf("error writing footer: %w", err))
			}
		}
	}

	return errs, nil
}

// processResults iterates over the results channel and handles renaming, display, and streaming.
// It reads from the results channel until closed, outputting and/or renaming files in O(1) memory.
func processResults(results <-chan pipeline.Result, cfg *Config, sw *StructuredWriter) []error {
	var errs []error

	for result := range results {
		// Capture and store errors from workers
		if result.Error != nil {
			errs = append(errs, fmt.Errorf("error processing file %s: %w", result.FilePath, result.Error))
			continue
		}

		// Handle file renaming in place inside its original directory
		if cfg.Rename {
			newPath := filepath.Join(filepath.Dir(result.FilePath), result.Hash+filepath.Ext(result.FilePath))
			if _, err := os.Stat(newPath); err == nil {
				errs = append(errs, fmt.Errorf("could not rename %s to %s: file already exists", result.FilePath, newPath))
				continue
			}
			if err := os.Rename(result.FilePath, newPath); err != nil {
				errs = append(errs, fmt.Errorf("error renaming file %s: %w", result.FilePath, err))
				continue
			}
		}

		// Stream output directly to the writer if active
		if sw != nil {
			if err := sw.WriteRecord(result.FilePath, result.Hash); err != nil {
				errs = append(errs, fmt.Errorf("error writing result for %s: %w", result.FilePath, err))
			}
		}
	}
	return errs
}

// decodeInputString decodes a raw string based on the chosen input encoding.
func decodeInputString(data string, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "utf8", "":
		return []byte(data), nil
	case "utf16le":
		runes := utf16.Encode([]rune(data))
		buf := make([]byte, len(runes)*2)
		for i, r := range runes {
			binary.LittleEndian.PutUint16(buf[i*2:], r)
		}
		return buf, nil
	case "utf16be":
		runes := utf16.Encode([]rune(data))
		buf := make([]byte, len(runes)*2)
		for i, r := range runes {
			binary.BigEndian.PutUint16(buf[i*2:], r)
		}
		return buf, nil
	case "hex":
		cleaned := strings.TrimSpace(data)
		buf, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid hex input: %w", err)
		}
		return buf, nil
	case "base64":
		cleaned := strings.TrimSpace(data)
		buf, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 input: %w", err)
		}
		return buf, nil
	case "base64url":
		cleaned := strings.TrimSpace(data)
		buf, err := base64.URLEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url input: %w", err)
		}
		return buf, nil
	default:
		return nil, fmt.Errorf("unsupported input encoding: %s", encoding)
	}
}

// StructuredWriter coordinates output formats (hex/base64/raw) and layout structures (text/json/yaml/csv/tsv/sql).
type StructuredWriter struct {
	writer     io.Writer
	format     string
	hashFormat string
	hasWritten bool
}

// NewStructuredWriter creates a StructuredWriter helper.
func NewStructuredWriter(w io.Writer, format, hashFormat string) *StructuredWriter {
	return &StructuredWriter{
		writer:     w,
		format:     strings.ToLower(format),
		hashFormat: strings.ToLower(hashFormat),
	}
}

// WriteHeader prints schema structure headers (brackets, CSV fields, SQL transactions).
func (sw *StructuredWriter) WriteHeader() error {
	switch sw.format {
	case "json":
		_, err := fmt.Fprint(sw.writer, "[\n")
		return err
	case "csv":
		_, err := fmt.Fprint(sw.writer, "file_path,hash\n")
		return err
	case "tsv":
		_, err := fmt.Fprint(sw.writer, "file_path\thash\n")
		return err
	case "sql":
		_, err := fmt.Fprint(sw.writer, "CREATE TABLE IF NOT EXISTS hashes (file_path TEXT, hash TEXT);\nBEGIN TRANSACTION;\n")
		return err
	}
	return nil
}

// WriteRecord prints a single file-path to hash mapping to the structured stream.
func (sw *StructuredWriter) WriteRecord(filePath string, hashHex string) error {
	if sw.hashFormat == "raw" && (sw.format == "text" || sw.format == "") {
		bytesVal, err := hex.DecodeString(hashHex)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(sw.writer, "%s: %s\n", filePath, string(bytesVal))
		return err
	}

	hashVal, err := sw.formatHash(hashHex)
	if err != nil {
		return err
	}

	switch sw.format {
	case "json":
		if sw.hasWritten {
			if _, err := fmt.Fprint(sw.writer, ",\n"); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(sw.writer, "  {\n    \"file_path\": %s,\n    \"hash\": %s\n  }", strconv.Quote(filePath), strconv.Quote(hashVal))
		sw.hasWritten = true
		return err
	case "yaml":
		_, err = fmt.Fprintf(sw.writer, "- file_path: %s\n  hash: %s\n", strconv.Quote(filePath), strconv.Quote(hashVal))
		return err
	case "csv":
		_, err = fmt.Fprintf(sw.writer, "%s,%s\n", sw.quoteCSV(filePath), sw.quoteCSV(hashVal))
		return err
	case "tsv":
		_, err = fmt.Fprintf(sw.writer, "%s\t%s\n", sw.quoteTSV(filePath), sw.quoteTSV(hashVal))
		return err
	case "sql":
		_, err = fmt.Fprintf(sw.writer, "INSERT INTO hashes (file_path, hash) VALUES (%s, %s);\n", sw.escapeSQL(filePath), sw.escapeSQL(hashVal))
		return err
	default:
		_, err = fmt.Fprintf(sw.writer, "%s: %s\n", filePath, hashVal)
		return err
	}
}

// WriteSingle prints a single target result.
func (sw *StructuredWriter) WriteSingle(sourceLabel string, hashHex string, displayOnlyHash bool) error {
	if sw.hashFormat == "raw" && (sw.format == "text" || sw.format == "") {
		bytesVal, err := hex.DecodeString(hashHex)
		if err != nil {
			return err
		}
		if displayOnlyHash {
			_, err = sw.writer.Write(bytesVal)
		} else {
			_, err = fmt.Fprintf(sw.writer, "%s: %s\n", sourceLabel, string(bytesVal))
		}
		return err
	}

	hashVal, err := sw.formatHash(hashHex)
	if err != nil {
		return err
	}

	switch sw.format {
	case "json":
		_, err = fmt.Fprintf(sw.writer, "{\n  \"source\": %s,\n  \"hash\": %s\n}\n", strconv.Quote(sourceLabel), strconv.Quote(hashVal))
		return err
	case "yaml":
		_, err = fmt.Fprintf(sw.writer, "source: %s\nhash: %s\n", strconv.Quote(sourceLabel), strconv.Quote(hashVal))
		return err
	case "csv":
		_, err = fmt.Fprintf(sw.writer, "source,hash\n%s,%s\n", sw.quoteCSV(sourceLabel), sw.quoteCSV(hashVal))
		return err
	case "tsv":
		_, err = fmt.Fprintf(sw.writer, "source\thash\n%s\t%s\n", sw.quoteTSV(sourceLabel), sw.quoteTSV(hashVal))
		return err
	case "sql":
		_, err = fmt.Fprintf(sw.writer, "CREATE TABLE IF NOT EXISTS hashes (source TEXT, hash TEXT);\nINSERT INTO hashes (source, hash) VALUES (%s, %s);\n", sw.escapeSQL(sourceLabel), sw.escapeSQL(hashVal))
		return err
	default:
		if displayOnlyHash {
			_, err = fmt.Fprintf(sw.writer, "%s\n", hashVal)
		} else {
			_, err = fmt.Fprintf(sw.writer, "%s: %s\n", sourceLabel, hashVal)
		}
		return err
	}
}

// WriteFooter prints footer structures (bracket endings, SQL commits).
func (sw *StructuredWriter) WriteFooter() error {
	switch sw.format {
	case "json":
		_, err := fmt.Fprint(sw.writer, "\n]\n")
		return err
	case "sql":
		_, err := fmt.Fprint(sw.writer, "COMMIT;\n")
		return err
	}
	return nil
}

func (sw *StructuredWriter) formatHash(hashHex string) (string, error) {
	switch sw.hashFormat {
	case "hex", "":
		return hashHex, nil
	case "hex-upper":
		return strings.ToUpper(hashHex), nil
	case "base64":
		bytesVal, err := hex.DecodeString(hashHex)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(bytesVal), nil
	case "base64url":
		bytesVal, err := hex.DecodeString(hashHex)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(bytesVal), nil
	case "raw":
		bytesVal, err := hex.DecodeString(hashHex)
		if err != nil {
			return "", err
		}
		return string(bytesVal), nil
	default:
		return "", fmt.Errorf("unsupported output format: %s", sw.hashFormat)
	}
}

func (sw *StructuredWriter) quoteCSV(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (sw *StructuredWriter) quoteTSV(s string) string {
	if strings.ContainsAny(s, "\t\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (sw *StructuredWriter) escapeSQL(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
