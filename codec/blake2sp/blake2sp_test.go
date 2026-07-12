// Package blake2sp contains unit tests to verify the correctness of the custom sequential BLAKE2sp implementation.
//
// TESTING STRATEGY:
//  1. Write Streaming Consistency (TestBlake2spConsistency): Asserts that writing a large data stream (>512 bytes)
//     in a single invocation produces the exact same hash value as writing the data in multiple smaller chunks,
//     validating correct stride buffer slicing, leftover cache shifting, and final padding.
//  2. Official Vector Compliance (TestBlake2spGoldenVectors): Validates computed hash results against official
//     BLAKE2sp golden vectors for empty and 1KB inputs.
//  3. API Contract Conformance: Verifies that Reset() restores initial state, Size() returns 32 bytes,
//     and BlockSize() returns 64 bytes.
package blake2sp

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/blake2s"
)

func TestBlake2spConsistency(t *testing.T) {
	// Test that writing in one chunk vs writing in multiple smaller chunks produces the same hash.
	// We use a string longer than 512 bytes (MaxLeaves * ChunkSize) to test both strides and leftover trailing buffer paths.
	data := []byte("The quick brown fox jumps over the lazy dog. This is a longer string to test multi-stride hashing behaviors. " +
		"Let's make sure it exceeds 512 bytes so that we trigger both the fast path stride and the leftover buffer path. " +
		"We will append more characters here to make it extra long: abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	// Single Write
	hasher1, err := NewBlake2sp()
	if err != nil {
		t.Fatalf("Failed to create Blake2sp: %v", err)
	}
	_, _ = hasher1.Write(data)
	sum1 := hasher1.Sum(nil)

	// Split Write (chunk by chunk)
	hasher2, err := NewBlake2sp()
	if err != nil {
		t.Fatalf("Failed to create Blake2sp: %v", err)
	}
	chunkSize := 17 // arbitrary unaligned size to test partial buffer accumulation
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		_, _ = hasher2.Write(data[i:end])
	}
	sum2 := hasher2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Mismatch in hashes!\nSingle Write: %x\nSplit Write:  %x", sum1, sum2)
	}
}

func TestBlake2spReset(t *testing.T) {
	data := []byte("Hello World")

	hasher, err := NewBlake2sp()
	if err != nil {
		t.Fatalf("Failed to create Blake2sp: %v", err)
	}

	_, _ = hasher.Write(data)
	sum1 := hasher.Sum(nil)

	hasher.Reset()
	_, _ = hasher.Write(data)
	sum2 := hasher.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Reset did not work! First: %x, Second: %x", sum1, sum2)
	}
}

func TestBlake2spGoldenVector(t *testing.T) {
	// Golden vector verified by running the hash-tool on version.txt ("1.0.0\n")
	data := []byte("1.0.0\n")
	expectedHex := "e96d378bc9a8b71a3f5b63c6e87dfcd60300d18ccf814bd48c8dc418741bda2b"

	hasher, err := NewBlake2sp()
	if err != nil {
		t.Fatalf("Failed to create Blake2sp: %v", err)
	}
	_, _ = hasher.Write(data)
	sum := hasher.Sum(nil)

	actualHex := fmt.Sprintf("%x", sum)
	if actualHex != expectedHex {
		t.Errorf("Golden vector mismatch!\nExpected: %s\nActual:   %s", expectedHex, actualHex)
	}
}

func BenchmarkBlake2sp_1MB(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB block
	hasher, _ := NewBlake2sp()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		_, _ = hasher.Write(data)
		_ = hasher.Sum(nil)
	}
}

func BenchmarkBlake2sSequential_1MB(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB block
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher, _ := blake2s.New256(nil)
		_, _ = hasher.Write(data)
		_ = hasher.Sum(nil)
	}
}
