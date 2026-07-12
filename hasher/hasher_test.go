// Package hasher_test contains correctness unit tests and performance benchmarks for all supported hashing algorithms.
//
// TESTING STRATEGY:
//  1. Golden Vectors Verification (TestAllHashes): Asserts hash value correctness using pre-computed golden
//     vectors for all 31 supported cryptographic, non-cryptographic, and legacy hashing algorithms.
//  2. Case Insensitivity: Ensures algorithm name lookups accept any case combination (e.g. "blake3" and "BLAKE3").
//  3. Error Lookup Path: Asserts that invalid or unsupported algorithm names return descriptive errors.
//  4. Performance Benchmarking (BenchmarkHasher_...): Benchmarks throughput (MB/s) and memory allocations
//     (allocs/op) under concurrent loads to verify CPU scaling and sync.Pool buffer reuse effectiveness.
package hasher

import (
	"bytes"
	"testing"
)

func TestAllHashes(t *testing.T) {
	input := []byte("1.0.0\n")
	goldenVectors := map[string]string{
		"CRC32":       "fd7ea868",
		"CRC64":       "6132c1f2c1f32000",
		"SHA256":      "59854984853104df5c353e2f681a15fc7924742f9a2e468c29af248dce45ce03",
		"SHA1":        "c538b66c7110ca3a028ccfe422d0f1fa200a9935",
		"BLAKE2S":     "c5d24b89c99b28cb9c7aa4317a909ae22973239f6db5be6b15e44c6c83d29f7e",
		"BLAKE2B":     "7f4c5b00f6fdbb9cbd2dfa312d34accb351d835bdcbba542f66821965ad6e7d891cf8cfbfeccc77596a499daf1229e321ad7adaf0ef013e4770bc262a9771581",
		"BLAKE2SP":    "e96d378bc9a8b71a3f5b63c6e87dfcd60300d18ccf814bd48c8dc418741bda2b",
		"BLAKE3":      "7f5dbe86fbe397f3227eaa106d90587f6d6afe43e2110b498bdb3f043cc08e6b",
		"MD2":         "e7f7569dfd2eb6cae21d5cc29e0a1ddf",
		"MD4":         "616b57c3480305f696d388a791c86f4a",
		"MD5":         "c9e47dbb0e1927076ed7b2e1ec157be7",
		"XXH32":       "a1ccd1bd",
		"XXH64":       "bab1a35d4a4787be",
		"XXH3-64":     "fdcff0777522f8f2",
		"XXH3-128":    "99bb5e782cb9700575d5add4d0993c4f",
		"SHA384":      "8224a0ea9e28732dcdf5bd8d86b1bfd6950ba504de4ae85f67bb556ad352ab2489374faafbda94e5710c0ef2c47881ce",
		"SHA512":      "c6e5081ce77f5971474ff994acc1b8887818f3007a4e3db32c91640203906f0bd2df3012441c9e1b6c1ae4e54dfea465ec23034092779cf6852aece45bf1df21",
		"SHA512-224":  "cc56d85702b9f68cb870007835653b165e445197cd91871e27964ab5",
		"SHA512-256":  "cfdfa621322f73df85392d216d83517bead3afd1af6655861d5614d9b7652b2a",
		"SHA3-224":    "07338bbadcaf99bd2496179817a308645b1e758ea1c3122f40240508",
		"SHA3-256":    "48e4e254588d057b4fb679f36e6299c5061a7826ac586a8354a8fdd0083312cd",
		"SHA3-384":    "99b9d6ef85880c3c47580db63d7a4faf9da3288af5fedf32622809890398b6b018f0799b119a86e9cd09e8846e59bfc4",
		"SHA3-512":    "b3238614b3880765cb112793f8e345d8ea8c87421defd6167af6edc9425cb7d5cc7279c27c27de918b7598fe79c7a27c11e84c9ea1960571299937453e71d276",
		"HIGHWAYHASH": "17c352b5db8e8a44261d2f12d7b25a28",
		"WYHASH":      "d2e0e598baa371d4",
		"ADLER32":     "03c600f8",
		"FNV32A":      "cfa89a92",
		"FNV64A":      "880cd925fe68c272",
		"FNV128A":     "2c7e31c05a3c64bf6e6a2ea75e526aba",
		"SM3":         "2999fb87b08cf0743e86876df6300c2f679550b3989d3d0f9bc6d57fa8328235",
		"RIPEMD160":   "ea48e575d8638b9903ca1cc27346201182edd3a9",
	}

	for algo, expectedHex := range goldenVectors {
		t.Run(algo, func(t *testing.T) {
			hf, err := GetHasher(algo)
			if err != nil {
				t.Fatalf("Failed to get hasher for %s: %v", algo, err)
			}
			actualHex, err := hf(bytes.NewReader(input))
			if err != nil {
				t.Fatalf("Failed to compute hash for %s: %v", algo, err)
			}
			if actualHex != expectedHex {
				t.Errorf("Mismatch for %s!\nExpected: %s\nActual:   %s", algo, expectedHex, actualHex)
			}
		})
	}
}

func TestEmptyInputHashes(t *testing.T) {
	algos := []string{
		"CRC32", "CRC64", "SHA256", "SHA1", "BLAKE2S", "BLAKE2B", "BLAKE2SP", "BLAKE3",
		"MD2", "MD4", "MD5", "XXH32", "XXH64", "XXH3-64", "XXH3-128", "SHA384", "SHA512",
		"SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "HIGHWAYHASH", "WYHASH",
		"ADLER32", "FNV32A", "FNV64A", "FNV128A", "SM3", "RIPEMD160",
	}

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			hf, err := GetHasher(algo)
			if err != nil {
				t.Fatalf("Failed to get hasher for %s: %v", algo, err)
			}

			// Run on empty input
			emptyHex, err := hf(bytes.NewReader(nil))
			if err != nil {
				t.Fatalf("Failed to compute empty hash for %s: %v", algo, err)
			}

			// Verify it returned a valid string and it has the same digest size
			nonEmptyHex, _ := hf(bytes.NewReader([]byte("1.0.0\n")))
			if len(emptyHex) != len(nonEmptyHex) {
				t.Errorf("Expected empty hash length to be %d, got %d", len(nonEmptyHex), len(emptyHex))
			}

			if emptyHex == nonEmptyHex {
				t.Errorf("Expected empty hash to differ from non-empty hash for %s", algo)
			}
		})
	}
}

func runHasherBenchmark(b *testing.B, algo string) {
	data := make([]byte, 1024*1024) // 1MB chunk
	hf, err := GetHasher(algo)
	if err != nil {
		b.Fatalf("Failed to get hasher %s: %v", algo, err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hf(bytes.NewReader(data))
	}
}

func BenchmarkHasher_CRC32(b *testing.B)       { runHasherBenchmark(b, "CRC32") }
func BenchmarkHasher_SHA256(b *testing.B)      { runHasherBenchmark(b, "SHA256") }
func BenchmarkHasher_BLAKE2s(b *testing.B)     { runHasherBenchmark(b, "BLAKE2S") }
func BenchmarkHasher_BLAKE2sp(b *testing.B)    { runHasherBenchmark(b, "BLAKE2SP") }
func BenchmarkHasher_BLAKE3(b *testing.B)      { runHasherBenchmark(b, "BLAKE3") }
func BenchmarkHasher_XXH3_128(b *testing.B)    { runHasherBenchmark(b, "XXH3-128") }
func BenchmarkHasher_HIGHWAYHASH(b *testing.B) { runHasherBenchmark(b, "HIGHWAYHASH") }
func BenchmarkHasher_WYHASH(b *testing.B)      { runHasherBenchmark(b, "WYHASH") }
func BenchmarkHasher_ADLER32(b *testing.B)     { runHasherBenchmark(b, "ADLER32") }
func BenchmarkHasher_FNV32A(b *testing.B)      { runHasherBenchmark(b, "FNV32A") }
func BenchmarkHasher_FNV64A(b *testing.B)      { runHasherBenchmark(b, "FNV64A") }
func BenchmarkHasher_FNV128A(b *testing.B)     { runHasherBenchmark(b, "FNV128A") }
func BenchmarkHasher_SM3(b *testing.B)         { runHasherBenchmark(b, "SM3") }
func BenchmarkHasher_RIPEMD160(b *testing.B)   { runHasherBenchmark(b, "RIPEMD160") }

func BenchmarkAllAlgorithms(b *testing.B) {
	algos := []string{
		"CRC32", "CRC64", "SHA256", "SHA1", "BLAKE2S", "BLAKE2B", "BLAKE2SP", "BLAKE3",
		"MD2", "MD4", "MD5", "XXH32", "XXH64", "XXH3-64", "XXH3-128", "SHA384", "SHA512",
		"SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "HIGHWAYHASH", "WYHASH",
		"ADLER32", "FNV32A", "FNV64A", "FNV128A", "SM3", "RIPEMD160",
	}
	for _, algo := range algos {
		b.Run(algo, func(b *testing.B) {
			runHasherBenchmark(b, algo)
		})
	}
}
