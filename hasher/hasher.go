// Package hasher provides a unified interface for various hashing algorithms.
//
// OBJECTIVES:
//  1. Abstract hashing computation behind a unified API contract (`hasher.Func`).
//  2. Support standard cryptographic (MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2, BLAKE3, SM3, RIPEMD160)
//     and high-performance non-cryptographic (CRC, xxHash, HighwayHash, Wyhash, Adler32, FNV) algorithms.
//  3. Optimize resource consumption by utilizing a global byte buffer pool (`sync.Pool`)
//     and `io.CopyBuffer` to eliminate transient buffer allocations.
//
// DATA FLOW:
//   - Caller requests a hash function by name (via GetHasher).
//   - GetHasher returns a Func closure that accepts an io.Reader.
//   - During execution, the Func acquires a 128KB buffer from the pool, reads chunks from the
//     reader, updates the hash state, returns the buffer to the pool, and returns the computed hex string.
package hasher

import (
	"crypto/md5"  // #nosec G501 -- MD5 is supported as a legacy/non-cryptographic hash option, not for security-critical contexts.
	"crypto/sha1" // #nosec G505 -- SHA1 is supported as a legacy/non-cryptographic hash option, not for security-critical contexts.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"strings"
	"sync"

	"criticalsys.net/hashcalcmt/codec/blake2sp"
	"github.com/cespare/xxhash/v2"
	"github.com/htruong/go-md2"
	"github.com/minio/highwayhash"
	"github.com/orisano/wyhash"
	"github.com/pierrec/xxHash/xxHash32"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	/* #nosec G506 */ "golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is supported as a legacy/non-cryptographic hash option, not for security-critical contexts.
	/* #nosec G507 */ "golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD160 is supported for legacy/ledger compatibility, not for security-critical contexts.
	"golang.org/x/crypto/sha3"
)

// Hash types constants define the supported hashing algorithms.
const (
	// HashCRC32 is the 32-bit Cyclic Redundancy Check (IEEE).
	HashCRC32 = "CRC32"
	// HashCRC64 is the 64-bit Cyclic Redundancy Check (ISO).
	HashCRC64 = "CRC64"
	// HashSHA256 is the standard SHA-256 algorithm (256-bit).
	HashSHA256 = "SHA256"
	// HashSHA1 is the legacy SHA1 algorithm (160-bit).
	HashSHA1 = "SHA1"
	// HashBLAKE2s is the standard BLAKE2s algorithm (256-bit).
	HashBLAKE2s = "BLAKE2S"
	// HashBLAKE2b is the standard BLAKE2b algorithm (512-bit).
	HashBLAKE2b = "BLAKE2B"
	// HashBLAKE2sp is the 8-way parallelized BLAKE2s algorithm (256-bit).
	HashBLAKE2sp = "BLAKE2SP"
	// HashBLAKE3 is the Blake3 cryptographic hash, designed for extreme speed and security.
	HashBLAKE3 = "BLAKE3"
	// HashMD2 is the legacy MD2 algorithm (128-bit).
	HashMD2 = "MD2"
	// HashMD4 is the legacy MD4 algorithm (128-bit).
	HashMD4 = "MD4"
	// HashMD5 is the legacy MD5 algorithm (128-bit).
	HashMD5 = "MD5"
	// HashXXH32 is the 32-bit xxHash algorithm.
	HashXXH32 = "XXH32"
	// HashXXH64 is the 64-bit xxHash algorithm.
	HashXXH64 = "XXH64"
	// HashXXH3_64 is the 64-bit version of XXH3.
	HashXXH3_64 = "XXH3-64"
	// HashXXH3_128 is the 128-bit version of XXH3, optimized for high performance.
	HashXXH3_128 = "XXH3-128"
	// HashSHA384 is the standard SHA-384 algorithm (384-bit).
	HashSHA384 = "SHA384"
	// HashSHA512 is the standard SHA-512 algorithm (512-bit).
	HashSHA512 = "SHA512"
	// HashSHA512_224 is the truncated SHA-512/224 algorithm.
	HashSHA512_224 = "SHA512-224"
	// HashSHA512_256 is the truncated SHA-512/256 algorithm.
	HashSHA512_256 = "SHA512-256"
	// HashSHA3_224 is the SHA3-224 standard algorithm.
	HashSHA3_224 = "SHA3-224"
	// HashSHA3_256 is the SHA3-256 standard algorithm.
	HashSHA3_256 = "SHA3-256"
	// HashSHA3_384 is the SHA3-384 standard algorithm.
	HashSHA3_384 = "SHA3-384"
	// HashSHA3_512 is the SHA3-512 standard algorithm.
	HashSHA3_512 = "SHA3-512"
	// HashHighway is HighwayHash-128, a robust and fast PRF.
	HashHighway = "HIGHWAYHASH"
	// HashWyhash is the 64-bit Wyhash algorithm, known for its extreme speed.
	HashWyhash = "WYHASH"
	// HashAdler32 is the Adler-32 checksum algorithm (32-bit).
	HashAdler32 = "ADLER32"
	// HashFNV32A is the 32-bit FNV-1a non-cryptographic hash.
	HashFNV32A = "FNV32A"
	// HashFNV64A is the 64-bit FNV-1a non-cryptographic hash.
	HashFNV64A = "FNV64A"
	// HashFNV128A is the 128-bit FNV-1a non-cryptographic hash.
	HashFNV128A = "FNV128A"
	// HashSM3 is the SM3 cryptographic hash standard (256-bit).
	HashSM3 = "SM3"
	// HashRIPEMD160 is the RIPEMD-160 cryptographic hash (160-bit).
	HashRIPEMD160 = "RIPEMD160"
)

// Func is a function type that takes a reader and returns a hash string or an error.
type Func func(io.Reader) (string, error)

// GetHasher returns the appropriate hash function based on the requested hash type.
// It returns a Func that can process an io.Reader and an error if the type is unsupported.
// Hash type comparison is case-insensitive.
func GetHasher(hashType string) (Func, error) {
	switch strings.ToUpper(hashType) {
	case HashMD2:
		return newHashStreamFunc(md2.New), nil
	case HashMD4:
		// #nosec G401 -- MD4 is supported as a legacy hash option for integrity verification, not for security-critical contexts.
		return newHashStreamFunc(md4.New), nil
	case HashMD5:
		// #nosec G401 -- MD5 is supported as a legacy hash option for file integrity verification, not for security-critical contexts.
		return newHashStreamFunc(md5.New), nil
	case HashSHA1:
		// #nosec G401 -- SHA1 is supported as a legacy hash option for file integrity verification, not for security-critical contexts.
		return newHashStreamFunc(sha1.New), nil
	case HashSHA256:
		return newHashStreamFunc(sha256.New), nil
	case HashSHA384:
		return newHashStreamFunc(sha512.New384), nil
	case HashSHA512:
		return newHashStreamFunc(sha512.New), nil
	case HashSHA512_224:
		return newHashStreamFunc(sha512.New512_224), nil
	case HashSHA512_256:
		return newHashStreamFunc(sha512.New512_256), nil
	case HashSHA3_224:
		return newHashStreamFunc(sha3.New224), nil
	case HashSHA3_256:
		return newHashStreamFunc(sha3.New256), nil
	case HashSHA3_384:
		return newHashStreamFunc(sha3.New384), nil
	case HashSHA3_512:
		return newHashStreamFunc(sha3.New512), nil
	case HashBLAKE2s:
		return func(r io.Reader) (string, error) {
			h, err := blake2s.New256(nil)
			if err != nil {
				return "", err
			}
			bufPtr := bufPool.Get().(*[]byte)
			defer bufPool.Put(bufPtr)
			if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
				return "", err
			}
			return hex.EncodeToString(h.Sum(nil)), nil
		}, nil
	case HashBLAKE2b:
		return func(r io.Reader) (string, error) {
			h, err := blake2b.New512(nil)
			if err != nil {
				return "", err
			}
			bufPtr := bufPool.Get().(*[]byte)
			defer bufPool.Put(bufPtr)
			if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
				return "", err
			}
			return hex.EncodeToString(h.Sum(nil)), nil
		}, nil
	case HashBLAKE2sp:
		return func(r io.Reader) (string, error) {
			h, err := blake2sp.NewBlake2sp()
			if err != nil {
				return "", err
			}
			bufPtr := bufPool.Get().(*[]byte)
			defer bufPool.Put(bufPtr)
			if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
				return "", err
			}
			return hex.EncodeToString(h.Sum(nil)), nil
		}, nil
	case HashBLAKE3:
		// Uses zeebo/blake3 for high-performance cryptographic hashing.
		return newHashStreamFunc(func() hash.Hash { return blake3.New() }), nil
	case HashCRC32:
		return newHashStreamFunc(func() hash.Hash { return crc32.NewIEEE() }), nil
	case HashCRC64:
		return newHashStreamFunc(func() hash.Hash { return crc64.New(crc64.MakeTable(crc64.ISO)) }), nil
	case HashXXH32:
		return newHashStreamFunc(func() hash.Hash { return xxHash32.New(0) }), nil
	case HashXXH64:
		return newHashStreamFunc(func() hash.Hash { return xxhash.New() }), nil
	case HashXXH3_64:
		return newHashStreamFunc(func() hash.Hash { return xxh3.New() }), nil
	case HashXXH3_128:
		// Uses zeebo/xxh3 implementation for 128-bit hashes.
		return newHashStreamFunc(func() hash.Hash { return xxh3.New128() }), nil
	case HashHighway:
		// Uses minio/highwayhash with a standardized fixed key.
		return hashHighwayStream, nil
	case HashWyhash:
		// Uses orisano/wyhash with a standardized fixed seed.
		return hashWyhashStream, nil
	case HashAdler32:
		return newHashStreamFunc(func() hash.Hash { return adler32.New() }), nil
	case HashFNV32A:
		return newHashStreamFunc(func() hash.Hash { return fnv.New32a() }), nil
	case HashFNV64A:
		return newHashStreamFunc(func() hash.Hash { return fnv.New64a() }), nil
	case HashFNV128A:
		return newHashStreamFunc(func() hash.Hash { return fnv.New128a() }), nil
	case HashSM3:
		return newHashStreamFunc(func() hash.Hash { return sm3.New() }), nil
	case HashRIPEMD160:
		// #nosec G406 -- RIPEMD-160 is supported for legacy/ledger verification, not for security-critical contexts.
		return newHashStreamFunc(func() hash.Hash { return ripemd160.New() }), nil
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", hashType)
	}
}

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 128*1024) // 128KB buffer
		return &buf
	},
}

// newHashStreamFunc creates a Func from a function that returns a new hash.Hash.
func newHashStreamFunc(newHasher func() hash.Hash) Func {
	return func(r io.Reader) (string, error) {
		h := newHasher()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
}

// hashHighwayStream computes HighwayHash using a fixed all-zeros 32-byte key.
func hashHighwayStream(r io.Reader) (string, error) {
	key := make([]byte, 32) // Fixed all-zeros key
	h, err := highwayhash.New128(key)
	if err != nil {
		return "", err
	}
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashWyhashStream computes Wyhash using a fixed seed of 0.
func hashWyhashStream(r io.Reader) (string, error) {
	h := wyhash.New(0)
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	if _, err := io.CopyBuffer(h, r, *bufPtr); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
