// Package blake2sp implements the 8-way parallel BLAKE2sp cryptographic hashing algorithm.
//
// OBJECTIVES:
// 1. Manage state context mapping for 8 parallel BLAKE2s instances.
// 2. Interleave incoming data streams in 64-byte strides across instances.
// 3. Combine individual leaf states into a final single root hash securely.
// 4. Avoid CGO overhead by using unsafe reflection layout mapping of the standard x/crypto/blake2s structure.
//
// DATA FLOW:
//   - Incoming data stream is sliced into 64-byte chunks.
//   - Each chunk is written to one of the 8 leaf instances in round-robin sequence (chunk i writes to leaf i % 8).
//     This simulates parallel tree hashing sequentially.
//   - For finalization, the root hash is computed by hashing the concatenated outputs of the 8 leaf digests.
package blake2sp

import (
	"encoding/binary"
	"hash"
	"unsafe"

	"golang.org/x/crypto/blake2s"
)

const (
	MaxLeaves = 8
	ChunkSize = 64
)

// Matches the internal memory layout of golang.org/x/crypto/blake2s.digest
type blake2sDigest struct {
	h      [8]uint32
	c      [2]uint32
	size   int
	block  [64]byte
	offset int
	key    [64]byte
	keyLen int
}

func init() {
	// Validate that our blake2sDigest layout matches the compiler size and alignment expectations
	// on both 32-bit and 64-bit architectures.
	var d blake2sDigest
	expectedSize := uintptr(168) + 3*unsafe.Sizeof(int(0))
	if unsafe.Sizeof(d) != expectedSize {
		panic("blake2sp: internal digest structure size mismatch")
	}
}

var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

type interfaceVal struct {
	typ unsafe.Pointer
	val unsafe.Pointer
}

// Blake2sp implements the 8-way parallel tree hashing over blake2s
type Blake2sp struct {
	leaves    [MaxLeaves]hash.Hash
	buffer    []byte
	byteCount uint64
}

func NewBlake2sp() (*Blake2sp, error) {
	b := &Blake2sp{
		buffer: make([]byte, 0, MaxLeaves*ChunkSize),
	}

	for i := 0; i < MaxLeaves; i++ {
		h, err := blake2s.New256(nil)
		if err != nil {
			return nil, err
		}

		// Override the internal state with tree parameters (NodeOffset = i)
		// #nosec G103 -- unsafe casting is required to access/modify unexported blake2s tree parameters without CGO
		d := (*blake2sDigest)((*interfaceVal)(unsafe.Pointer(&h)).val)
		var p [32]byte
		p[0] = 32      // digest size
		p[2] = 8       // fanout
		p[3] = 2       // max depth
		p[8] = byte(i) // node offset
		p[15] = 32     // inner length

		for j := 0; j < 8; j++ {
			d.h[j] = iv[j] ^ binary.LittleEndian.Uint32(p[j*4:(j+1)*4])
		}

		b.leaves[i] = h
	}

	return b, nil
}

func cloneBlake2s(h hash.Hash) hash.Hash {
	// #nosec G103 -- unsafe casting is required to deep-copy unexported blake2s digest structures
	originalVal := (*interfaceVal)(unsafe.Pointer(&h)).val

	// Create a new target hash
	cloneHash, _ := blake2s.New256(nil)
	// #nosec G103 -- unsafe casting is required to access memory location of the cloned digest
	cloneVal := (*interfaceVal)(unsafe.Pointer(&cloneHash)).val

	// Copy the contents of the digest struct (deep copy of value types)
	*(*blake2sDigest)(cloneVal) = *(*blake2sDigest)(originalVal)

	return cloneHash
}

func (b *Blake2sp) Write(p []byte) (n int, err error) {
	n = len(p)
	b.buffer = append(b.buffer, p...)

	// Process chunks in multiples of 512 bytes (8 leaves * 64 bytes)
	stride := MaxLeaves * ChunkSize
	processedBytes := (len(b.buffer) / stride) * stride

	if processedBytes > 0 {
		// Interleave data 64 bytes at a time across the 8 leaves
		for offset := 0; offset < processedBytes; offset += stride {
			for i := 0; i < MaxLeaves; i++ {
				leafOffset := offset + i*ChunkSize
				_, _ = b.leaves[i].Write(b.buffer[leafOffset : leafOffset+ChunkSize])
			}
		}

		// Shift remaining data to the beginning of the slice to reuse allocated memory
		leftover := len(b.buffer) - processedBytes
		if leftover > 0 {
			copy(b.buffer[0:], b.buffer[processedBytes:])
		}
		b.buffer = b.buffer[:leftover]
		b.byteCount += uint64(processedBytes)
	}
	return n, nil
}

func (b *Blake2sp) Sum(dst []byte) []byte {
	var leafDigests []byte
	var leavesCopy [MaxLeaves]hash.Hash

	for i := 0; i < MaxLeaves; i++ {
		leavesCopy[i] = cloneBlake2s(b.leaves[i])
	}

	// Handle trailing buffer data
	bufferCopy := make([]byte, len(b.buffer))
	copy(bufferCopy, b.buffer)

	if len(bufferCopy) > 0 {
		for i := 0; len(bufferCopy) > 0; i = (i + 1) % MaxLeaves {
			take := ChunkSize
			if len(bufferCopy) < ChunkSize {
				take = len(bufferCopy)
			}
			_, _ = leavesCopy[i].Write(bufferCopy[:take])
			bufferCopy = bufferCopy[take:]
		}
	}

	// Concatenate all 8 leaf hashes (8 * 32 bytes = 256 bytes)
	for i := 0; i < MaxLeaves; i++ {
		leafDigests = leavesCopy[i].Sum(leafDigests)
	}

	// Initialize the Root Node configuration using New256
	root, _ := blake2s.New256(nil)

	// Override the internal state of the root hasher to set NodeDepth = 1
	// #nosec G103 -- unsafe casting is required to access/modify unexported blake2s root node parameter
	d := (*blake2sDigest)((*interfaceVal)(unsafe.Pointer(&root)).val)
	var p [32]byte
	p[0] = 32  // digest size
	p[2] = 8   // fanout
	p[3] = 2   // max depth
	p[14] = 1  // node depth = 1 (indicating root combining leaves)
	p[15] = 32 // inner length

	for j := 0; j < 8; j++ {
		d.h[j] = iv[j] ^ binary.LittleEndian.Uint32(p[j*4:(j+1)*4])
	}

	_, _ = root.Write(leafDigests)

	return root.Sum(dst)
}

func (b *Blake2sp) Reset() {
	b.buffer = b.buffer[:0]
	b.byteCount = 0
	for i := 0; i < MaxLeaves; i++ {
		b.leaves[i].Reset()

		// Re-apply the tree parameter overrides on the leaf
		// #nosec G103 -- unsafe casting is required to access/modify leaf state overrides on Reset
		d := (*blake2sDigest)((*interfaceVal)(unsafe.Pointer(&b.leaves[i])).val)
		var p [32]byte
		p[0] = 32      // digest size
		p[2] = 8       // fanout
		p[3] = 2       // max depth
		p[8] = byte(i) // node offset
		p[15] = 32     // inner length

		for j := 0; j < 8; j++ {
			d.h[j] = iv[j] ^ binary.LittleEndian.Uint32(p[j*4:(j+1)*4])
		}
	}
}

func (b *Blake2sp) Size() int {
	return 32
}

func (b *Blake2sp) BlockSize() int {
	return MaxLeaves * ChunkSize
}
