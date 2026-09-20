package aee

import "crypto/sha256"

// RFC 6962 Merkle tree over observation-record PAE bytes (spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5):
// leaf = H(0x00 || PAE bytes), node = H(0x01 || left || right), the tree
// built by the RFC 6962 recursive split — never by duplicating a trailing
// node to pad the leaf count. A single-record tree's root is its leaf hash;
// an empty array has no root.
//
// Duplicate identity: this implementation rejects duplicate LEAF HASHES,
// the safe superset of byte-identical-entry rejection (a record's canonical
// identity is its leaf hash, spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5). Whether the two readings can
// ever diverge is an open spec question tracked in the conformance suite
// README; the superset reading rejects in both cases and therefore admits
// no false accepts.

const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// LeafHash computes H(0x00 || pae).
func LeafHash(pae []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(pae)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot computes the RFC 6962 root over leaves in order. It must not
// be called with zero leaves (an empty record array carries no root).
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestPowerOfTwoBelow(len(leaves))
	left := MerkleRoot(leaves[:k])
	right := MerkleRoot(leaves[k:])
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// largestPowerOfTwoBelow returns the largest power of two strictly less
// than n (n >= 2), per the RFC 6962 recursive split.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}
