"""Append-only Merkle tree with inclusion and consistency proofs.

WHY THIS EXISTS. The evidence log was originally a hash chain:
L_t = H(L_{t-1} || H(snapshot_t) || verdict_t). A chain is enough to detect
alteration and gaps, but only if you replay it. To convince yourself that one
particular record is in a history of n records, you have to fetch and rehash
all n. For an auditor who cares about a single action out of a billion, that is
the whole log.

A Merkle tree gives the same guarantees with proofs logarithmic in n. RFC 6962
(Certificate Transparency) already specifies exactly this structure, and the
specification cites CT throughout, so this is adoption rather than invention.

Two proof types, and they answer different questions:

  INCLUSION    "record i, which I have, is in the tree whose root you
               published." Size ceil(log2 n) hashes.

  CONSISTENCY  "the tree of size n you show me today is an append-only
               extension of the tree of size m you published before -- nothing
               was rewritten or removed." Also O(log n).

Consistency is the one that matters for the truncation and equivocation
attacks. Comparing bare anchor roots tells a verifier that two roots differ; a
consistency proof tells it which of the two histories is not an extension of
the other, without downloading either.

Hashing follows RFC 6962 section 2:
    MTH({})       = SHA-256()
    leaf hash     = SHA-256(0x00 || record)
    interior node = SHA-256(0x01 || left || right)
The domain-separating prefixes are what stop a leaf being passed off as an
interior node (the second-preimage attack on naive Merkle trees).
"""

from __future__ import annotations

import hashlib

__all__ = [
    "leaf_hash",
    "node_hash",
    "EMPTY_ROOT",
    "MerkleTree",
    "verify_inclusion",
    "verify_consistency",
    "reference_root",
]


def leaf_hash(record: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + record).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


def _lpo2(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << (n - 1).bit_length() - 1 if n & (n - 1) else n >> 1


def reference_root(leaves: list[bytes]) -> bytes:
    """The recursive definition, straight from the RFC. Slow and obviously
    correct -- the incremental implementation is checked against it."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _lpo2(n)
    return node_hash(reference_root(leaves[:k]), reference_root(leaves[k:]))


class MerkleTree:
    """Append-only tree.

    Appending is O(log n): we keep the roots of the perfect subtrees that
    tile the current leaf sequence -- the "mountain range" -- and merge
    whenever two of equal height meet. The tree root is the right-to-left
    fold of that range, so a new root costs a handful of hashes rather than a
    pass over the log.
    """

    def __init__(self):
        self.leaves: list[bytes] = []
        self._stack: list[tuple[int, bytes]] = []  # (height, hash), heights descend
        # Subtree roots are immutable once their range is full, because the log
        # is append-only. Caching them makes proof generation logarithmic
        # instead of linear -- otherwise the operator, not the auditor, becomes
        # the bottleneck.
        self._cache: dict[tuple[int, int], bytes] = {}

    # ------------------------------------------------------------ building
    def append(self, record: bytes) -> int:
        """Add a record; return its leaf index."""
        h = leaf_hash(record)
        self.leaves.append(h)
        self._stack.append((0, h))
        while len(self._stack) >= 2 and self._stack[-1][0] == self._stack[-2][0]:
            (lvl, right), (_, left) = self._stack.pop(), self._stack.pop()
            self._stack.append((lvl + 1, node_hash(left, right)))
        return len(self.leaves) - 1

    @property
    def size(self) -> int:
        return len(self.leaves)

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        r = self._stack[-1][1]
        for _, h in reversed(self._stack[:-1]):
            r = node_hash(h, r)
        return r

    # -------------------------------------------------------------- proofs
    def _range_root(self, lo: int, hi: int) -> bytes:
        """MTH over leaves[lo:hi], memoized."""
        key = (lo, hi)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        n = hi - lo
        if n == 1:
            r = self.leaves[lo]
        else:
            k = _lpo2(n)
            r = node_hash(self._range_root(lo, lo + k), self._range_root(lo + k, hi))
        self._cache[key] = r
        return r

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """PATH(index, D[size]) of RFC 6962. `size` lets an auditor ask for a
        proof against a root that was published earlier than now."""
        size = self.size if size is None else size
        if not 0 <= index < size <= self.size:
            raise IndexError(f"index {index} not in tree of size {size}")
        return self._path(index, 0, size)

    def _path(self, m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n == 1:
            return []
        k = _lpo2(n)
        if m < k:
            return self._path(m, lo, lo + k) + [self._range_root(lo + k, hi)]
        return self._path(m - k, lo + k, hi) + [self._range_root(lo, lo + k)]

    def consistency_proof(self, m: int, n: int | None = None) -> list[bytes]:
        """PROOF(m, D[n]): evidence that the size-n tree extends the size-m one."""
        n = self.size if n is None else n
        if not 0 < m <= n <= self.size:
            raise IndexError(f"cannot prove consistency of {m} within {n}")
        if m == n:
            return []
        return self._subproof(m, 0, n, True)

    def _subproof(self, m: int, lo: int, hi: int, b: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            return [] if b else [self._range_root(lo, hi)]
        k = _lpo2(n)
        if m <= k:
            return self._subproof(m, lo, lo + k, b) + [self._range_root(lo + k, hi)]
        return self._subproof(m - k, lo + k, hi, False) + [self._range_root(lo, lo + k)]

    def root_at(self, size: int) -> bytes:
        if size == 0:
            return EMPTY_ROOT
        return self._range_root(0, size)


# ------------------------------------------------------------- verification
#
# Both verifiers below run on the auditor's side and touch only the proof --
# never the log. That is the entire point: the work is O(log n) in the size of
# the history, and the log operator cannot influence it beyond supplying the
# proof, which either reconstructs the published root or does not.


def verify_inclusion(
    index: int, size: int, leaf: bytes, proof: list[bytes], root: bytes
) -> bool:
    """Does `leaf` sit at `index` of the tree of `size` with head `root`?"""
    if index >= size or size == 0:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    m: int, n: int, root_m: bytes, root_n: bytes, proof: list[bytes]
) -> bool:
    """Is the size-n tree an append-only extension of the size-m tree?

    A `False` here is the signal that history was rewritten: the operator is
    presenting a tree that is not a superset of one it already committed to.
    """
    if m > n or m == 0:
        return False
    if m == n:
        return not proof and root_m == root_n
    path = list(proof)
    if not m & (m - 1):  # m is a power of two: root_m is
        path = [root_m] + path  # an implicit node, restore it
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root_m and sr == root_n
