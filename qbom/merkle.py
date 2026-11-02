"""
Selective-disclosure layer: a *sorted* Merkle tree over salted finding
commitments.

Why sorted: an ordinary Merkle tree only lets you prove "this leaf is in the
set" (inclusion). Compliance questions are usually the opposite shape --
"prove you have NO SSLv2 endpoints" is a claim about something absent. If
leaves are kept in sorted order, absence of a target leaf L is provable by
exhibiting two *adjacent* leaves lo < L < hi (or a boundary case) together
with their inclusion proofs: since the tree is sorted, no leaf can exist
between lo and hi, so L cannot be present. This is the standard sorted-leaf
non-membership construction used in certificate-transparency-style logs.

Each leaf commits to one finding without revealing it:
    leaf = SHA3-256(catalog_id || location_id || salt)
The salt is a per-finding secret the scanning organisation keeps locally.
Publishing only the Merkle root discloses nothing; publishing one leaf's
salt + inclusion path discloses exactly that one finding and nothing about
its siblings -- this is the "prove one fact without revealing the rest of
the infrastructure" mechanism the framework is built around.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


def leaf_hash(catalog_id: str, location_id: str, salt: bytes) -> bytes:
    return hashlib.sha3_256(catalog_id.encode() + b"|" + location_id.encode() + b"|" + salt).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def _leaf_wrap(h: bytes) -> bytes:
    return hashlib.sha3_256(b"\x00" + h).digest()  # domain-separate leaves from internal nodes


@dataclass
class MerkleProof:
    leaf_index: int
    siblings: list  # list[(bytes, bool)] bool = True if sibling is on the right
    leaf_raw: bytes


@dataclass
class MerkleTree:
    sorted_leaves_raw: list  # sorted list of raw leaf hashes (pre-wrap), for non-membership search
    levels: list  # list[list[bytes]], levels[0] = wrapped leaves

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def root_hex(self) -> str:
        return self.root.hex()

    def prove_inclusion(self, raw_leaf: bytes) -> MerkleProof:
        idx = self.sorted_leaves_raw.index(raw_leaf)
        siblings = []
        level = self.levels[0]
        pos = idx
        for lvl in range(len(self.levels) - 1):
            level = self.levels[lvl]
            is_right = pos % 2 == 1
            sib_pos = pos - 1 if is_right else pos + 1
            if sib_pos < len(level):
                siblings.append((level[sib_pos], not is_right))  # (hash, sibling_is_on_right)
            pos //= 2
        return MerkleProof(idx, siblings, raw_leaf)

    def prove_non_membership(self, target_raw: bytes):
        """Returns (kind, payload). kind='absent_between' -> (lo_proof, hi_proof);
        kind='absent_below' -> hi_proof only; kind='absent_above' -> lo_proof only;
        raises if the target is actually present (can't prove a false statement)."""
        leaves = self.sorted_leaves_raw
        if target_raw in leaves:
            raise ValueError("target is present; cannot construct a non-membership proof")
        import bisect
        pos = bisect.bisect_left(leaves, target_raw)
        if pos == 0:
            return "absent_below", self.prove_inclusion(leaves[0])
        if pos == len(leaves):
            return "absent_above", self.prove_inclusion(leaves[-1])
        return "absent_between", (self.prove_inclusion(leaves[pos - 1]), self.prove_inclusion(leaves[pos]))


def build_tree(raw_leaves: list) -> MerkleTree:
    sorted_leaves = sorted(set(raw_leaves))
    if not sorted_leaves:
        sorted_leaves = [hashlib.sha3_256(b"EMPTY").digest()]
    level0 = [_leaf_wrap(x) for x in sorted_leaves]
    levels = [level0]
    cur = level0
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(_node_hash(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])  # odd one out promotes unchanged
        levels.append(nxt)
        cur = nxt
    return MerkleTree(sorted_leaves, levels)


def verify_inclusion(root: bytes, proof: MerkleProof) -> bool:
    h = _leaf_wrap(proof.leaf_raw)
    for sib, sib_is_right in proof.siblings:
        h = _node_hash(h, sib) if sib_is_right else _node_hash(sib, h)
    return h == root


def verify_non_membership(root: bytes, target_raw: bytes, kind: str, payload, total_leaves: int) -> bool:
    """`total_leaves` must be published alongside the root as public tree
    metadata (it reveals only a count of findings, not their content) so
    the endpoint cases can be pinned to the true first/last index rather
    than an index the prover picked."""
    if kind == "absent_between":
        lo_proof, hi_proof = payload
        if not (verify_inclusion(root, lo_proof) and verify_inclusion(root, hi_proof)):
            return False
        if hi_proof.leaf_index != lo_proof.leaf_index + 1:
            return False
        return lo_proof.leaf_raw < target_raw < hi_proof.leaf_raw
    if kind == "absent_below":
        hi_proof = payload
        return verify_inclusion(root, hi_proof) and hi_proof.leaf_index == 0 and target_raw < hi_proof.leaf_raw
    if kind == "absent_above":
        lo_proof = payload
        return (verify_inclusion(root, lo_proof) and lo_proof.leaf_index == total_leaves - 1
                and target_raw > lo_proof.leaf_raw)
    return False
