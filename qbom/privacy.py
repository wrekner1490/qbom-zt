"""
Zero-trust disclosure orchestration.

This is the piece that answers "how do we let a central authority get useful
signal without giving it (or a compromised scanning tool) our crypto
inventory": the scanner and the QBOM model above run entirely locally, on
the org's own infrastructure, with no network access required. What crosses
the trust boundary is an Attestation: a small bundle of public commitments,
a Merkle root, and zero-knowledge proofs -- never the findings themselves.

Two disclosure modes are supported, matching two different verifier needs:

  * Exact-count commitments per catalog_id, with optional threshold or
    zero-count proofs ("prove RSA-SUB2048 count < 5", "prove count == 0").
    These support homomorphic aggregation: a parent org can sum the
    per-catalog-id commitments from N subsidiaries and verify the *sector*
    total opens correctly, without any subsidiary's count being visible to
    the parent or to other subsidiaries.

  * A sorted Merkle tree over per-finding commitments, for selective
    disclosure of individual findings ("here is proof of exactly this one
    finding, and only this one"). Non-membership proofs over this tree are
    only meaningful for a finding whose salt is already known to the
    verifier -- i.e. to confirm remediation of a specific, previously
    disclosed finding ("the item you flagged last quarter no longer
    appears in this scan"). They cannot prove "no finding of this algorithm
    exists anywhere" in general, because salts are private per finding and
    a nonexistent finding has no salt to reconstruct a comparable leaf from;
    that broader claim is what prove_zero (Pedersen count commitment) is for.

The org keeps the QBOM, the finding salts, and all blinding factors locally.
Only Attestation.to_public_dict() ever leaves the machine.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import merkle, zk
from .model import QBOM


@dataclass
class CatalogCommitment:
    catalog_id: str
    commitment: zk.Commitment
    blinding: int   # LOCAL ONLY -- never serialised to the public attestation


@dataclass
class Attestation:
    org: str
    catalog_hash: str
    merkle_root: bytes
    leaf_count: int
    catalog_commitments: dict            # catalog_id -> CatalogCommitment (local; blinding kept)
    published_zero_proofs: dict = field(default_factory=dict)          # catalog_id -> PublicValueProof
    published_threshold_proofs: dict = field(default_factory=dict)     # catalog_id -> ThresholdProof
    published_finding_disclosures: list = field(default_factory=list)  # list[(finding_dict, salt, MerkleProof)]
    published_remediation_proofs: list = field(default_factory=list)   # list[(label, kind, payload)]

    def to_public_dict(self) -> dict:
        """The ONLY thing that should ever cross the trust boundary."""
        return {
            "org": self.org,
            "catalog_hash": self.catalog_hash,
            "merkle_root": self.merkle_root.hex(),
            "leaf_count": self.leaf_count,
            "catalog_commitments": {cid: cc.commitment.to_hex() for cid, cc in self.catalog_commitments.items()},
            "zero_proofs": {cid: p.to_dict() for cid, p in self.published_zero_proofs.items()},
            "threshold_proofs": {cid: p.to_dict() for cid, p in self.published_threshold_proofs.items()},
            "finding_disclosures": [
                {"finding": fd, "salt": salt.hex(), "leaf_index": mp.leaf_index,
                 "siblings": [(s.hex(), r) for s, r in mp.siblings]}
                for fd, salt, mp in self.published_finding_disclosures
            ],
            "remediation_proofs": [
                {"label": label, "kind": kind, "payload": _serialize_nm(kind, payload)}
                for label, kind, payload in self.published_remediation_proofs
            ],
        }


def _serialize_mp(mp: merkle.MerkleProof):
    return {"leaf_index": mp.leaf_index, "siblings": [(s.hex(), r) for s, r in mp.siblings],
            "leaf_raw": mp.leaf_raw.hex()}


def _serialize_nm(kind, payload):
    if kind == "absent_between":
        return [_serialize_mp(p) for p in payload]
    return _serialize_mp(payload)


def build_attestation(qbom: QBOM) -> Attestation:
    """Runs entirely locally. Produces per-catalog-id Pedersen commitments
    (with blindings kept LOCAL) and a Merkle tree over salted finding
    leaves. Nothing here leaves the machine until the org explicitly calls
    one of the functions below and ships the result of `.to_public_dict()`."""
    counts = qbom.counts()
    catalog_commitments = {}
    for cid, n in counts.items():
        c, r = zk.commit_random(n)
        catalog_commitments[cid] = CatalogCommitment(cid, c, r)

    raw_leaves = [merkle.leaf_hash(f.catalog_id, f.location_id, f.salt) for f in qbom.findings]
    tree = merkle.build_tree(raw_leaves)

    return Attestation(
        org=qbom.org, catalog_hash=qbom.catalog_hash, merkle_root=tree.root,
        leaf_count=len(tree.sorted_leaves_raw), catalog_commitments=catalog_commitments,
    )


def _tree_from(qbom: QBOM) -> merkle.MerkleTree:
    raw_leaves = [merkle.leaf_hash(f.catalog_id, f.location_id, f.salt) for f in qbom.findings]
    return merkle.build_tree(raw_leaves)


# --- org-side: choosing what to disclose ------------------------------------
def prove_zero(att: Attestation, catalog_id: str) -> None:
    """Publish a proof that count(catalog_id) == 0 -- e.g. for a banned
    legacy algorithm the org wants to affirmatively demonstrate is absent
    across the whole scanned estate."""
    cc = att.catalog_commitments.get(catalog_id)
    if cc is None:
        c, r = zk.commit_random(0)
        cc = CatalogCommitment(catalog_id, c, r)
        att.catalog_commitments[catalog_id] = cc
    proof = zk.prove_public_value(0, cc.blinding, cc.commitment, context=f"zero:{catalog_id}".encode())
    att.published_zero_proofs[catalog_id] = proof


def prove_below_threshold_for_qbom(qbom: QBOM, att: Attestation, catalog_id: str, threshold: int,
                                    n_bits: int = 24) -> None:
    """Publish a proof that count(catalog_id) < threshold. `count` is read
    from the org's own local QBOM (never from the commitment -- commitments
    don't store plaintext)."""
    count = qbom.counts().get(catalog_id, 0)
    cc = att.catalog_commitments.get(catalog_id)
    if cc is None:
        c, r = zk.commit_random(count)
        cc = CatalogCommitment(catalog_id, c, r)
        att.catalog_commitments[catalog_id] = cc
    proof = zk.prove_below_threshold(count, cc.blinding, cc.commitment, threshold, n_bits,
                                      context=f"below:{catalog_id}:{threshold}".encode())
    att.published_threshold_proofs[catalog_id] = proof


def disclose_finding(qbom: QBOM, att: Attestation, catalog_id: str, location_id: str) -> None:
    """Reveal exactly one finding (its content, salt, and a Merkle inclusion
    proof) -- e.g. because an auditor flagged it and the org wants to confirm
    or discuss that specific item without exposing the rest of the scan.
    The salt must be published for this one finding for the disclosure to be
    verifiable at all (see verify_finding_disclosure); every other finding's
    salt, and the findings themselves, stay local."""
    f = next((x for x in qbom.findings if x.catalog_id == catalog_id and x.location_id == location_id), None)
    if f is None:
        raise KeyError(f"no finding {catalog_id}@{location_id} in this QBOM")
    tree = _tree_from(qbom)
    leaf = merkle.leaf_hash(catalog_id, location_id, f.salt)
    mp = tree.prove_inclusion(leaf)
    att.published_finding_disclosures.append((f.to_public_dict(), f.salt, mp))


def prove_remediated(qbom_before: QBOM, qbom_after: QBOM, att_after: Attestation,
                      catalog_id: str, location_id: str, salt: bytes, label: str = "") -> None:
    """Confirm a previously disclosed finding (catalog_id, location_id, salt
    -- from an earlier disclose_finding call) is no longer present in a new
    scan's Merkle tree, without revealing anything else about the new scan.
    `salt` must be the exact salt published in that earlier disclosure --
    non-membership can only be checked against a leaf hash the verifier can
    reconstruct, which requires knowing (catalog_id, location_id, salt) in
    full; it cannot answer 'is this algorithm absent anywhere' in general."""
    target = merkle.leaf_hash(catalog_id, location_id, salt)
    tree_after = _tree_from(qbom_after)
    kind, payload = tree_after.prove_non_membership(target)
    att_after.published_remediation_proofs.append((label or f"{catalog_id}@{location_id}", kind, payload))


# --- verifier-side: checking a published attestation ------------------------
def verify_zero_proof(public: dict, catalog_id: str) -> bool:
    hexc = public["catalog_commitments"].get(catalog_id)
    proof_d = public["zero_proofs"].get(catalog_id)
    if not hexc or not proof_d:
        return False
    c = zk.commitment_from_hex(hexc)
    proof = zk.PublicValueProof.from_dict(proof_d)
    return zk.verify_public_value(c, proof, context=f"zero:{catalog_id}".encode())


def verify_threshold_proof(public: dict, catalog_id: str) -> bool:
    """Fully self-contained: verifies directly from the published dict, no
    access to the original Python proof objects required."""
    hexc = public["catalog_commitments"].get(catalog_id)
    proof_d = public["threshold_proofs"].get(catalog_id)
    if not hexc or not proof_d:
        return False
    commitment = zk.commitment_from_hex(hexc)
    proof = zk.ThresholdProof.from_dict(proof_d)
    context = f"below:{catalog_id}:{proof.threshold}".encode()
    return zk.verify_below_threshold(commitment, proof, context)


def verify_finding_disclosure(public: dict, index: int) -> bool:
    root = bytes.fromhex(public["merkle_root"])
    entry = public["finding_disclosures"][index]
    finding = entry["finding"]
    salt = bytes.fromhex(entry["salt"])
    leaf = merkle.leaf_hash(finding["catalog_id"], f'{finding["file_path"]}:{finding["line"]}', salt)
    siblings = [(bytes.fromhex(h), r) for h, r in entry["siblings"]]
    mp = merkle.MerkleProof(entry["leaf_index"], siblings, leaf)
    return merkle.verify_inclusion(root, mp)


def verify_remediation_proof(public: dict, index: int, catalog_id: str, location_id: str, salt: bytes) -> bool:
    root = bytes.fromhex(public["merkle_root"])
    entry = public["remediation_proofs"][index]
    target = merkle.leaf_hash(catalog_id, location_id, salt)
    kind = entry["kind"]
    if kind == "absent_between":
        lo_d, hi_d = entry["payload"]
        lo = merkle.MerkleProof(lo_d["leaf_index"], [(bytes.fromhex(h), r) for h, r in lo_d["siblings"]],
                                 bytes.fromhex(lo_d["leaf_raw"]))
        hi = merkle.MerkleProof(hi_d["leaf_index"], [(bytes.fromhex(h), r) for h, r in hi_d["siblings"]],
                                 bytes.fromhex(hi_d["leaf_raw"]))
        payload = (lo, hi)
    else:
        d = entry["payload"]
        payload = merkle.MerkleProof(d["leaf_index"], [(bytes.fromhex(h), r) for h, r in d["siblings"]],
                                      bytes.fromhex(d["leaf_raw"]))
    return merkle.verify_non_membership(root, target, kind, payload, public["leaf_count"])


# --- homomorphic aggregation across multiple orgs/business units -----------
def aggregate_commitments(public_dicts: list, catalog_id: str) -> zk.Commitment:
    """A parent org / regulator sums the same catalog_id's commitment across
    N published attestations. This requires ONLY the public commitments --
    no counts, no blindings -- and produces a valid commitment to the sector
    total. To learn the actual total (not just verify a claim about it), the
    N orgs must cooperate to reveal the summed blinding (secure multiparty
    summation) or a designated auditor with per-org blindings opens it --
    summing commitments alone never leaks any individual org's value."""
    total = zk.ZERO_COMMITMENT
    for pub in public_dicts:
        hexc = pub["catalog_commitments"].get(catalog_id)
        if hexc:
            total = total + zk.commitment_from_hex(hexc)
    return total
