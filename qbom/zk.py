"""
Zero-knowledge layer for QBOM disclosure.

The problem this solves: a central risk/compliance authority (a regulator,
a parent company, a customer doing vendor risk assessment) wants assurance
about an organisation's post-quantum exposure -- "you have zero RSA-1024",
"fewer than 50 legacy TLS endpoints", "at least 30% of your KEX is PQ-safe"
-- without the organisation handing over its actual crypto inventory, which
is itself a sensitive attack-surface map.

Building blocks, all on NIST P-256 (see ec.py):

1. PedersenCommitment: C = v*G + r*H. Perfectly hiding (r is uniform, so C
   looks like a random point regardless of v), computationally binding
   (opening it to two different values would mean knowing log_G(H), which
   nobody does since H was derived by hash-to-curve).

2. Additive homomorphism: Commit(v1,r1) + Commit(v2,r2) = Commit(v1+v2,r1+r2).
   This is what lets a parent company sum business-unit commitments into a
   sector-wide total for the SAME catalog algorithm ID without ever seeing
   any business unit's individual count.

3. Sigma-protocol proofs, all made non-interactive via Fiat-Shamir
   (challenge = hash of the protocol transcript):
   - ProofOfOpening: "I know (v, r) behind this commitment." Used when an
     authorised auditor is allowed to see the value; the proof lets them
     confirm the opening is genuine (not just an assertion).
   - ProofOfPublicValue: "This commitment opens to public value m," without
     revealing r. This is the main compliance primitive: proves
     count(BANNED_ALG) == 0 while the verifier never learns the blinding
     factor and, in the finding-level Merkle layer, never sees any other
     finding either.
   - RangeProof: "The committed value lies in [0, 2^n)," via bit
     decomposition plus a Schnorr OR-proof per bit (Cramer-Damgard-
     Schoenmakers construction) that a bit commitment opens to 0 or to 1
     without revealing which. Used to prove threshold claims like
     "count(RSA-SUB2048) < 10" by proving (10 - 1 - count) is in range.

None of this is a general-purpose crypto library: it implements exactly the
proofs this framework's privacy model needs, nothing more.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from . import ec
from .ec import G, H, N, O, Point, point_add, point_eq, point_to_bytes, scalar_mult


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def _neg(p: Point) -> Point:
    if p.is_infinity():
        return p
    return Point(p.x, (-p.y) % ec.P)


def _sub(p1: Point, p2: Point) -> Point:
    return point_add(p1, _neg(p2))


def _challenge(*parts: bytes) -> int:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return int.from_bytes(h.digest(), "big") % N


# ---------------------------------------------------------------------------
# Commitment
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Commitment:
    point: Point

    def to_hex(self) -> str:
        return point_to_bytes(self.point).hex()

    def __add__(self, other: "Commitment") -> "Commitment":
        return Commitment(point_add(self.point, other.point))


def point_from_hex(h: str) -> Point:
    b = bytes.fromhex(h)
    if b == b"\x00":
        return O
    assert b[0] == 0x04, "expected uncompressed point encoding"
    x = int.from_bytes(b[1:33], "big")
    y = int.from_bytes(b[33:65], "big")
    return Point(x, y)


def commitment_from_hex(h: str) -> Commitment:
    return Commitment(point_from_hex(h))


def commit(value: int, blinding: int) -> Commitment:
    return Commitment(point_add(scalar_mult(value % N, G), scalar_mult(blinding, H)))


def commit_random(value: int) -> tuple[Commitment, int]:
    r = rand_scalar()
    return commit(value, r), r


ZERO_COMMITMENT = Commitment(O)  # neutral element: identity for homomorphic sum


# ---------------------------------------------------------------------------
# Proof of knowledge of opening: C = vG + rH
# ---------------------------------------------------------------------------
@dataclass
class OpeningProof:
    t: Point
    s_v: int
    s_r: int

    def to_dict(self):
        return {"t": point_to_bytes(self.t).hex(), "s_v": self.s_v, "s_r": self.s_r}

    @staticmethod
    def from_dict(d):
        return OpeningProof(point_from_hex(d["t"]), d["s_v"], d["s_r"])


def prove_opening(value: int, blinding: int, commitment: Commitment, context: bytes = b"") -> OpeningProof:
    k_v, k_r = rand_scalar(), rand_scalar()
    t = point_add(scalar_mult(k_v, G), scalar_mult(k_r, H))
    c = _challenge(context, point_to_bytes(commitment.point), point_to_bytes(t))
    s_v = (k_v + c * value) % N
    s_r = (k_r + c * blinding) % N
    return OpeningProof(t, s_v, s_r)


def verify_opening(commitment: Commitment, proof: OpeningProof, context: bytes = b"") -> bool:
    c = _challenge(context, point_to_bytes(commitment.point), point_to_bytes(proof.t))
    lhs = point_add(scalar_mult(proof.s_v, G), scalar_mult(proof.s_r, H))
    rhs = point_add(proof.t, scalar_mult(c, commitment.point))
    return point_eq(lhs, rhs)


# ---------------------------------------------------------------------------
# Proof that a commitment opens to a *known public* value m (blinding hidden)
# Reduces to a Schnorr proof of knowledge of r for (C - mG) = rH.
# ---------------------------------------------------------------------------
@dataclass
class PublicValueProof:
    public_value: int
    t: Point
    s: int

    def to_dict(self):
        return {"public_value": self.public_value, "t": point_to_bytes(self.t).hex(), "s": self.s}

    @staticmethod
    def from_dict(d):
        return PublicValueProof(d["public_value"], point_from_hex(d["t"]), d["s"])


def prove_public_value(value: int, blinding: int, commitment: Commitment, context: bytes = b"") -> PublicValueProof:
    assert value % N == value, "value must already be reduced"
    k = rand_scalar()
    t = scalar_mult(k, H)
    target = _sub(commitment.point, scalar_mult(value, G))
    c = _challenge(context, point_to_bytes(target), point_to_bytes(t))
    s = (k + c * blinding) % N
    return PublicValueProof(value, t, s)


def verify_public_value(commitment: Commitment, proof: PublicValueProof, context: bytes = b"") -> bool:
    target = _sub(commitment.point, scalar_mult(proof.public_value, G))
    c = _challenge(context, point_to_bytes(target), point_to_bytes(proof.t))
    lhs = scalar_mult(proof.s, H)
    rhs = point_add(proof.t, scalar_mult(c, target))
    return point_eq(lhs, rhs)


# ---------------------------------------------------------------------------
# Schnorr OR-proof that a bit-commitment opens to 0 or to 1 (CDS construction)
# ---------------------------------------------------------------------------
@dataclass
class BitProof:
    t0: Point
    t1: Point
    c0: int
    c1: int
    s0: int
    s1: int

    def to_dict(self):
        return {"t0": point_to_bytes(self.t0).hex(), "t1": point_to_bytes(self.t1).hex(),
                "c0": self.c0, "c1": self.c1, "s0": self.s0, "s1": self.s1}

    @staticmethod
    def from_dict(d):
        return BitProof(point_from_hex(d["t0"]), point_from_hex(d["t1"]), d["c0"], d["c1"], d["s0"], d["s1"])


def prove_bit(bit: int, blinding: int, commitment: Commitment, context: bytes = b"") -> BitProof:
    assert bit in (0, 1)
    target0 = commitment.point                          # C - 0*G = C
    target1 = _sub(commitment.point, G)                  # C - 1*G

    if bit == 0:
        # real branch 0, simulated branch 1
        k0 = rand_scalar()
        t0 = scalar_mult(k0, H)
        c1 = rand_scalar()
        s1 = rand_scalar()
        t1 = _sub(scalar_mult(s1, H), scalar_mult(c1, target1))
        c = _challenge(context, point_to_bytes(commitment.point), point_to_bytes(t0), point_to_bytes(t1))
        c0 = (c - c1) % N
        s0 = (k0 + c0 * blinding) % N
    else:
        k1 = rand_scalar()
        t1 = scalar_mult(k1, H)
        c0 = rand_scalar()
        s0 = rand_scalar()
        t0 = _sub(scalar_mult(s0, H), scalar_mult(c0, target0))
        c = _challenge(context, point_to_bytes(commitment.point), point_to_bytes(t0), point_to_bytes(t1))
        c1 = (c - c0) % N
        s1 = (k1 + c1 * blinding) % N
    return BitProof(t0, t1, c0, c1, s0, s1)


def verify_bit(commitment: Commitment, proof: BitProof, context: bytes = b"") -> bool:
    target0 = commitment.point
    target1 = _sub(commitment.point, G)
    c = _challenge(context, point_to_bytes(commitment.point), point_to_bytes(proof.t0), point_to_bytes(proof.t1))
    if (proof.c0 + proof.c1) % N != c % N:
        return False
    ok0 = point_eq(scalar_mult(proof.s0, H), point_add(proof.t0, scalar_mult(proof.c0, target0)))
    ok1 = point_eq(scalar_mult(proof.s1, H), point_add(proof.t1, scalar_mult(proof.c1, target1)))
    return ok0 and ok1


# ---------------------------------------------------------------------------
# Range proof via bit decomposition: proves 0 <= value < 2^n_bits
# ---------------------------------------------------------------------------
@dataclass
class RangeProof:
    n_bits: int
    bit_commitments: list
    bit_proofs: list

    def to_summary(self):
        return {"n_bits": self.n_bits, "bits": len(self.bit_commitments)}

    def to_dict(self):
        return {
            "n_bits": self.n_bits,
            "bit_commitments": [c.to_hex() for c in self.bit_commitments],
            "bit_proofs": [p.to_dict() for p in self.bit_proofs],
        }

    @staticmethod
    def from_dict(d):
        return RangeProof(
            d["n_bits"],
            [commitment_from_hex(h) for h in d["bit_commitments"]],
            [BitProof.from_dict(p) for p in d["bit_proofs"]],
        )


def prove_range(value: int, blinding: int, commitment: Commitment, n_bits: int = 24,
                 context: bytes = b"") -> RangeProof:
    if value < 0 or value >= (1 << n_bits):
        raise ValueError(f"value {value} out of declared range [0, 2^{n_bits})")
    bits = [(value >> i) & 1 for i in range(n_bits)]
    blindings = [rand_scalar() for _ in range(n_bits)]
    # force the *last* bit's blinding so that sum(2^i r_i) == r  (mod N),
    # which makes commitment == sum(2^i * bitCommit_i) hold exactly.
    weighted_prior = sum((1 << i) * blindings[i] for i in range(n_bits - 1)) % N
    last_weight = pow(1 << (n_bits - 1), -1, N)
    blindings[n_bits - 1] = ((blinding - weighted_prior) * last_weight) % N

    bit_commits = [commit(bits[i], blindings[i]) for i in range(n_bits)]
    bit_proofs = [prove_bit(bits[i], blindings[i], bit_commits[i], context + i.to_bytes(2, "big"))
                  for i in range(n_bits)]
    return RangeProof(n_bits, bit_commits, bit_proofs)


def verify_range(commitment: Commitment, proof: RangeProof, context: bytes = b"") -> bool:
    if len(proof.bit_commitments) != proof.n_bits or len(proof.bit_proofs) != proof.n_bits:
        return False
    for i in range(proof.n_bits):
        if not verify_bit(proof.bit_commitments[i], proof.bit_proofs[i], context + i.to_bytes(2, "big")):
            return False
    acc = O
    for i in range(proof.n_bits):
        acc = point_add(acc, scalar_mult(1 << i, proof.bit_commitments[i].point))
    return point_eq(acc, commitment.point)


# ---------------------------------------------------------------------------
# "count is strictly less than threshold" — fully linked and sound:
#
#   slack = threshold - 1 - count            (prover computes; must be >= 0)
#   D     = count_commitment + slack_commitment
#         = Commit(count + slack, r_count + r_slack)
#         = Commit(threshold - 1, r_count + r_slack)     <- exact group identity
#
# The prover knows r_count (blinding of the pre-existing count_commitment)
# and r_slack (its own), so it can produce a PublicValueProof that D opens to
# the *public* value (threshold - 1). A cheating prover who picks a
# slack_commitment for a different value cannot produce that linkage proof
# without solving a discrete log, and a range proof alone (without the
# linkage) could be satisfied by any unrelated small commitment -- the
# linkage is what forces slack to be the actual value threshold-1-count.
# ---------------------------------------------------------------------------
@dataclass
class ThresholdProof:
    threshold: int
    slack_commitment: Commitment
    range_proof: RangeProof
    linkage_proof: PublicValueProof

    def to_dict(self):
        return {"threshold": self.threshold, "slack_commitment": self.slack_commitment.to_hex(),
                "range": self.range_proof.to_dict(), "linkage": self.linkage_proof.to_dict()}

    @staticmethod
    def from_dict(d):
        return ThresholdProof(
            d["threshold"], commitment_from_hex(d["slack_commitment"]),
            RangeProof.from_dict(d["range"]), PublicValueProof.from_dict(d["linkage"]),
        )


def prove_below_threshold(count: int, r_count: int, count_commitment: Commitment, threshold: int,
                           n_bits: int = 24, context: bytes = b"") -> ThresholdProof:
    slack = threshold - 1 - count
    if slack < 0:
        raise ValueError("count is not below threshold; refusing to construct a false proof")
    r_slack = rand_scalar()
    slack_commit = commit(slack, r_slack)
    rp = prove_range(slack, r_slack, slack_commit, n_bits, context)
    d_point = count_commitment + slack_commit
    linkage = prove_public_value(threshold - 1, (r_count + r_slack) % N, d_point, context)
    return ThresholdProof(threshold, slack_commit, rp, linkage)


def verify_below_threshold(count_commitment: Commitment, proof: ThresholdProof, context: bytes = b"") -> bool:
    if not verify_range(proof.slack_commitment, proof.range_proof, context):
        return False
    d_point = count_commitment + proof.slack_commitment
    if proof.linkage_proof.public_value != proof.threshold - 1:
        return False
    return verify_public_value(d_point, proof.linkage_proof, context)
