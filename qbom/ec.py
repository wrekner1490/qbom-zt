"""
Minimal, auditable NIST P-256 (secp256r1) point arithmetic.

Why hand-rolled instead of a dependency: this module underpins the
zero-knowledge layer that decides what a scanning agent is allowed to reveal
about an organisation's infrastructure. For a security-sensitive primitive
like that, a ~100-line file anyone can read beats an opaque black box.
It implements only what commitments.py needs: point add/double, scalar
multiplication (Montgomery ladder, constant-time in the loop structure),
and a deterministic hash-to-curve for the second Pedersen generator H.

Curve parameters are the standard NIST P-256 constants (FIPS 186-4 / SEC2).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

# NIST P-256 domain parameters
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3 % P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # order
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


@dataclass(frozen=True)
class Point:
    x: int | None  # None, None = point at infinity
    y: int | None

    def is_infinity(self) -> bool:
        return self.x is None


O = Point(None, None)


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def point_add(p1: Point, p2: Point) -> Point:
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P == 0:
        return O
    if p1.x == p2.x and p1.y == p2.y:
        return point_double(p1)
    lam = ((p2.y - p1.y) * _inv((p2.x - p1.x) % P, P)) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def point_double(p1: Point) -> Point:
    if p1.is_infinity() or p1.y == 0:
        return O
    lam = ((3 * p1.x * p1.x + A) * _inv((2 * p1.y) % P, P)) % P
    x3 = (lam * lam - 2 * p1.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def scalar_mult(k: int, p1: Point) -> Point:
    """Montgomery ladder: fixed sequence of add+double regardless of bit value,
    so branch timing doesn't leak bits of a secret scalar."""
    k %= N
    r0, r1 = O, p1
    for bit in bin(k)[2:].zfill(256):
        if bit == "0":
            r1 = point_add(r0, r1)
            r0 = point_double(r0)
        else:
            r0 = point_add(r0, r1)
            r1 = point_double(r1)
    return r0


def is_on_curve(p: Point) -> bool:
    if p.is_infinity():
        return True
    return (p.y * p.y - (p.x**3 + A * p.x + B)) % P == 0


G = Point(GX, GY)
assert is_on_curve(G)


def hash_to_curve(label: bytes) -> Point:
    """Deterministic, nothing-up-my-sleeve second generator: try-and-increment
    over SHA3-256(label || counter) until the resulting x-coordinate lands on
    the curve. Used only to derive H for Pedersen commitments -- nobody,
    including us, knows log_G(H), which is exactly the property Pedersen
    commitments need to be computationally binding and perfectly hiding."""
    counter = 0
    while True:
        candidate = hashlib.sha3_256(label + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(candidate, "big") % P
        rhs = (x**3 + A * x + B) % P
        y = pow(rhs, (P + 1) // 4, P)  # P ≡ 3 mod 4, so this is a valid sqrt if one exists
        if (y * y) % P == rhs:
            if y % 2 != 0:
                y = P - y
            pt = Point(x, y)
            if is_on_curve(pt) and not pt.is_infinity():
                return pt
        counter += 1


H = hash_to_curve(b"QBOM-ZT-PEDERSEN-H-v1")


def point_to_bytes(p: Point) -> bytes:
    if p.is_infinity():
        return b"\x00"
    return b"\x04" + p.x.to_bytes(32, "big") + p.y.to_bytes(32, "big")


def point_eq(p1: Point, p2: Point) -> bool:
    return p1.x == p2.x and p1.y == p2.y
