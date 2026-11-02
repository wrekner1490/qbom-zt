"""
Cryptographic algorithm catalog with quantum-threat classification.

The catalog is the *public, ordered* vocabulary of the whole framework:
  * the scanner normalises everything it sees into catalog IDs,
  * the risk engine keys its quantum-threat model off `threat`,
  * the zero-trust layer commits to one counter per catalog entry (fixed order),
    so a verifier can ask about "RSA-SUB2048" without the prover revealing
    anything else.

Threat classes (the quantum "principles" the tool actually uses):
  SHOR              Public-key scheme broken outright by Shor's algorithm
                    (RSA, DH/FFDH, DSA, ECDSA/ECDH, EdDSA/X25519).
  GROVER            Symmetric/hash scheme whose effective security is roughly
                    halved by Grover's search (AES-128 -> ~64-bit quantum).
  CLASSICAL_BROKEN  Already broken/deprecated without any quantum computer.
  PQ_SAFE           NIST-standardised PQC or a symmetric/hash primitive with
                    an adequate quantum margin.
  HYBRID            Classical + PQ combined (e.g. X25519MLKEM768).
  LEGACY_PQ         Pre-standard PQ names (Kyber/Dilithium drafts): right idea,
                    but not interoperable with the final FIPS 203/204.
  UNKNOWN           Could not be classified.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

CATALOG_VERSION = "1"

SHOR, GROVER, BROKEN, SAFE, HYBRID, LEGACY_PQ, UNKNOWN = (
    "SHOR", "GROVER", "CLASSICAL_BROKEN", "PQ_SAFE", "HYBRID", "LEGACY_PQ", "UNKNOWN",
)


@dataclass(frozen=True)
class Alg:
    id: str
    label: str
    primitive: str       # CycloneDX 1.6 primitive vocabulary
    threat: str
    classical_bits: int  # approx. classical security strength
    nist_q_level: int    # CycloneDX nistQuantumSecurityLevel (0 = no quantum security)
    replacement: str
    kind: str = "algorithm"   # algorithm | protocol


def _a(id, label, primitive, threat, cbits, qlvl, repl, kind="algorithm"):
    return Alg(id, label, primitive, threat, cbits, qlvl, repl, kind)


_KEM = "ML-KEM-768 (FIPS 203); in TLS/SSH use hybrid X25519MLKEM768 first"
_SIG = "ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) for long-lived roots/firmware"
_H256 = "SHA-256 / SHA3-256 (or SHA-384 for CNSA 2.0)"

# NOTE: order is part of the zero-trust commitment format. Append only.
_ALGS = [
    # --- Shor-vulnerable public key ------------------------------------
    _a("RSA-SUB2048", "RSA (<2048-bit)", "pke", SHOR, 80, 0, _KEM + " / " + _SIG + "; and stop using <2048 now"),
    _a("RSA-2048", "RSA-2048", "pke", SHOR, 112, 0, _KEM + " / " + _SIG),
    _a("RSA-3072", "RSA-3072", "pke", SHOR, 128, 0, _KEM + " / " + _SIG),
    _a("RSA-4096", "RSA-4096+", "pke", SHOR, 140, 0, _KEM + " / " + _SIG),
    _a("RSA-UNK", "RSA (size unknown)", "pke", SHOR, 112, 0, _KEM + " / " + _SIG),
    _a("DH-SUB2048", "DH/FFDH (<2048-bit)", "key-agree", SHOR, 80, 0, _KEM + "; stop using <2048 now"),
    _a("DH-2048", "DH/FFDH (>=2048-bit)", "key-agree", SHOR, 112, 0, _KEM),
    _a("DSA", "DSA", "signature", SHOR, 112, 0, _SIG),
    _a("EC-P256", "ECC P-256 (ECDSA/ECDH)", "signature", SHOR, 128, 0, _KEM + " / " + _SIG),
    _a("EC-P384", "ECC P-384 (ECDSA/ECDH)", "signature", SHOR, 192, 0, _KEM + " / " + _SIG),
    _a("EC-P521", "ECC P-521 (ECDSA/ECDH)", "signature", SHOR, 256, 0, _KEM + " / " + _SIG),
    _a("ED25519", "Ed25519", "signature", SHOR, 128, 0, _SIG),
    _a("ED448", "Ed448", "signature", SHOR, 224, 0, _SIG),
    _a("X25519", "X25519", "key-agree", SHOR, 128, 0, "Hybrid X25519MLKEM768 now, ML-KEM-768 later"),
    _a("X448", "X448", "key-agree", SHOR, 224, 0, "Hybrid X448MLKEM1024 / ML-KEM-1024"),
    # --- Grover-weakened symmetric ---------------------------------------
    _a("AES-128", "AES-128", "block-cipher", GROVER, 128, 1, "AES-256 (CNSA 2.0 requires 256-bit keys)"),
    _a("AES-192", "AES-192", "block-cipher", GROVER, 192, 3, "AES-256"),
    _a("AES-256", "AES-256", "block-cipher", SAFE, 256, 5, "none needed"),
    _a("AES-UNK", "AES (key size unknown)", "block-cipher", GROVER, 128, 1, "Verify key size; use AES-256"),
    _a("CHACHA20", "ChaCha20(-Poly1305)", "stream-cipher", SAFE, 256, 5, "none needed"),
    # --- Classically broken / deprecated ---------------------------------
    _a("MD5", "MD5", "hash", BROKEN, 0, 0, _H256),
    _a("SHA1", "SHA-1", "hash", BROKEN, 63, 0, _H256),
    _a("DES", "DES", "block-cipher", BROKEN, 56, 0, "AES-256-GCM"),
    _a("3DES", "3DES", "block-cipher", BROKEN, 112, 0, "AES-256-GCM"),
    _a("RC4", "RC4", "stream-cipher", BROKEN, 0, 0, "AES-256-GCM or ChaCha20-Poly1305"),
    _a("BLOWFISH", "Blowfish", "block-cipher", BROKEN, 64, 0, "AES-256-GCM"),
    _a("MODE-ECB", "ECB mode (misuse)", "block-cipher", BROKEN, 0, 0, "AES-256-GCM (AEAD)"),
    # --- Hashes with adequate margin ---------------------------------------
    _a("SHA-224", "SHA-224", "hash", GROVER, 112, 1, _H256),
    _a("SHA-256", "SHA-256", "hash", SAFE, 128, 2, "none needed"),
    _a("SHA-384", "SHA-384", "hash", SAFE, 192, 4, "none needed"),
    _a("SHA-512", "SHA-512", "hash", SAFE, 256, 5, "none needed"),
    _a("SHA3", "SHA-3 family", "hash", SAFE, 256, 4, "none needed"),
    # --- Protocols ---------------------------------------------------------
    _a("SSL-2/3", "SSLv2/SSLv3", "other", BROKEN, 0, 0, "TLS 1.3", "protocol"),
    _a("TLS1.0", "TLS 1.0", "other", BROKEN, 0, 0, "TLS 1.3 with hybrid PQ key exchange", "protocol"),
    _a("TLS1.1", "TLS 1.1", "other", BROKEN, 0, 0, "TLS 1.3 with hybrid PQ key exchange", "protocol"),
    _a("TLS1.2", "TLS 1.2", "other", SHOR, 112, 0, "TLS 1.3 with hybrid PQ key exchange", "protocol"),
    _a("TLS1.3", "TLS 1.3 (classical KEX)", "other", SHOR, 128, 0, "Enable X25519MLKEM768 key share", "protocol"),
    _a("TLS1.3-HYBRID", "TLS 1.3 (hybrid PQ key exchange configured)", "other", HYBRID, 128, 3,
       "none needed -- verify the hybrid group is actually negotiated, not just configured", "protocol"),
    # --- Post-quantum ---------------------------------------------------------
    _a("ML-KEM-512", "ML-KEM-512", "kem", SAFE, 128, 1, "none needed"),
    _a("ML-KEM-768", "ML-KEM-768", "kem", SAFE, 192, 3, "none needed"),
    _a("ML-KEM-1024", "ML-KEM-1024", "kem", SAFE, 256, 5, "none needed"),
    _a("ML-DSA", "ML-DSA (44/65/87)", "signature", SAFE, 192, 3, "none needed"),
    _a("SLH-DSA", "SLH-DSA (SPHINCS+)", "signature", SAFE, 192, 3, "none needed"),
    _a("FN-DSA", "FN-DSA (Falcon)", "signature", SAFE, 192, 1, "none needed (FIPS 206 pending)"),
    _a("HBS", "Hash-based sigs (LMS/XMSS)", "signature", SAFE, 192, 3, "none needed"),
    _a("HYBRID-KEM", "Hybrid KEM (classical+ML-KEM)", "kem", HYBRID, 192, 3, "Later: pure ML-KEM where policy allows"),
    _a("KYBER-LEGACY", "Kyber (pre-standard)", "kem", LEGACY_PQ, 192, 3, "Move to final ML-KEM (FIPS 203) - not wire-compatible"),
    _a("DILITHIUM-LEGACY", "Dilithium (pre-standard)", "signature", LEGACY_PQ, 192, 3, "Move to final ML-DSA (FIPS 204) - not wire-compatible"),
    # --- Fallback -----------------------------------------------------------------
    _a("UNCLASSIFIED", "Unclassified crypto", "other", UNKNOWN, 0, 0, "Manual review"),
]

CATALOG: dict[str, Alg] = {a.id: a for a in _ALGS}
CATALOG_IDS: list[str] = [a.id for a in _ALGS]
CATALOG_HASH: str = hashlib.sha3_256(
    (CATALOG_VERSION + "|" + "|".join(CATALOG_IDS)).encode()
).hexdigest()


def get(alg_id: str) -> Alg:
    return CATALOG.get(alg_id, CATALOG["UNCLASSIFIED"])


# ---------------------------------------------------------------------------
# Parameter -> catalog-ID helpers
# ---------------------------------------------------------------------------
def rsa_id(bits: Optional[int]) -> str:
    if not bits:
        return "RSA-UNK"
    if bits < 2048:
        return "RSA-SUB2048"
    if bits < 3072:
        return "RSA-2048"
    if bits < 4096:
        return "RSA-3072"
    return "RSA-4096"


def dh_id(bits: Optional[int]) -> str:
    return "DH-SUB2048" if (bits and bits < 2048) else "DH-2048"


def aes_id(bits: Optional[int]) -> str:
    return {128: "AES-128", 192: "AES-192", 256: "AES-256"}.get(bits or 0, "AES-UNK")


def curve_id(name: Optional[str]) -> str:
    n = (name or "").lower().replace("_", "").replace("-", "")
    if any(k in n for k in ("384",)):
        return "EC-P384"
    if any(k in n for k in ("521",)):
        return "EC-P521"
    return "EC-P256"  # P-256, secp256k1, brainpool256, unknown -> most common


def hash_id(name: str) -> Optional[str]:
    n = name.lower().replace("_", "").replace("-", "").replace(" ", "")
    if n.startswith("md5"):
        return "MD5"
    if n in ("sha1", "sha"):
        return "SHA1"
    if n.startswith("sha3"):
        return "SHA3"
    return {"sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}.get(n)


# ---------------------------------------------------------------------------
# Free-text token resolver, used by config parsers and inventory ingestion
# (JWT names, sshd KexAlgorithms, nginx curves, "ECDHE-RSA-AES128-GCM-SHA256"...)
# Returns (alg_id, purpose_hint) or None.
# ---------------------------------------------------------------------------
_TOKEN_RULES: list[tuple[re.Pattern, object, str, bool]] = []


def _t(pattern: str, target, purpose: str = "UNKNOWN", search: bool = False):
    _TOKEN_RULES.append((re.compile(pattern, re.I), target, purpose, search))


# post-quantum & hybrid first (they contain classical substrings)
_t(r"(x25519|x448|secp\d+r1|p-?\d+).*(mlkem|kyber)|(mlkem|kyber).*(x25519|x448|secp\d+r1)|sntrup761x25519", "HYBRID-KEM", "KEY_EXCHANGE", search=True)
_t(r"^ml-?kem-?512$", "ML-KEM-512", "KEY_EXCHANGE")
_t(r"^ml-?kem-?768$", "ML-KEM-768", "KEY_EXCHANGE")
_t(r"^ml-?kem-?1024$", "ML-KEM-1024", "KEY_EXCHANGE")
_t(r"^kyber-?(512|768|1024)$", "KYBER-LEGACY", "KEY_EXCHANGE")
_t(r"^dilithium-?[2-5]?$|^dilithium\d?$", "DILITHIUM-LEGACY", "SIGNATURE")
_t(r"^ml-?dsa(-?(44|65|87))?$", "ML-DSA", "SIGNATURE")
_t(r"^(slh-?dsa|sphincs\+?)(.*)$", "SLH-DSA", "SIGNATURE")
_t(r"^(falcon|fn-?dsa)(-?\d+)?$", "FN-DSA", "SIGNATURE")
_t(r"^(lms|xmss|hss|xmssmt)(.*)$", "HBS", "SIGNATURE")
# protocols
_t(r"^ssl-?v?[23](\.0)?$|^sslv23$", "SSL-2/3", "PROTOCOL")
_t(r"^tls-?v?1(\.0)?$|^tlsv1$", "TLS1.0", "PROTOCOL")
_t(r"^tls-?v?1[._]1$", "TLS1.1", "PROTOCOL")
_t(r"^tls-?v?1[._]2$", "TLS1.2", "PROTOCOL")
_t(r"^tls-?v?1[._]3$", "TLS1.3", "PROTOCOL")
# classical asymmetric
_t(r"^rsa[-_: ]?(\d{3,5})$", lambda m: rsa_id(int(m.group(1))), "UNKNOWN_ASYM")
_t(r"^(ssh-rsa|rsa-sha2-\d+|rs\d{3}|ps\d{3}|rsa|rsassa.*|rsa-oaep|rsaes.*)$", "RSA-UNK", "UNKNOWN_ASYM")
_t(r"^(dsa|ssh-dss)$", "DSA", "SIGNATURE")
_t(r"^diffie-hellman-group1-.*|^dh-?(512|768|1024)$", "DH-SUB2048", "KEY_EXCHANGE")
_t(r"^diffie-hellman-group(14|15|16|17|18)-.*|^dh-?(2048|3072|4096|8192)$|^dhe$|^diffie-hellman-group-exchange-.*|^dh$", "DH-2048", "KEY_EXCHANGE")
_t(r"^(ecdsa|ecdh|ecdhe|ec)[-_ ]?(p-?|nistp|secp)?(256|384|521)(r1)?$", lambda m: curve_id(m.group(3)), "UNKNOWN_ASYM")
_t(r"^(es256|ecdsa-sha2-nistp256|prime256v1|secp256r1|secp256k1|p-?256|nistp256|ecdhe?-?(p-?256|nistp256)?|ecdhe|ecdh-sha2-nistp256)$", "EC-P256", "UNKNOWN_ASYM")
_t(r"^(es384|ecdsa-sha2-nistp384|secp384r1|p-?384|nistp384|ecdh-sha2-nistp384|ecdhe-p-?384)$", "EC-P384", "UNKNOWN_ASYM")
_t(r"^(es512|ecdsa-sha2-nistp521|secp521r1|p-?521|nistp521|ecdh-sha2-nistp521)$", "EC-P521", "UNKNOWN_ASYM")
_t(r"^(x25519|curve25519(-sha256(@libssh\.org)?)?)$", "X25519", "KEY_EXCHANGE")
_t(r"^x448$", "X448", "KEY_EXCHANGE")
_t(r"^(ed25519|eddsa|ssh-ed25519|ed25519-sha512)$", "ED25519", "SIGNATURE")
_t(r"^ed448$", "ED448", "SIGNATURE")
# symmetric
_t(r"aes[-_]?128", "AES-128", "SYMMETRIC", search=True)
_t(r"aes[-_]?192", "AES-192", "SYMMETRIC", search=True)
_t(r"aes[-_]?256", "AES-256", "SYMMETRIC", search=True)
_t(r"^(3des|des-ede3.*|des3|tripledes|desede.*)$|des-cbc3", "3DES", "SYMMETRIC", search=True)
_t(r"^des(-cbc|-ecb)?$", "DES", "SYMMETRIC")
_t(r"^(rc4|arcfour\d*)$|(^|[-_])rc4($|[-_])", "RC4", "SYMMETRIC", search=True)
_t(r"^chacha20(-poly1305)?(@openssh\.com)?$", "CHACHA20", "SYMMETRIC")
_t(r"^blowfish|^bf-", "BLOWFISH", "SYMMETRIC")
_t(r"^ecb$", "MODE-ECB", "SYMMETRIC")
# hashes
_t(r"^md5$|^hmac-md5.*", "MD5", "HASH")
_t(r"^sha-?1$|^sha$|^hmac-sha1.*|^sha1-.*", "SHA1", "HASH")
_t(r"^sha-?224$", "SHA-224", "HASH")
_t(r"^sha-?256$", "SHA-256", "HASH")
_t(r"^sha-?384$", "SHA-384", "HASH")
_t(r"^sha-?512$", "SHA-512", "HASH")
_t(r"^sha3-?\d*$", "SHA3", "HASH")


def resolve_token(token: str) -> Optional[tuple[str, str]]:
    t = token.strip().strip("'\"").lower()
    if not t:
        return None
    for pat, target, purpose, search in _TOKEN_RULES:
        m = pat.search(t) if search else pat.match(t)
        if m:
            alg = target(m) if callable(target) else target
            return alg, purpose
    return None


# OpenSSL-style cipher-suite decomposition: "ECDHE-RSA-AES128-GCM-SHA256"
def resolve_cipher_suite(suite: str) -> list[tuple[str, str]]:
    s = suite.upper().strip()
    out: list[tuple[str, str]] = []
    if s in ("", "ALL", "DEFAULT", "HIGH", "MEDIUM", "LOW", "EXPORT", "NULL", "!ANULL", "!ENULL"):
        return out
    s = s.lstrip("!+-@")
    if s.startswith("ECDHE"):
        out.append(("EC-P256", "KEY_EXCHANGE"))
    elif s.startswith(("DHE", "EDH")):
        out.append(("DH-2048", "KEY_EXCHANGE"))
    if "RSA" in s and not s.startswith(("AES", "CHACHA")):
        auth = s.startswith(("ECDHE", "DHE", "EDH"))
        out.append(("RSA-UNK", "SIGNATURE" if auth else "KEY_EXCHANGE"))
    elif s.startswith(("AES", "DES", "RC4", "CAMELLIA", "SEED", "IDEA")) and "RSA" not in s.split("-")[0]:
        out.append(("RSA-UNK", "KEY_EXCHANGE"))  # static-RSA key transport, e.g. AES128-SHA
    if "ECDSA" in s:
        out.append(("EC-P256", "SIGNATURE"))
    for key, alg in (("AES256", "AES-256"), ("AES128", "AES-128"), ("3DES", "3DES"), ("DES-CBC3", "3DES"),
                     ("RC4", "RC4"), ("CHACHA20", "CHACHA20")):
        if key in s:
            out.append((alg, "SYMMETRIC"))
            break
    if s.endswith("-MD5") or "-MD5" in s:
        out.append(("MD5", "HASH"))
    elif s.endswith("-SHA") or "-SHA-" in s or s.endswith("SHA1"):
        out.append(("SHA1", "HASH"))
    return out
