"""
Pattern-based QBOM scanner.

You raised the right objection: crawling an entire organisation's estate
with a tool that "understands everything" is itself a new attack surface,
and it doesn't scale past a few repos anyway. This scanner leans on a
different idea -- there are only a handful of *shapes* cryptographic usage
takes in code and configuration, because there are only a handful of APIs
and config grammars in the world that touch crypto:

  1. Library call sites with an explicit algorithm name/param
     (`RSA.generate_private_key(key_size=1024)`, `hashlib.md5(...)`,
     `Cipher(algorithms.AES(key), modes.ECB())`).
  2. Declarative config keys with enumerated values
     (sshd `KexAlgorithms`, nginx `ssl_protocols`/`ssl_ciphers`,
     Java `.keystore`/TLS provider configs, `openssl.cnf`).
  3. Wire artefacts that self-describe their algorithm
     (X.509 certificates' signature/public-key OIDs, JWT `alg` headers,
     PEM key headers).
  4. Free-text cipher-suite strings (OpenSSL suite names), which decompose
     into (2) via a fixed grammar.

So instead of "understand the whole codebase", the scanner runs a small,
fixed set of pattern extractors per file type and resolves every token it
finds through the catalog's classifier (`catalog.resolve_token` /
`resolve_cipher_suite` / the `*_id()` helpers). It never executes, imports,
or semantically interprets the target code -- pure text/AST-literal
inspection, which is also why it is safe to run with no elevated privileges
and no network access from within a CI job or a single developer's laptop
rather than a central crawler with broad credentials.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from . import catalog
from .model import Finding

TEXT_EXTS = {
    ".py", ".java", ".js", ".ts", ".go", ".rb", ".php", ".c", ".cpp", ".h", ".cs",
    ".conf", ".cnf", ".config", ".yaml", ".yml", ".json", ".ini", ".toml", ".xml",
    ".properties", ".pem", ".crt", ".cer", ".key", "",
}


def _snippet(line: str, limit=140) -> str:
    s = line.strip()
    return (s[:limit] + "...") if len(s) > limit else s


# ---------------------------------------------------------------------------
# 1. Python: parse with ast, look at call sites (no execution, ever)
# ---------------------------------------------------------------------------
_PY_HASH_NAMES = {"md5": "MD5", "sha1": "SHA1", "sha224": "SHA-224", "sha256": "SHA-256",
                   "sha384": "SHA-384", "sha512": "SHA-512", "sha3_256": "SHA3", "sha3_512": "SHA3"}

_PY_CIPHER_ATTR = {"AES": None, "TripleDES": "3DES", "DES": "DES", "Blowfish": "BLOWFISH",
                    "ARC4": "RC4", "ChaCha20": "CHACHA20"}


def scan_python(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return scan_generic_text(path, text)  # fall back to regex if it doesn't parse
    lines = text.splitlines()

    def add(catalog_id, purpose, node, source):
        ln = getattr(node, "lineno", 1)
        snip = _snippet(lines[ln - 1]) if 0 < ln <= len(lines) else ""
        findings.append(Finding(catalog_id, purpose, str(path), ln, snip, source))

    def kw(node: ast.Call, name):
        for k in node.keywords:
            if k.arg == name:
                return k.value
        return None

    def const_int(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, int) else None

    def const_str(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    def attr_chain(node) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = attr_chain(node.func) if isinstance(node.func, (ast.Attribute, ast.Name)) else ""
        low = callee.lower()

        # hashlib.md5() / hashlib.new("md5")
        if low.startswith("hashlib."):
            fn = low.split(".")[-1]
            if fn in _PY_HASH_NAMES:
                add(_PY_HASH_NAMES[fn], "HASH", node, "python-ast:hashlib")
            elif fn == "new" and node.args:
                s = const_str(node.args[0])
                if s and s.lower() in _PY_HASH_NAMES:
                    add(_PY_HASH_NAMES[s.lower()], "HASH", node, "python-ast:hashlib.new")

        # RSA.generate_private_key(key_size=...) / rsa.generate_private_key
        if low.endswith("generate_private_key") and "rsa" in low:
            ks = kw(node, "key_size")
            bits = const_int(ks) if ks else None
            add(catalog.rsa_id(bits), "UNKNOWN_ASYM", node, "python-ast:rsa.generate_private_key")

        if low.endswith("generate_private_key") and "dh" in low:
            add("DH-2048", "KEY_EXCHANGE", node, "python-ast:dh.generate_private_key")

        # ec.generate_private_key(ec.SECP256R1())
        if low.endswith("generate_private_key") and node.args:
            arg0 = node.args[0]
            curve_call = attr_chain(arg0.func) if isinstance(arg0, ast.Call) else attr_chain(arg0)
            if "secp" in curve_call.lower() or "sect" in curve_call.lower():
                add(catalog.curve_id(curve_call), "UNKNOWN_ASYM", node, "python-ast:ec.generate_private_key")
            elif curve_call.lower() in ("ed25519",):
                add("ED25519", "SIGNATURE", node, "python-ast:ed25519")
            elif curve_call.lower() in ("ed448",):
                add("ED448", "SIGNATURE", node, "python-ast:ed448")
            elif curve_call.lower() in ("x25519",):
                add("X25519", "KEY_EXCHANGE", node, "python-ast:x25519")
            elif curve_call.lower() in ("x448",):
                add("X448", "KEY_EXCHANGE", node, "python-ast:x448")

        # X25519PrivateKey.generate() / Ed25519PrivateKey.generate() / etc. (no curve arg passed)
        if low.endswith(".generate") and not node.args:
            if "x25519privatekey" in low:
                add("X25519", "KEY_EXCHANGE", node, "python-ast:x25519.generate")
            elif "x448privatekey" in low:
                add("X448", "KEY_EXCHANGE", node, "python-ast:x448.generate")
            elif "ed25519privatekey" in low:
                add("ED25519", "SIGNATURE", node, "python-ast:ed25519.generate")
            elif "ed448privatekey" in low:
                add("ED448", "SIGNATURE", node, "python-ast:ed448.generate")

        # algorithms.AES(key) / algorithms.TripleDES(key) / modes.ECB()
        if callee in ("algorithms.AES", "algorithms.AES128", "algorithms.AES256"):
            bits = None
            if node.args and isinstance(node.args[0], ast.Name):
                bits = None  # can't know key length from a variable; flag unknown
            add(catalog.aes_id(bits), "SYMMETRIC", node, "python-ast:algorithms.AES")
        elif callee.startswith("algorithms.") and callee.split(".")[-1] in _PY_CIPHER_ATTR:
            mapped = _PY_CIPHER_ATTR[callee.split(".")[-1]]
            if mapped:
                add(mapped, "SYMMETRIC", node, f"python-ast:{callee}")
        if callee.endswith("modes.ECB"):
            add("MODE-ECB", "SYMMETRIC", node, "python-ast:modes.ECB")

        # pycryptodome-style: Crypto.Cipher.DES.new / Crypto.Hash.MD5.new
        if ".new" in low:
            for name, cid in (("des3", "3DES"), ("des", "DES"), ("arc4", "RC4"), ("blowfish", "BLOWFISH")):
                if f".{name}." in low or low.startswith(f"{name}."):
                    add(cid, "SYMMETRIC", node, "python-ast:pycryptodome")

        # liboqs-python idiom: oqs.KeyEncapsulation("ML-KEM-768") / oqs.Signature("ML-DSA-65")
        # -- this is what a *post-quantum migration* looks like at the call-site level, so the
        # scanner needs to recognise it for the same reason it recognises the classical calls
        # above: a rescan after remediation has to be able to see the replacement, not just the
        # absence of the old call. Matches the bare method name too (from oqs import Signature).
        last = callee.split(".")[-1] if callee else ""
        if last in ("KeyEncapsulation", "Signature") and node.args:
            alg_name = const_str(node.args[0]) or (kw(node, "alg_name") and const_str(kw(node, "alg_name")))
            if alg_name:
                resolved = catalog.resolve_token(alg_name)
                if resolved:
                    purpose = "KEY_EXCHANGE" if last == "KeyEncapsulation" else "SIGNATURE"
                    add(resolved[0], purpose, node, f"python-ast:oqs.{last}")

    # module-level ssl.PROTOCOL_* / ssl.wrap_socket(ssl_version=...) constants aren't Call nodes
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ssl":
            tok = node.attr.replace("PROTOCOL_", "").replace("_", ".").lower()
            resolved = catalog.resolve_token(tok)
            if resolved and catalog.get(resolved[0]).kind == "protocol":
                add(resolved[0], "PROTOCOL", node, "python-ast:ssl.PROTOCOL_*")

    return findings


# ---------------------------------------------------------------------------
# 2 & 4. Generic line-oriented regex scan for everything else: Java/JS/Go/
#    config files/cipher-suite strings. Deliberately simple and explainable.
# ---------------------------------------------------------------------------
_GENERIC_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bnew\s+RSAKeyGenParameterSpec\s*\(\s*(\d+)", re.I), "java-rsa-keygen"),
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"RSA"', re.I), "java-rsa-generic"),
    # BouncyCastle-PQC idiom: KeyPairGenerator.getInstance("ML-DSA") / ("Kyber768", "BCPQC") / etc.
    # -- same reasoning as the liboqs-python rule above: a Java PQC migration needs to be
    # recognisable by a rescan, not just invisible once the RSA call is gone.
    (re.compile(
        r'KeyPairGenerator\.getInstance\(\s*"(ML-DSA[\w-]*|ML-KEM[\w-]*|Dilithium\d*|Kyber\d*|'
        r'SLH-DSA[\w-]*|SPHINCS\+?[\w-]*|Falcon\d*|FN-DSA[\w-]*)"', re.I), "java-pqc-keygen"),
    (re.compile(r'initialize\(\s*(\d+)\s*\)', re.I), "java-keygen-initialize"),
    (re.compile(r'MessageDigest\.getInstance\(\s*"([\w-]+)"', re.I), "java-messagedigest"),
    (re.compile(r'Cipher\.getInstance\(\s*"([\w/]+)"', re.I), "java-cipher"),
    (re.compile(r"crypto\.createHash\(\s*['\"]([\w-]+)['\"]", re.I), "node-createhash"),
    (re.compile(r"crypto\.createCipheriv?\(\s*['\"]([\w-]+)['\"]", re.I), "node-createcipher"),
    (re.compile(r"(?:hashlib\.)?\bmd5\(|MD5\(", re.I), "generic-md5-call"),
    (re.compile(r"DES\.new\(|des\.NewCipher\(", re.I), "generic-des-call"),
    (re.compile(r"rsa\.GenerateKey\(\s*[\w.]+\s*,\s*(\d+)\)", re.I), "go-rsa-generatekey"),
    (re.compile(r"^\s*KexAlgorithms\s+(.+)", re.I), "sshd-kex"),
    (re.compile(r"^\s*Ciphers\s+(.+)", re.I), "sshd-ciphers"),
    (re.compile(r"^\s*MACs\s+(.+)", re.I), "sshd-macs"),
    (re.compile(r"^\s*HostKeyAlgorithms\s+(.+)", re.I), "sshd-hostkeys"),
    (re.compile(r"^\s*ssl_protocols\s+(.+);", re.I), "nginx-ssl-protocols"),
    (re.compile(r"^\s*ssl_ciphers\s+[\"']?([^;\"']+)", re.I), "nginx-ssl-ciphers"),
    # ssl_ecdh_curve is where nginx configures (hybrid) key-exchange groups -- e.g.
    # "X25519:X25519MLKEM768" enables a post-quantum hybrid group alongside classical X25519.
    (re.compile(r"^\s*ssl_ecdh_curve\s+([^;]+);", re.I), "nginx-ssl-ecdh-curve"),
    (re.compile(r"^\s*SSLProtocol\s+(.+)", re.I), "apache-sslprotocol"),
    (re.compile(r"^\s*SSLCipherSuite\s+(.+)", re.I), "apache-sslcipher"),
    (re.compile(r'"alg"\s*:\s*"([\w-]+)"', re.I), "jwt-alg-header"),
    (re.compile(r"^\s*default_bits\s*=\s*(\d+)", re.I), "openssl-cnf-default-bits"),
    (re.compile(r"^\s*Protocol\s*=\s*(.+)", re.I | re.M), "openssl-cnf-protocol"),
    (re.compile(r"^\s*CipherString\s*=\s*(.+)", re.I), "openssl-cnf-cipherstring"),
    # OpenSSL 3.2+ [system_default_sect] Groups= -- same idea as nginx's ssl_ecdh_curve.
    (re.compile(r"^\s*Groups\s*=\s*(.+)", re.I), "openssl-cnf-groups"),
]


def scan_generic_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pat, rule in _GENERIC_RULES:
            m = pat.search(line)
            if not m:
                continue
            findings.extend(_resolve_generic_match(rule, m, path, lineno, line))
    _correlate_tls13_hybrid(findings)
    return findings


def _correlate_tls13_hybrid(findings: list[Finding]) -> None:
    """TLS 1.3 is catalogued SHOR because it *defaults* to classical key
    exchange -- but that default is overridden by a same-file hybrid PQ
    group directive (nginx ssl_ecdh_curve / OpenSSL Groups=, both of which
    resolve to a HYBRID-KEM finding). If both are present in the same file,
    the protocol-version finding is relabelled TLS1.3-HYBRID in place,
    rather than silently dropped, so the report still shows a TLS 1.3 line
    -- just a correctly-classified one. This is a same-file correlation
    only: it does not claim anything about what a client actually
    negotiates at runtime (see README limitations)."""
    if not any(f.catalog_id == "HYBRID-KEM" for f in findings):
        return
    for f in findings:
        if f.catalog_id == "TLS1.3":
            f.catalog_id = "TLS1.3-HYBRID"


def _emit(cid, purpose, path, lineno, line, rule) -> Finding:
    return Finding(cid, purpose, str(path), lineno, _snippet(line), f"regex:{rule}")


def _resolve_generic_match(rule, m, path, lineno, line) -> list[Finding]:
    out = []
    if rule == "java-rsa-keygen" or rule == "go-rsa-generatekey":
        out.append(_emit(catalog.rsa_id(int(m.group(1))), "UNKNOWN_ASYM", path, lineno, line, rule))
    elif rule == "java-rsa-generic":
        out.append(_emit("RSA-UNK", "UNKNOWN_ASYM", path, lineno, line, rule))
    elif rule == "java-pqc-keygen":
        resolved = catalog.resolve_token(m.group(1))
        if resolved:
            out.append(_emit(resolved[0], resolved[1], path, lineno, line, rule))
    elif rule == "java-keygen-initialize":
        bits = int(m.group(1))
        if bits in (512, 1024, 1536, 2048, 3072, 4096):
            out.append(_emit(catalog.rsa_id(bits), "UNKNOWN_ASYM", path, lineno, line, rule))
    elif rule == "java-messagedigest":
        hid = catalog.hash_id(m.group(1))
        if hid:
            out.append(_emit(hid, "HASH", path, lineno, line, rule))
    elif rule == "java-cipher":
        spec = m.group(1)
        first = spec.split("/")[0]
        resolved = catalog.resolve_token(first)
        if resolved:
            out.append(_emit(resolved[0], "SYMMETRIC", path, lineno, line, rule))
        if "ECB" in spec.upper():
            out.append(_emit("MODE-ECB", "SYMMETRIC", path, lineno, line, rule))
    elif rule == "node-createhash":
        hid = catalog.hash_id(m.group(1))
        if hid:
            out.append(_emit(hid, "HASH", path, lineno, line, rule))
    elif rule == "node-createcipher":
        resolved = catalog.resolve_token(m.group(1))
        if resolved:
            out.append(_emit(resolved[0], "SYMMETRIC", path, lineno, line, rule))
    elif rule == "generic-md5-call":
        out.append(_emit("MD5", "HASH", path, lineno, line, rule))
    elif rule == "generic-des-call":
        out.append(_emit("DES", "SYMMETRIC", path, lineno, line, rule))
    elif rule in ("sshd-kex", "sshd-ciphers", "sshd-macs", "sshd-hostkeys"):
        for tok in re.split(r"[,\s]+", m.group(1).strip()):
            resolved = catalog.resolve_token(tok)
            if resolved:
                out.append(_emit(resolved[0], resolved[1], path, lineno, line, rule))
    elif rule == "nginx-ssl-protocols":
        for tok in m.group(1).split():
            resolved = catalog.resolve_token(tok)
            if resolved:
                out.append(_emit(resolved[0], "PROTOCOL", path, lineno, line, rule))
    elif rule == "nginx-ssl-ecdh-curve":
        for tok in m.group(1).split(":"):
            resolved = catalog.resolve_token(tok.strip())
            if resolved:
                out.append(_emit(resolved[0], "KEY_EXCHANGE", path, lineno, line, rule))
    elif rule in ("nginx-ssl-ciphers", "apache-sslcipher"):
        for suite in re.split(r"[:,]", m.group(1)):
            suite = suite.strip()
            for cid, purpose in catalog.resolve_cipher_suite(suite):
                out.append(_emit(cid, purpose, path, lineno, line, rule))
    elif rule == "apache-sslprotocol":
        for tok in re.split(r"[,\s]+", m.group(1).strip()):
            resolved = catalog.resolve_token(tok.lstrip("+-"))
            if resolved:
                out.append(_emit(resolved[0], "PROTOCOL", path, lineno, line, rule))
    elif rule == "jwt-alg-header":
        resolved = catalog.resolve_token(m.group(1))
        if resolved:
            out.append(_emit(resolved[0], "SIGNATURE", path, lineno, line, rule))
    elif rule == "openssl-cnf-default-bits":
        out.append(_emit(catalog.rsa_id(int(m.group(1))), "UNKNOWN_ASYM", path, lineno, line, rule))
    elif rule == "openssl-cnf-protocol":
        resolved = catalog.resolve_token(m.group(1).strip())
        if resolved:
            out.append(_emit(resolved[0], "PROTOCOL", path, lineno, line, rule))
    elif rule == "openssl-cnf-cipherstring":
        for suite in re.split(r"[:,]", m.group(1)):
            for cid, purpose in catalog.resolve_cipher_suite(suite.strip()):
                out.append(_emit(cid, purpose, path, lineno, line, rule))
    elif rule == "openssl-cnf-groups":
        for tok in m.group(1).split(":"):
            resolved = catalog.resolve_token(tok.strip())
            if resolved:
                out.append(_emit(resolved[0], "KEY_EXCHANGE", path, lineno, line, rule))
    return out


# ---------------------------------------------------------------------------
# 3. X.509 certificates & PEM keys: parse structure via `cryptography`, never
#    just regex-guess (signature/key algorithm is unambiguous once parsed).
# ---------------------------------------------------------------------------
def scan_pem_or_cert(path: Path, raw: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    except ImportError:
        return findings

    # ML-DSA / ML-KEM support landed in `cryptography` 47 -- feature-detect so
    # this scanner keeps working (just without recognising PQ keys/certs) on
    # older installs rather than hard-requiring a very recent release.
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        _MLDSA_TYPES = {
            mldsa.MLDSA44PublicKey: "ML-DSA", mldsa.MLDSA65PublicKey: "ML-DSA",
            mldsa.MLDSA87PublicKey: "ML-DSA",
        }
        _MLDSA_PRIV_TYPES = tuple({mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey})
    except ImportError:
        _MLDSA_TYPES, _MLDSA_PRIV_TYPES = {}, ()
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
        _MLKEM_TYPES = {}
        _MLKEM_PRIV_TYPES = {}
        for bits in (512, 768, 1024):
            pub_cls = getattr(mlkem, f"MLKEM{bits}PublicKey", None)
            priv_cls = getattr(mlkem, f"MLKEM{bits}PrivateKey", None)
            if pub_cls is not None:
                _MLKEM_TYPES[pub_cls] = f"ML-KEM-{bits}"
            if priv_cls is not None:
                _MLKEM_PRIV_TYPES[priv_cls] = f"ML-KEM-{bits}"
    except ImportError:
        _MLKEM_TYPES, _MLKEM_PRIV_TYPES = {}, {}

    def classify_pubkey(pub) -> tuple[str, str] | None:
        if isinstance(pub, rsa.RSAPublicKey):
            return catalog.rsa_id(pub.key_size), "UNKNOWN_ASYM"
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return catalog.curve_id(pub.curve.name), "UNKNOWN_ASYM"
        if isinstance(pub, dsa.DSAPublicKey):
            return "DSA", "SIGNATURE"
        if isinstance(pub, ed25519.Ed25519PublicKey):
            return "ED25519", "SIGNATURE"
        if isinstance(pub, ed448.Ed448PublicKey):
            return "ED448", "SIGNATURE"
        for t, cid in _MLDSA_TYPES.items():
            if isinstance(pub, t):
                return cid, "SIGNATURE"
        for t, cid in _MLKEM_TYPES.items():
            if isinstance(pub, t):
                return cid, "KEY_EXCHANGE"
        return None

    try:
        cert = x509.load_pem_x509_certificate(raw)
        pk = classify_pubkey(cert.public_key())
        if pk:
            findings.append(Finding(pk[0], pk[1], str(path), 1, "x509 public key", "x509-cert:public_key"))
        sig_hash = getattr(cert.signature_hash_algorithm, "name", None)
        if sig_hash:
            hid = catalog.hash_id(sig_hash)
            if hid:
                findings.append(Finding(hid, "SIGNATURE", str(path), 1, f"x509 signature hash: {sig_hash}",
                                         "x509-cert:signature_hash"))
        return findings
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(raw, password=None)
        pk = None
        if isinstance(key, rsa.RSAPrivateKey):
            pk = (catalog.rsa_id(key.key_size), "UNKNOWN_ASYM")
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            pk = (catalog.curve_id(key.curve.name), "UNKNOWN_ASYM")
        elif isinstance(key, dsa.DSAPrivateKey):
            pk = ("DSA", "SIGNATURE")
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            pk = ("ED25519", "SIGNATURE")
        elif isinstance(key, ed448.Ed448PrivateKey):
            pk = ("ED448", "SIGNATURE")
        elif _MLDSA_PRIV_TYPES and isinstance(key, _MLDSA_PRIV_TYPES):
            pk = ("ML-DSA", "SIGNATURE")
        elif _MLKEM_PRIV_TYPES and isinstance(key, tuple(_MLKEM_PRIV_TYPES.keys())):
            for t, cid in _MLKEM_PRIV_TYPES.items():
                if isinstance(key, t):
                    pk = (cid, "KEY_EXCHANGE")
                    break
        if pk:
            findings.append(Finding(pk[0], pk[1], str(path), 1, "PEM private key", "pem:private_key"))
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", "target"}


def scan_file(path: Path) -> list[Finding]:
    if path.suffix.lower() in (".pem", ".crt", ".cer", ".key"):
        try:
            raw = path.read_bytes()
            if b"-----BEGIN" in raw:
                return scan_pem_or_cert(path, raw)
        except OSError:
            return []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    if b"-----BEGIN" in text.encode(errors="ignore")[:64] or "-----BEGIN" in text[:200]:
        found = scan_pem_or_cert(path, text.encode())
        if found:
            return found
    if path.suffix == ".py":
        return scan_python(path, text)
    return scan_generic_text(path, text)


def scan_directory(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in TEXT_EXTS and p.name.lower() not in ("sshd_config", "openssl.cnf", "ssh_config"):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        findings.extend(scan_file(p))
    return findings
