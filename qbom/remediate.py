"""
Simulated infra remediation for the QBOM engagement loop.

This is deliberately the least "generic" module in the framework, and that
is on purpose. Every other module (catalog/scanner/risk/report) works on
*any* codebase you point it at. Actually applying a fix does not generalise
the same way -- "replace this RSA-1024 signing key" is a different concrete
edit in every codebase, in every language, under every team's change
process. A real deployment plugs the org's own remediation playbooks or
CI/CD automation in at this exact seam (see `RemediationAction.apply`).

What ships here is a working demonstration of that seam against the bundled
`samples/vulnerable-app` fixture, so `qbom engage` is runnable end-to-end
without a human in the loop for a hackathon demo -- while still being
*honest* about what it fixes and what it can't:

  * Classically-broken hashes/ciphers and clearly-wrong config lines
    (MD5/SHA-1, DES/3DES/RC4, ECB mode, legacy TLS/SSH protocol versions
    and key-exchange groups) are mechanically fixable by any competent
    infra team in an afternoon, so those are auto-remediated here.
  * Shor-vulnerable asymmetric primitives (RSA/ECDSA/EdDSA/X25519) are
    NOT patched with a bigger key size -- a bigger RSA key is still
    Shor-breakable. They are migrated to a post-quantum equivalent
    (ML-KEM / ML-DSA, via the liboqs-python API shape) so the *next scan*
    can genuinely verify the migration happened, not just that the old
    string is gone.
  * X.509 certificates are never hand-edited (you cannot sed a signature).
    The legacy partner cert is re-issued, exactly as a PKI team would.
  * A handful of items are left deliberately unfixed and explained (see
    RESIDUAL_NOTES below) -- e.g. there is no standardised post-quantum
    SSH host-key algorithm yet, so ssh-ed25519 stays. A tool that claims
    to fix everything is lying; the engagement report says so explicitly.

Every `apply()` is idempotent: safe to call every iteration, a no-op once
already applied. Nothing here ever touches `samples/` -- only the working
copy under the engagement's `work_root`.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


@dataclass
class ChangeRecord:
    action_id: str
    title: str
    files_changed: list
    summary: str
    resolves: list
    applied_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RemediationAction:
    id: str
    title: str
    resolves: frozenset          # catalog_ids this action is expected to address
    rationale: str
    fn: Callable[[Path], Optional[ChangeRecord]]

    def apply(self, work_root: Path) -> Optional[ChangeRecord]:
        return self.fn(work_root)


# ---------------------------------------------------------------------------
# Working-copy management -- remediation NEVER touches the original tree.
# ---------------------------------------------------------------------------
def prepare_workdir(source: str | Path, work_root: Path) -> Path:
    """Copy `source` into `work_root` once (idempotent). Returns work_root."""
    work_root = Path(work_root)
    marker = work_root / ".qbom-workdir"
    if not marker.exists():
        if work_root.exists():
            shutil.rmtree(work_root)
        shutil.copytree(Path(source), work_root)
        marker.write_text(f"copied from {source} at {datetime.now(timezone.utc).isoformat()}\n")
    return work_root


def _replace_once(path: Path, old: str, new: str) -> bool:
    if not path.exists():
        return False
    text = path.read_text()
    if old not in text:
        return False
    path.write_text(text.replace(old, new))
    return True


def _ensure_import(path: Path, import_line: str) -> None:
    text = path.read_text()
    if import_line in text:
        return
    lines = text.splitlines(keepends=True)
    # insert after the existing import block (or at the top if none)
    idx = 0
    for i, ln in enumerate(lines):
        if ln.startswith(("import ", "from ")):
            idx = i + 1
        elif ln.strip() and idx > 0:
            break
    lines.insert(idx, import_line + "\n")
    path.write_text("".join(lines))


# ---------------------------------------------------------------------------
# Fixers -- each one is specific to the bundled samples/vulnerable-app
# fixture. See module docstring: this is the seam a real deployment swaps
# for its own playbooks.
# ---------------------------------------------------------------------------
def _fix_broken_hashes(root: Path) -> Optional[ChangeRecord]:
    files = []
    if _replace_once(root / "web-service/crypto-utils.js",
                      'crypto.createHash("md5")', 'crypto.createHash("sha256")'):
        files.append("web-service/crypto-utils.js")
    if _replace_once(root / "app/payments/service.py",
                      "hashlib.md5(payload)", "hashlib.sha256(payload)"):
        files.append("app/payments/service.py")
    if _replace_once(root / "app/legacy/hash.py", "hashlib.sha1(data)", "hashlib.sha256(data)"):
        files.append("app/legacy/hash.py")
    if _replace_once(root / "app/legacy/hash.py",
                      "hashlib.md5(pw.encode())", "hashlib.sha256(pw.encode())"):
        files.append("app/legacy/hash.py")
    if _replace_once(root / "app/api/AuthService.java",
                      'MessageDigest.getInstance("SHA1")', 'MessageDigest.getInstance("SHA-256")'):
        files.append("app/api/AuthService.java")
    if not files:
        return None
    return ChangeRecord(
        "fix-broken-hashes", "Replace MD5/SHA-1 with SHA-256", sorted(set(files)),
        "Swapped classically-broken digest calls for SHA-256 at each call site. "
        "No key-management change needed -- this is a same-shape replacement.",
        ["MD5", "SHA1"],
    )


def _fix_symmetric_ciphers(root: Path) -> Optional[ChangeRecord]:
    files = []
    if _replace_once(root / "web-service/crypto-utils.js",
                      'crypto.createCipheriv("des-ede3-cbc", key, iv)',
                      'crypto.createCipheriv("aes-256-gcm", key, iv)'):
        files.append("web-service/crypto-utils.js")
    if _replace_once(root / "app/api/AuthService.java",
                      'Cipher.getInstance("DES/ECB/PKCS5Padding")',
                      'Cipher.getInstance("AES/GCM/NoPadding")'):
        files.append("app/api/AuthService.java")
    old_fn = (
        "def encrypt_card_batch(key, data):\n"
        "    cipher = Cipher(algorithms.AES(key), modes.ECB())\n"
        "    encryptor = cipher.encryptor()\n"
        "    return encryptor.update(data) + encryptor.finalize()\n"
    )
    new_fn = (
        "def encrypt_card_batch(key, nonce, data):\n"
        "    # AEAD mode, matching the pattern already used in app/crypto/vault.py\n"
        "    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))\n"
        "    encryptor = cipher.encryptor()\n"
        "    return encryptor.update(data) + encryptor.finalize()\n"
    )
    if _replace_once(root / "app/payments/service.py", old_fn, new_fn):
        files.append("app/payments/service.py")
    if not files:
        return None
    return ChangeRecord(
        "fix-symmetric-ciphers", "Replace DES/3DES and ECB mode with AES-256-GCM", sorted(set(files)),
        "DES/3DES block ciphers and unauthenticated ECB mode replaced with AES-256 in an "
        "authenticated (GCM) mode. `encrypt_card_batch` now takes an explicit nonce, matching "
        "the AEAD pattern already used elsewhere in this codebase.",
        ["DES", "3DES", "MODE-ECB"],
    )


def _fix_sshd_config(root: Path) -> Optional[ChangeRecord]:
    p = root / "config/sshd_config"
    changed = []
    changed.append(_replace_once(
        p, "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256,sntrup761x25519-sha512@openssh.com",
        "KexAlgorithms sntrup761x25519-sha512@openssh.com"))
    changed.append(_replace_once(
        p, "Ciphers aes256-gcm@openssh.com,3des-cbc,chacha20-poly1305@openssh.com",
        "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"))
    changed.append(_replace_once(p, "MACs hmac-sha1,hmac-sha2-256", "MACs hmac-sha2-256,hmac-sha2-512"))
    changed.append(_replace_once(p, "HostKeyAlgorithms ssh-rsa,ssh-ed25519", "HostKeyAlgorithms ssh-ed25519"))
    if not any(changed):
        return None
    return ChangeRecord(
        "fix-sshd-config", "Harden sshd_config key exchange, ciphers, MACs, host keys",
        ["config/sshd_config"],
        "Dropped diffie-hellman-group1-sha1 and curve25519-sha256 from KexAlgorithms, keeping "
        "the already-present hybrid PQ group (sntrup761x25519). Dropped 3des-cbc and hmac-sha1. "
        "Dropped the legacy ssh-rsa host key, keeping ssh-ed25519 -- OpenSSH has no standardised "
        "post-quantum host-key algorithm yet, so this one item is a documented residual, not a fix.",
        ["DH-SUB2048", "X25519", "3DES", "SHA1", "RSA-UNK"],
    )


def _fix_nginx_tls(root: Path) -> Optional[ChangeRecord]:
    p = root / "config/nginx.conf"
    old = (
        '    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n'
        '    ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:RC4-MD5";\n'
    )
    new = (
        '    ssl_protocols TLSv1.3;\n'
        '    ssl_ecdh_curve X25519:X25519MLKEM768;\n'
        '    ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";\n'
    )
    if not _replace_once(p, old, new):
        return None
    return ChangeRecord(
        "fix-nginx-tls", "Restrict nginx to TLS 1.3 with a hybrid PQ key-exchange group",
        ["config/nginx.conf"],
        "Dropped TLS 1.0/1.1/1.2 entirely. Added a hybrid classical+ML-KEM group "
        "(X25519MLKEM768) alongside the classical fallback. Replaced the legacy dash-separated "
        "cipher-suite string (which implied static-RSA key transport and still listed RC4/3DES) "
        "with the standard TLS 1.3 suite names.",
        ["TLS1.0", "TLS1.1", "TLS1.2", "RC4", "MD5", "3DES", "SHA1", "RSA-UNK", "EC-P256", "AES-128"],
    )


def _fix_openssl_cnf(root: Path) -> Optional[ChangeRecord]:
    p = root / "config/openssl.cnf"
    changed = []
    changed.append(_replace_once(p, "default_bits = 1024", "default_bits = 3072"))
    changed.append(_replace_once(
        p, "CipherString = DEFAULT:!aNULL:!eNULL:RC4-SHA:AES256-SHA256",
        "CipherString = HIGH:!aNULL:!eNULL"))
    changed.append(_replace_once(p, "Protocol = TLSv1.2", "Protocol = TLSv1.3"))
    if p.exists() and "Groups = " not in p.read_text():
        with p.open("a") as fh:
            fh.write("Groups = X25519:X25519MLKEM768\n")
        changed.append(True)
    if not any(changed):
        return None
    return ChangeRecord(
        "fix-openssl-cnf", "Raise default_bits, drop RC4, add a hybrid PQ group", ["config/openssl.cnf"],
        "default_bits raised to 3072 (classical hygiene only -- RSA of any size stays "
        "Shor-vulnerable; this does not by itself move the readiness needle, and the report "
        "says so). CipherString no longer names RC4/legacy static-RSA suites. Added a "
        "Groups= directive enabling a hybrid ML-KEM group (OpenSSL 3.2+).",
        ["RSA-SUB2048", "RC4", "SHA1", "RSA-UNK", "TLS1.2"],
    )


def _reissue_cert(crt: Path, key: Path, common_name: str) -> Optional[tuple[bool, str]]:
    """Re-issue a self-signed cert+key pair in place. Prefers a genuine
    ML-DSA-65 (FIPS 204) certificate -- `cryptography` >= 47 -- so the next
    scan finds a real post-quantum signature, not a still-classical one;
    falls back to EC P-256/SHA-256 (today's best-practice classical
    baseline) on older installs where ML-DSA X.509 support isn't present.
    Returns (used_pqc, profile_label) or None if nothing to do."""
    if not crt.exists() or not key.exists():
        return None
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    try:
        existing = x509.load_pem_x509_certificate(crt.read_bytes())
    except Exception:
        existing = None

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        if existing is not None and isinstance(existing.public_key(), mldsa.MLDSA65PublicKey):
            return None  # already reissued as ML-DSA
        private_key = mldsa.MLDSA65PrivateKey.generate()
        sign_kwargs = {}
        used_pqc, profile = True, "ML-DSA-65 (FIPS 204)"
    except ImportError:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        if existing is not None and isinstance(existing.public_key(), ec.EllipticCurvePublicKey):
            return None  # already reissued as EC
        private_key = ec.generate_private_key(ec.SECP256R1())
        sign_kwargs = {"algorithm": hashes.SHA256()}
        used_pqc, profile = False, "EC P-256 / SHA-256"

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=365))
        .sign(private_key, sign_kwargs.get("algorithm"))
    )
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return used_pqc, profile


def _reissue_legacy_partner_cert(root: Path) -> Optional[ChangeRecord]:
    result = _reissue_cert(root / "certs/legacy_partner.crt", root / "certs/legacy_partner.key",
                            "legacy-partner.example.com")
    if result is None:
        return None
    used_pqc, profile = result
    return ChangeRecord(
        "reissue-legacy-partner-cert", f"Re-issue legacy_partner.crt as {profile}",
        ["certs/legacy_partner.crt", "certs/legacy_partner.key"],
        "A certificate's signature algorithm cannot be hand-edited -- it is re-issued, exactly "
        "as a PKI/CA team would. " + (
            "Signed with ML-DSA-65 (FIPS 204): this is a genuine post-quantum-safe certificate, "
            "not an interim step."
            if used_pqc else
            "Re-issued as EC P-256/SHA-256 (today's classical best practice); ML-DSA X.509 "
            "support requires `cryptography` >= 47, not present in this environment, so this "
            "closes the classically-broken RSA-1024/SHA-1 gap but is still Shor-vulnerable."
        ),
        ["RSA-SUB2048", "SHA1"],
    )


def _reissue_modern_service_cert(root: Path) -> Optional[ChangeRecord]:
    """A second, later-wave reissuance: modern_service.crt was already
    today's best practice (EC P-256/SHA-256), so fixing it isn't urgent --
    it's the last item in ACTIONS on purpose, only reached once the org has
    kept accepting the loop past the genuinely urgent findings."""
    result = _reissue_cert(root / "certs/modern_service.crt", root / "certs/modern_service.key",
                            "api.example.com")
    if result is None:
        return None
    used_pqc, profile = result
    if not used_pqc:
        return None  # not worth a change record if we can't actually improve on EC P-256
    return ChangeRecord(
        "reissue-modern-service-cert", f"Re-issue modern_service.crt as {profile}",
        ["certs/modern_service.crt", "certs/modern_service.key"],
        "modern_service.crt was already today's classical best practice (EC P-256/SHA-256) -- "
        "not urgent, which is why this is the lowest-priority action in the catalog. Re-issued "
        "as ML-DSA-65 now that PQ certificate tooling is available, completing the wave.",
        ["EC-P256"],
    )


def _migrate_payments_signing_key(root: Path) -> Optional[ChangeRecord]:
    p = root / "app/payments/service.py"
    if not _replace_once(
        p,
        "def generate_signing_key():\n"
        "    # Legacy key still used for backward-compat with a 2019 partner integration\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=1024)\n",
        "def generate_signing_key():\n"
        "    # Migrated off RSA-1024: a bigger RSA key would still be Shor-breakable.\n"
        "    return oqs.Signature(\"ML-DSA-65\")\n",
    ):
        return None
    _ensure_import(p, "import oqs  # liboqs-python; ML-DSA-65 = FIPS 204 signing")
    return ChangeRecord(
        "migrate-payments-signing-key", "Migrate payments signing key RSA-1024 -> ML-DSA-65",
        ["app/payments/service.py"],
        "RSA is Shor-breakable at any key size, so this is a real algorithm migration, not a "
        "bigger key: signing now uses ML-DSA-65 (FIPS 204) via the liboqs-python API shape.",
        ["RSA-SUB2048"],
    )


def _migrate_payments_tls_key(root: Path) -> Optional[ChangeRecord]:
    p = root / "app/payments/service.py"
    if not _replace_once(
        p,
        "def generate_new_tls_key():\n    return ec.generate_private_key(ec.SECP256R1())\n",
        "def generate_new_tls_key():\n"
        "    # Hybrid classical+PQ key exchange, not pure ECC (ECC alone is Shor-breakable)\n"
        "    return oqs.KeyEncapsulation(\"X25519MLKEM768\")\n",
    ):
        return None
    _ensure_import(p, "import oqs  # liboqs-python; X25519MLKEM768 = hybrid PQ key exchange")
    return ChangeRecord(
        "migrate-payments-tls-key", "Migrate payments TLS key EC P-256 -> hybrid X25519+ML-KEM-768",
        ["app/payments/service.py"], "Same reasoning as the signing key: EC P-256 alone is "
        "Shor-breakable, so the replacement is a hybrid KEM, not a different curve.",
        ["EC-P256"],
    )


def _migrate_vault_kex(root: Path) -> Optional[ChangeRecord]:
    p = root / "app/crypto/vault.py"
    if not _replace_once(
        p, "def new_kex_key():\n    return x25519.X25519PrivateKey.generate()\n",
        "def new_kex_key():\n"
        "    # Hybrid classical+PQ key exchange (X25519 alone is Shor-breakable)\n"
        "    return oqs.KeyEncapsulation(\"X25519MLKEM768\")\n",
    ):
        return None
    _ensure_import(p, "import oqs  # liboqs-python; X25519MLKEM768 = hybrid PQ key exchange")
    return ChangeRecord(
        "migrate-vault-kex", "Migrate vault key-exchange X25519 -> hybrid X25519+ML-KEM-768",
        ["app/crypto/vault.py"], "X25519 alone is Shor-breakable; the vault service now "
        "negotiates a hybrid classical+PQ group.", ["X25519"],
    )


def _migrate_vault_signing(root: Path) -> Optional[ChangeRecord]:
    p = root / "app/crypto/vault.py"
    if not _replace_once(
        p, "def new_signing_key():\n    return ed25519.Ed25519PrivateKey.generate()\n",
        "def new_signing_key():\n"
        "    # Ed25519 alone is Shor-breakable; ML-DSA-65 is the FIPS 204 PQ signature scheme\n"
        "    return oqs.Signature(\"ML-DSA-65\")\n",
    ):
        return None
    _ensure_import(p, "import oqs  # liboqs-python; ML-DSA-65 = FIPS 204 signing")
    return ChangeRecord(
        "migrate-vault-signing", "Migrate vault signing key Ed25519 -> ML-DSA-65",
        ["app/crypto/vault.py"], "Ed25519 is Shor-breakable; vault signing now uses ML-DSA-65.",
        ["ED25519"],
    )


def _migrate_auth_service_keygen(root: Path) -> Optional[ChangeRecord]:
    p = root / "app/api/AuthService.java"
    if not _replace_once(
        p,
        '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
        '        kpg.initialize(2048);\n',
        '        // Migrated off RSA: a bigger key would still be Shor-breakable (BouncyCastle-PQC provider)\n'
        '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");\n',
    ):
        return None
    return ChangeRecord(
        "migrate-auth-service-keygen", "Migrate AuthService key generation RSA -> ML-DSA",
        ["app/api/AuthService.java"],
        "Same reasoning as the Python signing-key migrations: RSA is Shor-breakable at any "
        "size, so the fix is an algorithm swap (BouncyCastle-PQC ML-DSA), not a bigger key.",
        ["RSA-UNK", "RSA-2048"],
    )


ACTIONS: list[RemediationAction] = [
    RemediationAction("fix-broken-hashes", "Replace MD5/SHA-1 with SHA-256",
                       frozenset({"MD5", "SHA1"}),
                       "Classically broken today, independent of any quantum timeline.",
                       _fix_broken_hashes),
    RemediationAction("fix-symmetric-ciphers", "Replace DES/3DES/ECB with AES-256-GCM",
                       frozenset({"DES", "3DES", "MODE-ECB"}),
                       "Classically broken/unauthenticated; fixable without any protocol redesign.",
                       _fix_symmetric_ciphers),
    RemediationAction("fix-sshd-config", "Harden sshd_config",
                       frozenset({"DH-SUB2048", "X25519", "SHA1", "RSA-UNK"}),
                       "Config-only change; the hybrid PQ KexAlgorithm was already present.",
                       _fix_sshd_config),
    RemediationAction("fix-nginx-tls", "Restrict nginx to TLS 1.3 + hybrid PQ group",
                       frozenset({"TLS1.0", "TLS1.1", "TLS1.2", "RC4", "MD5", "3DES",
                                  "SHA1", "RSA-UNK", "EC-P256", "AES-128"}),
                       "Config-only change.", _fix_nginx_tls),
    RemediationAction("fix-openssl-cnf", "Harden openssl.cnf",
                       frozenset({"RSA-SUB2048", "RC4", "SHA1", "RSA-UNK", "TLS1.2"}),
                       "Config-only change.", _fix_openssl_cnf),
    RemediationAction("reissue-legacy-partner-cert", "Re-issue legacy_partner cert",
                       frozenset({"RSA-SUB2048", "SHA1"}),
                       "Certificates are re-issued, not hand-edited.", _reissue_legacy_partner_cert),
    RemediationAction("migrate-payments-signing-key", "payments: RSA-1024 -> ML-DSA-65",
                       frozenset({"RSA-SUB2048"}), "Algorithm migration, not a bigger key.",
                       _migrate_payments_signing_key),
    RemediationAction("migrate-payments-tls-key", "payments: EC P-256 -> hybrid ML-KEM-768",
                       frozenset({"EC-P256"}), "Algorithm migration, not a different curve.",
                       _migrate_payments_tls_key),
    RemediationAction("migrate-vault-kex", "vault: X25519 -> hybrid ML-KEM-768",
                       frozenset({"X25519"}), "Algorithm migration.", _migrate_vault_kex),
    RemediationAction("migrate-vault-signing", "vault: Ed25519 -> ML-DSA-65",
                       frozenset({"ED25519"}), "Algorithm migration.", _migrate_vault_signing),
    RemediationAction("migrate-auth-service-keygen", "AuthService: RSA -> ML-DSA",
                       frozenset({"RSA-UNK", "RSA-2048"}), "Algorithm migration.",
                       _migrate_auth_service_keygen),
    RemediationAction("reissue-modern-service-cert", "Re-issue modern_service cert (2nd wave)",
                       frozenset({"EC-P256"}),
                       "Not urgent -- already today's best practice; lowest priority on purpose.",
                       _reissue_modern_service_cert),
]
ACTIONS_BY_ID = {a.id: a for a in ACTIONS}

# Items intentionally left unfixed by the demo remediation set, and why --
# surfaced verbatim in the engagement report so the "why isn't this 100%"
# question always has a documented, honest answer.
RESIDUAL_NOTES = {
    "EC-P256": "modern_service.crt/.key and the ECDHE TLS group already reflect today's best "
               "practice (EC P-256). Still Shor-vulnerable by definition -- ECC is classical "
               "public-key crypto -- but scheduled for a later migration wave once CA/browser "
               "support for ML-DSA certificates is mainstream, not this engagement.",
    "ED25519": "OpenSSH has not standardised a post-quantum host-key algorithm yet. ssh-ed25519 "
               "is kept as the strongest currently-interoperable option; revisit when upstream "
               "support lands.",
    "AES-UNK": "Key length is supplied at runtime, not as a literal in source, so static "
               "analysis cannot confirm 256-bit keys are actually used. Verify operationally "
               "(e.g. a runtime assertion or config lint), not with this scanner.",
    "TLS1.3": "Flagged SHOR because TLS 1.3 defaults to classical key exchange. A hybrid group "
              "is a separate, per-listener negotiation setting (see ssl_ecdh_curve / Groups=) "
              "that this scanner cannot yet correlate back to the protocol-version finding "
              "itself -- a known limitation, not a false claim of safety.",
    "RSA-3072": "default_bits was raised for classical hygiene only. RSA is Shor-vulnerable at "
                "any key size, so this has no automated fix short of migrating off RSA entirely "
                "-- which the actual signing/TLS call sites already do; this default only "
                "affects ad-hoc CSRs generated directly from openssl.cnf.",
    "X25519": "Kept as an explicit classical fallback alongside the configured hybrid group "
              "(X25519:X25519MLKEM768) for clients that don't yet support the hybrid group. "
              "Removing it would break compatibility with those clients, so it is a deliberate, "
              "monitored trade-off, not an oversight.",
}


def priority_ordered_actions(migration_plan) -> list[RemediationAction]:
    """Order not-yet-applied actions by the highest score among the catalog_ids
    they resolve, in this iteration's own migration plan -- i.e. fix what's
    currently most urgent first, the same principle risk.py uses."""
    score_by_id = {item.catalog_id: item.score for item in migration_plan}

    def action_score(a: RemediationAction) -> float:
        return max((score_by_id.get(cid, 0.0) for cid in a.resolves), default=0.0)

    return sorted(ACTIONS, key=action_score, reverse=True)


def apply_round(work_root: Path, migration_plan, already_applied: set,
                 max_actions: Optional[int] = None) -> list[ChangeRecord]:
    """Apply the next batch of not-yet-applied, still-relevant actions
    against `work_root`, in priority order. Mutates `already_applied` in
    place. Returns the ChangeRecords actually produced this round (a
    RemediationAction that turns out to be a no-op -- e.g. because an
    earlier action already touched the same lines -- is still marked
    applied, so it is never retried)."""
    changes: list[ChangeRecord] = []
    count = 0
    for action in priority_ordered_actions(migration_plan):
        if action.id in already_applied:
            continue
        if max_actions is not None and count >= max_actions:
            break
        record = action.apply(work_root)
        already_applied.add(action.id)
        count += 1
        if record is not None:
            changes.append(record)
    return changes
