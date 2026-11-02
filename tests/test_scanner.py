from pathlib import Path

from qbom import scanner

SAMPLES = Path(__file__).parent.parent / "samples" / "vulnerable-app"


def test_python_ast_finds_weak_rsa():
    findings = scanner.scan_directory(SAMPLES / "app" / "payments")
    ids = {f.catalog_id for f in findings}
    assert "RSA-SUB2048" in ids


def test_python_ast_finds_md5_and_sha1():
    findings = scanner.scan_directory(SAMPLES / "app")
    ids = {f.catalog_id for f in findings}
    assert "MD5" in ids
    assert "SHA1" in ids


def test_python_ast_finds_ecb_mode():
    findings = scanner.scan_directory(SAMPLES / "app" / "payments")
    ids = {f.catalog_id for f in findings}
    assert "MODE-ECB" in ids


def test_python_ast_finds_modern_x25519_ed25519():
    findings = scanner.scan_directory(SAMPLES / "app" / "crypto")
    ids = {f.catalog_id for f in findings}
    assert "X25519" in ids
    assert "ED25519" in ids


def test_java_regex_finds_rsa_and_des_ecb():
    findings = scanner.scan_directory(SAMPLES / "app" / "api")
    ids = {f.catalog_id for f in findings}
    assert "RSA-2048" in ids  # initialize(2048)
    assert "DES" in ids
    assert "MODE-ECB" in ids
    assert "SHA1" in ids


def test_js_regex_finds_md5_3des_and_jwt_alg():
    findings = scanner.scan_directory(SAMPLES / "web-service")
    ids = {f.catalog_id for f in findings}
    assert "MD5" in ids
    assert "3DES" in ids


def test_sshd_config_finds_weak_kex_and_hybrid():
    findings = scanner.scan_file(SAMPLES / "config" / "sshd_config")
    ids = {f.catalog_id for f in findings}
    assert "DH-SUB2048" in ids      # diffie-hellman-group1-sha1
    assert "HYBRID-KEM" in ids      # sntrup761x25519
    assert "SHA1" in ids            # hmac-sha1 MAC


def test_nginx_config_finds_weak_tls_and_ciphers():
    findings = scanner.scan_file(SAMPLES / "config" / "nginx.conf")
    ids = {f.catalog_id for f in findings}
    assert "TLS1.0" in ids
    assert "TLS1.1" in ids
    assert "RC4" in ids
    assert "3DES" in ids


def test_nginx_ciphers_not_double_counted_with_sshd_rules():
    # regression test: `ssl_ciphers` must not also match the sshd `Ciphers` rule
    findings = scanner.scan_file(SAMPLES / "config" / "nginx.conf")
    aes128 = [f for f in findings if f.catalog_id == "AES-128"]
    assert len(aes128) == 1, f"expected exactly one AES-128 finding, got {len(aes128)}"


def test_openssl_cnf_finds_weak_default_bits():
    findings = scanner.scan_file(SAMPLES / "config" / "openssl.cnf")
    ids = {f.catalog_id for f in findings}
    assert "RSA-SUB2048" in ids   # default_bits = 1024
    assert "TLS1.2" in ids


def test_x509_cert_weak_key_and_signature():
    cert = SAMPLES / "certs" / "legacy_partner.crt"
    if not cert.exists():
        return  # openssl not available in this environment
    findings = scanner.scan_file(cert)
    ids = {f.catalog_id for f in findings}
    assert "RSA-SUB2048" in ids
    assert "SHA1" in ids


def test_x509_cert_modern_key_and_signature():
    cert = SAMPLES / "certs" / "modern_service.crt"
    if not cert.exists():
        return
    findings = scanner.scan_file(cert)
    ids = {f.catalog_id for f in findings}
    assert "EC-P256" in ids
    assert "SHA-256" in ids


def test_pem_private_key_classified():
    key = SAMPLES / "certs" / "legacy_partner.key"
    if not key.exists():
        return
    findings = scanner.scan_file(key)
    ids = {f.catalog_id for f in findings}
    assert "RSA-SUB2048" in ids


def test_scanner_never_executes_target_code(tmp_path):
    # a file that would raise/exit if actually executed must not affect the scan
    malicious = tmp_path / "dangerous.py"
    malicious.write_text("import sys\nsys.exit(1)\nimport hashlib\nhashlib.md5(b'x')\n")
    findings = scanner.scan_file(malicious)  # must not raise SystemExit
    ids = {f.catalog_id for f in findings}
    assert "MD5" in ids


def test_scanner_handles_syntax_errors_gracefully(tmp_path):
    bad = tmp_path / "broken.py"
    bad.write_text("def foo(:\n    md5(")
    findings = scanner.scan_file(bad)  # should not raise
    assert isinstance(findings, list)


def test_full_sample_scan_no_crash_and_reasonable_count():
    findings = scanner.scan_directory(SAMPLES)
    assert len(findings) > 30
    assert all(f.catalog_id in __import__("qbom.catalog", fromlist=["CATALOG"]).CATALOG for f in findings)


def test_liboqs_python_calls_recognised(tmp_path):
    f = tmp_path / "vault.py"
    f.write_text(
        "import oqs\n"
        "def kex():\n    return oqs.KeyEncapsulation(\"X25519MLKEM768\")\n"
        "def sig():\n    return oqs.Signature(\"ML-DSA-65\")\n"
    )
    ids = {finding.catalog_id for finding in scanner.scan_python(f, f.read_text())}
    assert "HYBRID-KEM" in ids
    assert "ML-DSA" in ids


def test_java_pqc_keygen_recognised():
    findings = scanner.scan_generic_text(
        Path("X.java"), 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");')
    assert any(f.catalog_id == "ML-DSA" for f in findings)


def test_nginx_hybrid_group_and_tls13_correlation():
    text = 'ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519:X25519MLKEM768;\n'
    findings = scanner.scan_generic_text(Path("nginx.conf"), text)
    ids = {f.catalog_id for f in findings}
    assert "HYBRID-KEM" in ids
    # same-file correlation: TLS1.3 is relabelled, not left as a bare SHOR finding
    assert "TLS1.3" not in ids
    assert "TLS1.3-HYBRID" in ids


def test_openssl_groups_directive_recognised():
    findings = scanner.scan_generic_text(Path("openssl.cnf"), "Groups = X25519:X25519MLKEM768")
    assert any(f.catalog_id == "HYBRID-KEM" for f in findings)
