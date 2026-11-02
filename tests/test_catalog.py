from qbom import catalog


def test_catalog_ids_unique():
    assert len(catalog.CATALOG_IDS) == len(set(catalog.CATALOG_IDS))


def test_catalog_hash_deterministic():
    h1 = catalog.CATALOG_HASH
    # recompute independently
    import hashlib
    h2 = hashlib.sha3_256((catalog.CATALOG_VERSION + "|" + "|".join(catalog.CATALOG_IDS)).encode()).hexdigest()
    assert h1 == h2


def test_rsa_id_boundaries():
    assert catalog.rsa_id(1024) == "RSA-SUB2048"
    assert catalog.rsa_id(2047) == "RSA-SUB2048"
    assert catalog.rsa_id(2048) == "RSA-2048"
    assert catalog.rsa_id(3071) == "RSA-2048"
    assert catalog.rsa_id(3072) == "RSA-3072"
    assert catalog.rsa_id(4096) == "RSA-4096"
    assert catalog.rsa_id(None) == "RSA-UNK"


def test_aes_id():
    assert catalog.aes_id(128) == "AES-128"
    assert catalog.aes_id(256) == "AES-256"
    assert catalog.aes_id(None) == "AES-UNK"


def test_shor_algorithms_flagged_correctly():
    for cid in ("RSA-SUB2048", "RSA-2048", "DH-2048", "DSA", "EC-P256", "ED25519", "X25519"):
        assert catalog.get(cid).threat == "SHOR", cid


def test_grover_vs_pq_safe_aes():
    assert catalog.get("AES-128").threat == "GROVER"
    assert catalog.get("AES-256").threat == "PQ_SAFE"


def test_classically_broken_independent_of_quantum():
    for cid in ("MD5", "SHA1", "DES", "3DES", "RC4", "MODE-ECB"):
        assert catalog.get(cid).threat == "CLASSICAL_BROKEN", cid


def test_pq_and_hybrid_recognized():
    assert catalog.get("ML-KEM-768").threat == "PQ_SAFE"
    assert catalog.get("HYBRID-KEM").threat == "HYBRID"
    assert catalog.get("KYBER-LEGACY").threat == "LEGACY_PQ"


def test_unknown_catalog_id_falls_back():
    a = catalog.get("NOT-A-REAL-ID")
    assert a.id == "UNCLASSIFIED"
    assert a.threat == "UNKNOWN"


def test_resolve_token_hybrid_kem_variants():
    for tok in ("X25519MLKEM768", "mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com",
                "kyber768x25519"):
        r = catalog.resolve_token(tok)
        assert r is not None and r[0] == "HYBRID-KEM", tok


def test_resolve_token_bare_kyber_not_hybrid():
    r = catalog.resolve_token("kyber768")
    assert r is not None and r[0] == "KYBER-LEGACY"


def test_resolve_token_pure_mlkem():
    assert catalog.resolve_token("ML-KEM-768") == ("ML-KEM-768", "KEY_EXCHANGE")


def test_resolve_token_tls_versions():
    assert catalog.resolve_token("TLSv1.2")[0] == "TLS1.2"
    assert catalog.resolve_token("tls1.3")[0] == "TLS1.3"
    assert catalog.resolve_token("SSLv23")[0] == "SSL-2/3"


def test_resolve_token_curves():
    assert catalog.resolve_token("prime256v1")[0] == "EC-P256"
    assert catalog.resolve_token("secp384r1")[0] == "EC-P384"
    assert catalog.resolve_token("ecdsa-p384")[0] == "EC-P384"


def test_resolve_token_hashes():
    assert catalog.resolve_token("md5")[0] == "MD5"
    assert catalog.resolve_token("SHA-1")[0] == "SHA1"
    assert catalog.resolve_token("sha256")[0] == "SHA-256"


def test_resolve_token_none_for_garbage():
    assert catalog.resolve_token("this-is-not-a-crypto-token") is None
    assert catalog.resolve_token("") is None


def test_resolve_cipher_suite_ecdhe_rsa():
    parts = catalog.resolve_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")
    kinds = {p[0] for p in parts}
    assert "EC-P256" in kinds       # key exchange
    assert "RSA-UNK" in kinds       # authentication, not key transport
    assert "AES-128" in kinds
    purposes = dict(parts)
    assert purposes["RSA-UNK"] == "SIGNATURE"  # ECDHE-RSA: RSA authenticates, doesn't transport the key


def test_resolve_cipher_suite_static_rsa_key_transport():
    parts = catalog.resolve_cipher_suite("AES128-SHA")
    purposes = dict(parts)
    assert purposes.get("RSA-UNK") == "KEY_EXCHANGE"  # static RSA: the key IS transported via RSA


def test_resolve_cipher_suite_des_rc4_md5():
    parts = catalog.resolve_cipher_suite("DES-CBC3-SHA")
    assert ("3DES", "SYMMETRIC") in parts
    parts2 = catalog.resolve_cipher_suite("RC4-MD5")
    assert ("RC4", "SYMMETRIC") in parts2
    assert ("MD5", "HASH") in parts2


def test_resolve_cipher_suite_skips_meta_tokens():
    assert catalog.resolve_cipher_suite("DEFAULT") == []
    assert catalog.resolve_cipher_suite("!aNULL") == []
