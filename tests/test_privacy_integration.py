import pytest

from qbom import privacy, zk
from qbom.model import Finding, QBOM


def _qbom():
    q = QBOM(org="TestOrg")
    q.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q.add_finding(Finding("MD5", "HASH", "b.py", 2, "x", "t"))
    q.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "c.py", 3, "x", "t"))
    q.add_finding(Finding("AES-256", "SYMMETRIC", "d.py", 4, "x", "t"))
    return q


def test_attestation_public_dict_never_contains_raw_locations():
    q = _qbom()
    att = privacy.build_attestation(q)
    public = att.to_public_dict()
    blob = str(public)
    assert "a.py" not in blob
    assert "b.py" not in blob


def test_zero_proof_true_claim_verifies():
    q = _qbom()
    att = privacy.build_attestation(q)
    privacy.prove_zero(att, "SHA1")  # genuinely zero in this qbom
    public = att.to_public_dict()
    assert privacy.verify_zero_proof(public, "SHA1")


def test_zero_proof_false_claim_fails_verification():
    q = _qbom()
    att = privacy.build_attestation(q)
    privacy.prove_zero(att, "MD5")  # MD5 count is actually 2 -- lying
    public = att.to_public_dict()
    assert not privacy.verify_zero_proof(public, "MD5")


def test_threshold_proof_true_claim_verifies():
    q = _qbom()
    att = privacy.build_attestation(q)
    privacy.prove_below_threshold_for_qbom(q, att, "MD5", threshold=5)  # true: count is 2
    public = att.to_public_dict()
    assert privacy.verify_threshold_proof(public, "MD5")


def test_threshold_proof_false_claim_raises_at_construction():
    q = _qbom()
    att = privacy.build_attestation(q)
    with pytest.raises(ValueError):
        privacy.prove_below_threshold_for_qbom(q, att, "MD5", threshold=2)  # count==2, not <2


def test_disclose_single_finding_reveals_only_that_one():
    q = _qbom()
    att = privacy.build_attestation(q)
    privacy.disclose_finding(q, att, "MD5", "a.py:1")
    public = att.to_public_dict()
    assert len(public["finding_disclosures"]) == 1
    assert privacy.verify_finding_disclosure(public, 0)
    # the second MD5 finding (b.py:2) must not appear anywhere in the public dict
    assert "b.py" not in str(public)


def test_disclose_nonexistent_finding_raises():
    q = _qbom()
    att = privacy.build_attestation(q)
    with pytest.raises(KeyError):
        privacy.disclose_finding(q, att, "MD5", "nowhere.py:999")


def test_remediation_proof_true_claim():
    from qbom.model import QBOM as _QBOM
    secret = zk.rand_scalar().to_bytes(32, "big")

    q_before = QBOM(org="TestOrg", org_secret=secret)
    q_before.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q_before.add_finding(Finding("MD5", "HASH", "b.py", 2, "x", "t"))
    q_before.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "c.py", 3, "x", "t"))
    att_before = privacy.build_attestation(q_before)
    privacy.disclose_finding(q_before, att_before, "MD5", "a.py:1")
    salt = q_before.findings[0].salt  # matches the MD5@a.py:1 finding

    # simulate remediation: new scan, SAME org secret, without that finding
    q_after = QBOM(org="TestOrg", org_secret=secret)
    q_after.add_finding(Finding("MD5", "HASH", "b.py", 2, "x", "t"))
    q_after.add_finding(Finding("AES-256", "SYMMETRIC", "d.py", 4, "x", "t"))
    att_after = privacy.build_attestation(q_after)
    privacy.prove_remediated(q_before, q_after, att_after, "MD5", "a.py:1", salt, label="fixed")
    public_after = att_after.to_public_dict()
    assert privacy.verify_remediation_proof(public_after, 0, "MD5", "a.py:1", salt)


def test_remediation_proof_refuses_when_still_present():
    secret = zk.rand_scalar().to_bytes(32, "big")

    q_before = QBOM(org="TestOrg", org_secret=secret)
    q_before.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    salt = q_before.findings[0].salt

    # SAME org secret, finding genuinely still present -> same salt, still there
    q_after = QBOM(org="TestOrg", org_secret=secret)
    q_after.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    att_after = privacy.build_attestation(q_after)
    with pytest.raises(ValueError):
        privacy.prove_remediated(q_before, q_after, att_after, "MD5", "a.py:1", salt)


def test_remediation_salt_stable_across_rescans_with_same_secret():
    secret = zk.rand_scalar().to_bytes(32, "big")
    q1 = QBOM(org="A", org_secret=secret)
    q1.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q2 = QBOM(org="A", org_secret=secret)
    q2.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    assert q1.findings[0].salt == q2.findings[0].salt


def test_remediation_salt_differs_across_orgs_with_different_secrets():
    q1 = QBOM(org="A")  # random secret
    q1.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q2 = QBOM(org="B")  # different random secret
    q2.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    assert q1.findings[0].salt != q2.findings[0].salt


def test_homomorphic_aggregation_across_orgs_never_exposes_individual_counts():
    q1 = QBOM(org="BU1")
    q1.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "x.py", 1, "x", "t"))
    q1.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "y.py", 2, "x", "t"))
    q2 = QBOM(org="BU2")
    q2.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "z.py", 3, "x", "t"))

    att1 = privacy.build_attestation(q1)
    att2 = privacy.build_attestation(q2)
    pub1, pub2 = att1.to_public_dict(), att2.to_public_dict()

    assert "2" not in [v for v in pub1["catalog_commitments"].values()]  # commitments are hex points, not counts

    agg = privacy.aggregate_commitments([pub1, pub2], "RSA-SUB2048")
    total_r = (att1.catalog_commitments["RSA-SUB2048"].blinding +
               att2.catalog_commitments["RSA-SUB2048"].blinding) % zk.N
    opening = zk.prove_opening(3, total_r, agg, b"agg-test")  # true sector total = 2 + 1 = 3
    assert zk.verify_opening(agg, opening, b"agg-test")

    wrong_opening = zk.prove_opening(99, total_r, agg, b"agg-test")
    assert not zk.verify_opening(agg, wrong_opening, b"agg-test")


def test_catalog_commitment_reveals_nothing_by_inspection():
    q_small = QBOM(org="A")
    q_small.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q_big = QBOM(org="B")
    for i in range(50):
        q_big.add_finding(Finding("MD5", "HASH", f"f{i}.py", i, "x", "t"))

    att_small = privacy.build_attestation(q_small)
    att_big = privacy.build_attestation(q_big)
    # commitments are indistinguishable in *form* regardless of the hidden count
    c_small = att_small.to_public_dict()["catalog_commitments"]["MD5"]
    c_big = att_big.to_public_dict()["catalog_commitments"]["MD5"]
    assert len(c_small) == len(c_big)  # same encoding length, no length side-channel on count
