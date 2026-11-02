import pytest

from qbom import zk


def test_commit_deterministic_for_same_inputs():
    c1 = zk.commit(7, 42)
    c2 = zk.commit(7, 42)
    assert zk.point_eq(c1.point, c2.point)


def test_commit_hiding_different_blindings_differ():
    c1 = zk.commit(7, 42)
    c2 = zk.commit(7, 43)
    assert not zk.point_eq(c1.point, c2.point)


def test_commit_homomorphic_addition():
    c1, r1 = zk.commit_random(3)
    c2, r2 = zk.commit_random(5)
    summed = c1 + c2
    expected = zk.commit(8, (r1 + r2) % zk.N)
    assert zk.point_eq(summed.point, expected.point)


def test_opening_proof_valid_and_binds_to_context():
    v, r = zk.rand_scalar() % 1000, zk.rand_scalar()
    c = zk.commit(v, r)
    p = zk.prove_opening(v, r, c, b"ctx-a")
    assert zk.verify_opening(c, p, b"ctx-a")
    assert not zk.verify_opening(c, p, b"ctx-b")


def test_opening_proof_rejects_wrong_commitment():
    v, r = 10, zk.rand_scalar()
    c = zk.commit(v, r)
    other = zk.commit(11, zk.rand_scalar())
    p = zk.prove_opening(v, r, c)
    assert not zk.verify_opening(other, p)


def test_public_value_proof_true_claim():
    r = zk.rand_scalar()
    c = zk.commit(0, r)
    p = zk.prove_public_value(0, r, c, b"claim")
    assert zk.verify_public_value(c, p, b"claim")


def test_public_value_proof_false_claim_rejected():
    # commitment genuinely holds 3, but someone tries to *claim* it's 0
    r = zk.rand_scalar()
    c = zk.commit(3, r)
    p = zk.prove_public_value(0, r, c, b"claim")  # honest about r, dishonest about the public value
    assert not zk.verify_public_value(c, p, b"claim")


def test_bit_proof_zero_and_one():
    r0 = zk.rand_scalar()
    c0 = zk.commit(0, r0)
    p0 = zk.prove_bit(0, r0, c0, b"ctx")
    assert zk.verify_bit(c0, p0, b"ctx")

    r1 = zk.rand_scalar()
    c1 = zk.commit(1, r1)
    p1 = zk.prove_bit(1, r1, c1, b"ctx")
    assert zk.verify_bit(c1, p1, b"ctx")


def test_bit_proof_hides_which_bit():
    # both proofs verify identically-shaped; can't distinguish bit=0 vs bit=1
    # from proof structure alone (both have t0,t1,c0,c1,s0,s1 of the same type)
    r0, r1 = zk.rand_scalar(), zk.rand_scalar()
    c0, c1 = zk.commit(0, r0), zk.commit(1, r1)
    p0 = zk.prove_bit(0, r0, c0)
    p1 = zk.prove_bit(1, r1, c1)
    assert type(p0) == type(p1)
    assert all(hasattr(p0, f) for f in ("t0", "t1", "c0", "c1", "s0", "s1"))


def test_range_proof_valid_value():
    v, r = 12, zk.rand_scalar()
    c = zk.commit(v, r)
    rp = zk.prove_range(v, r, c, n_bits=8)
    assert zk.verify_range(c, rp)


def test_range_proof_boundary_values():
    for v in (0, 1, 254, 255):
        r = zk.rand_scalar()
        c = zk.commit(v, r)
        rp = zk.prove_range(v, r, c, n_bits=8)
        assert zk.verify_range(c, rp), v


def test_range_proof_rejects_out_of_declared_range():
    r = zk.rand_scalar()
    c = zk.commit(300, r)
    with pytest.raises(ValueError):
        zk.prove_range(300, r, c, n_bits=8)


def test_range_proof_tamper_detected():
    v, r = 12, zk.rand_scalar()
    c = zk.commit(v, r)
    rp = zk.prove_range(v, r, c, n_bits=8)
    # tamper: swap in a bit proof from a different, unrelated commitment
    other_c = zk.commit(1, zk.rand_scalar())
    other_p = zk.prove_bit(1, zk.rand_scalar(), other_c)  # wrong blinding on purpose won't even verify itself
    rp.bit_commitments[0] = other_c
    assert not zk.verify_range(c, rp)


def test_threshold_proof_true_claim():
    count, threshold = 4, 10
    r_count = zk.rand_scalar()
    c_count = zk.commit(count, r_count)
    tp = zk.prove_below_threshold(count, r_count, c_count, threshold, n_bits=16)
    assert zk.verify_below_threshold(c_count, tp)


def test_threshold_proof_refuses_false_claim_at_construction():
    count, threshold = 15, 10
    r_count = zk.rand_scalar()
    c_count = zk.commit(count, r_count)
    with pytest.raises(ValueError):
        zk.prove_below_threshold(count, r_count, c_count, threshold, n_bits=16)


def test_threshold_proof_exact_boundary():
    # count == threshold - 1 should be the tightest TRUE claim
    count, threshold = 9, 10
    r_count = zk.rand_scalar()
    c_count = zk.commit(count, r_count)
    tp = zk.prove_below_threshold(count, r_count, c_count, threshold, n_bits=16)
    assert zk.verify_below_threshold(c_count, tp)

    # count == threshold should FAIL to construct (not strictly below)
    count2 = 10
    r2 = zk.rand_scalar()
    c2 = zk.commit(count2, r2)
    with pytest.raises(ValueError):
        zk.prove_below_threshold(count2, r2, c2, threshold, n_bits=16)


def test_threshold_proof_cannot_be_replayed_on_unrelated_commitment():
    count, threshold = 4, 10
    r_count = zk.rand_scalar()
    c_count = zk.commit(count, r_count)
    tp = zk.prove_below_threshold(count, r_count, c_count, threshold, n_bits=16)

    forged_commitment = zk.commit(999, zk.rand_scalar())
    assert not zk.verify_below_threshold(forged_commitment, tp)


def test_threshold_proof_full_dict_roundtrip():
    count, threshold = 3, 5
    r_count = zk.rand_scalar()
    c_count = zk.commit(count, r_count)
    tp = zk.prove_below_threshold(count, r_count, c_count, threshold, n_bits=12, context=b"rt")
    d = tp.to_dict()
    tp2 = zk.ThresholdProof.from_dict(d)
    assert zk.verify_below_threshold(c_count, tp2, context=b"rt")


def test_sector_aggregation_across_business_units():
    counts = [3, 5, 2, 7, 0]
    total = zk.ZERO_COMMITMENT
    total_r = 0
    for cnt in counts:
        c, r = zk.commit_random(cnt)
        total = total + c
        total_r = (total_r + r) % zk.N
    opening = zk.prove_opening(sum(counts), total_r, total, b"agg")
    assert zk.verify_opening(total, opening, b"agg")
    # wrong total is rejected
    bad_opening = zk.prove_opening(sum(counts) + 1, total_r, total, b"agg")
    assert not zk.verify_opening(total, bad_opening, b"agg")
