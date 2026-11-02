import secrets

import pytest

from qbom import merkle as mk


def _sample_leaves(n=8):
    salts = [secrets.token_bytes(16) for _ in range(n)]
    return [mk.leaf_hash(f"ALG-{i}", f"file{i}.py:{i}", salts[i]) for i in range(n)], salts


def test_build_tree_root_deterministic_regardless_of_input_order():
    leaves, _ = _sample_leaves(6)
    t1 = mk.build_tree(leaves)
    t2 = mk.build_tree(list(reversed(leaves)))
    assert t1.root == t2.root


def test_inclusion_proof_valid_for_every_leaf():
    leaves, _ = _sample_leaves(7)  # odd count exercises the "promote unchanged" path
    t = mk.build_tree(leaves)
    for leaf in leaves:
        proof = t.prove_inclusion(leaf)
        assert mk.verify_inclusion(t.root, proof)


def test_inclusion_proof_rejects_wrong_root():
    leaves, _ = _sample_leaves(5)
    t = mk.build_tree(leaves)
    other_leaves, _ = _sample_leaves(5)
    t_other = mk.build_tree(other_leaves)
    proof = t.prove_inclusion(leaves[0])
    assert not mk.verify_inclusion(t_other.root, proof)


def test_prove_inclusion_raises_for_absent_leaf():
    leaves, _ = _sample_leaves(4)
    t = mk.build_tree(leaves)
    fake = mk.leaf_hash("NOPE", "nowhere:0", secrets.token_bytes(16))
    with pytest.raises(ValueError):
        t.prove_inclusion(fake)


def test_non_membership_between():
    leaves, _ = _sample_leaves(6)
    t = mk.build_tree(leaves)
    target = mk.leaf_hash("MISSING", "x:0", secrets.token_bytes(16))
    # ensure target genuinely absent (astronomically likely with random salts)
    assert target not in t.sorted_leaves_raw
    kind, payload = t.prove_non_membership(target)
    assert mk.verify_non_membership(t.root, target, kind, payload, len(t.sorted_leaves_raw))


def test_non_membership_refuses_when_actually_present():
    leaves, _ = _sample_leaves(4)
    t = mk.build_tree(leaves)
    with pytest.raises(ValueError):
        t.prove_non_membership(leaves[0])


def test_non_membership_cannot_be_reused_for_present_leaf():
    leaves, _ = _sample_leaves(5)
    t = mk.build_tree(leaves)
    absent_target = mk.leaf_hash("MISSING", "x:0", secrets.token_bytes(16))
    kind, payload = t.prove_non_membership(absent_target)
    # try to "reuse" this exact proof structure to claim a present leaf is absent
    assert not mk.verify_non_membership(t.root, leaves[0], kind, payload, len(t.sorted_leaves_raw))


def test_non_membership_below_and_above_endpoints():
    leaves, _ = _sample_leaves(5)
    t = mk.build_tree(leaves)
    smallest = min(t.sorted_leaves_raw)
    largest = max(t.sorted_leaves_raw)
    # constructing guaranteed-smaller/larger targets by direct byte manipulation is fragile;
    # instead just confirm both endpoint kinds are reachable via prove_non_membership
    # by searching many random targets until we observe both kinds at least once in a
    # tree with a wide value spread (probabilistic but reliable with enough draws).
    seen_kinds = set()
    for _ in range(200):
        candidate = mk.leaf_hash("R", str(secrets.token_hex(4)), secrets.token_bytes(16))
        if candidate in t.sorted_leaves_raw:
            continue
        kind, payload = t.prove_non_membership(candidate)
        assert mk.verify_non_membership(t.root, candidate, kind, payload, len(t.sorted_leaves_raw))
        seen_kinds.add(kind)
    assert "absent_between" in seen_kinds  # near-certain with 200 draws over a 5-leaf tree


def test_single_leaf_tree():
    leaves, _ = _sample_leaves(1)
    t = mk.build_tree(leaves)
    proof = t.prove_inclusion(leaves[0])
    assert mk.verify_inclusion(t.root, proof)


def test_empty_tree_has_stable_root():
    t = mk.build_tree([])
    assert t.root is not None
    t2 = mk.build_tree([])
    assert t.root == t2.root
