from qbom import ec


def test_generator_on_curve():
    assert ec.is_on_curve(ec.G)


def test_h_on_curve_and_distinct_from_g():
    assert ec.is_on_curve(ec.H)
    assert not ec.point_eq(ec.H, ec.G)


def test_scalar_mult_matches_repeated_addition():
    q1 = ec.scalar_mult(5, ec.G)
    q2 = ec.G
    for _ in range(4):
        q2 = ec.point_add(q2, ec.G)
    assert ec.point_eq(q1, q2)


def test_order_times_generator_is_infinity():
    assert ec.scalar_mult(ec.N, ec.G).is_infinity()


def test_homomorphic_scalar_addition():
    a, b = 12345, 67890
    lhs = ec.scalar_mult(a + b, ec.G)
    rhs = ec.point_add(ec.scalar_mult(a, ec.G), ec.scalar_mult(b, ec.G))
    assert ec.point_eq(lhs, rhs)


def test_point_add_identity():
    p = ec.scalar_mult(42, ec.G)
    assert ec.point_eq(ec.point_add(p, ec.O), p)
    assert ec.point_eq(ec.point_add(ec.O, p), p)


def test_point_add_inverse_is_infinity():
    p = ec.scalar_mult(42, ec.G)
    neg_p = ec.Point(p.x, (-p.y) % ec.P)
    assert ec.point_add(p, neg_p).is_infinity()


def test_hash_to_curve_deterministic():
    h1 = ec.hash_to_curve(b"test-label")
    h2 = ec.hash_to_curve(b"test-label")
    assert ec.point_eq(h1, h2)


def test_hash_to_curve_different_labels_differ():
    h1 = ec.hash_to_curve(b"label-a")
    h2 = ec.hash_to_curve(b"label-b")
    assert not ec.point_eq(h1, h2)


def test_point_to_bytes_roundtrip_via_zk_helper():
    from qbom import zk
    p = ec.scalar_mult(999, ec.G)
    h = ec.point_to_bytes(p).hex()
    p2 = zk.point_from_hex(h)
    assert ec.point_eq(p, p2)
