from qbom import risk
from qbom.model import Component, Finding, QBOM


def _qbom_with(catalog_id, n, exposure="internal", sensitivity="medium", lifetime=3.0, component="svc"):
    q = QBOM(org="test")
    q.add_component(Component(component, exposure=exposure, data_sensitivity=sensitivity, data_lifetime_years=lifetime))
    for i in range(n):
        q.add_finding(Finding(catalog_id, "UNKNOWN_ASYM", f"f{i}.py", i, "x", "t", component=component))
    return q


def test_shor_outranks_grover_at_equal_exposure():
    q = QBOM(org="test")
    q.add_component(Component("svc", exposure="internal", data_sensitivity="medium", data_lifetime_years=3))
    q.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "a.py", 1, "x", "t", component="svc"))
    q.add_finding(Finding("AES-128", "SYMMETRIC", "b.py", 1, "x", "t", component="svc"))
    plan = risk.build_migration_plan(q)
    order = [item.catalog_id for item in plan]
    assert order.index("RSA-SUB2048") < order.index("AES-128")


def test_classically_broken_outranks_hybrid():
    q = QBOM(org="test")
    q.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q.add_finding(Finding("HYBRID-KEM", "KEY_EXCHANGE", "b.py", 1, "x", "t"))
    plan = risk.build_migration_plan(q)
    order = [item.catalog_id for item in plan]
    assert order.index("MD5") < order.index("HYBRID-KEM")


def test_longer_data_lifetime_increases_shor_urgency():
    q_short = _qbom_with("RSA-SUB2048", 1, lifetime=1.0)
    q_long = _qbom_with("RSA-SUB2048", 1, lifetime=20.0)
    score_short = risk.build_migration_plan(q_short)[0].score
    score_long = risk.build_migration_plan(q_long)[0].score
    assert score_long > score_short


def test_internet_facing_increases_urgency_over_air_gapped():
    q_air = _qbom_with("RSA-SUB2048", 1, exposure="air_gapped")
    q_net = _qbom_with("RSA-SUB2048", 1, exposure="internet_facing")
    score_air = risk.build_migration_plan(q_air)[0].score
    score_net = risk.build_migration_plan(q_net)[0].score
    assert score_net > score_air


def test_critical_sensitivity_increases_urgency():
    q_low = _qbom_with("RSA-SUB2048", 1, sensitivity="low")
    q_crit = _qbom_with("RSA-SUB2048", 1, sensitivity="critical")
    score_low = risk.build_migration_plan(q_low)[0].score
    score_crit = risk.build_migration_plan(q_crit)[0].score
    assert score_crit > score_low


def test_pq_safe_scores_lowest():
    q = QBOM(org="test")
    q.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "a.py", 1, "x", "t"))
    q.add_finding(Finding("AES-256", "SYMMETRIC", "b.py", 1, "x", "t"))
    plan = risk.build_migration_plan(q)
    scores = {item.catalog_id: item.score for item in plan}
    assert scores["AES-256"] < scores["RSA-SUB2048"]


def test_readiness_summary_percentages_sum_reasonably():
    q = QBOM(org="test")
    q.add_finding(Finding("AES-256", "SYMMETRIC", "a.py", 1, "x", "t"))
    q.add_finding(Finding("RSA-SUB2048", "UNKNOWN_ASYM", "b.py", 1, "x", "t"))
    q.add_finding(Finding("MD5", "HASH", "c.py", 1, "x", "t"))
    q.add_finding(Finding("AES-128", "SYMMETRIC", "d.py", 1, "x", "t"))
    summary = risk.readiness_summary(q)
    assert summary["total_findings"] == 4
    pct_sum = (summary["pq_ready_pct"] + summary["shor_vulnerable_pct"] +
               summary["grover_weakened_pct"] + summary["classically_broken_pct"])
    assert abs(pct_sum - 100.0) < 0.1


def test_migration_plan_empty_qbom():
    q = QBOM(org="test")
    assert risk.build_migration_plan(q) == []
