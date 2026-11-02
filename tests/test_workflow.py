import json

import pytest

from qbom import workflow


def _new(tmp_path, **kw):
    defaults = dict(org="Test Org", source_path="samples/vulnerable-app",
                     out_dir=str(tmp_path / "out"), manifest_path="samples/manifest.json",
                     target_pct=80.0, max_iterations=8, max_actions_per_round=3)
    defaults.update(kw)
    return workflow.new_engagement(**defaults)


def test_iteration_requires_consent_first(tmp_path):
    eng = _new(tmp_path)
    assert eng.status == "PENDING_CONSENT"
    with pytest.raises(ValueError):
        workflow.run_iteration(eng)


def test_consent_moves_status_to_in_progress(tmp_path):
    eng = _new(tmp_path)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    assert eng.status == "IN_PROGRESS"
    assert eng.consent.accepted_by == "Alice"
    with pytest.raises(ValueError):
        workflow.give_consent(eng, accepted_by="Bob")  # consent is one-shot


def test_full_loop_reaches_target_and_is_reproducible(tmp_path):
    eng = _new(tmp_path)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    eng = workflow.run_full_loop(eng, verbose=False)
    assert eng.status == "TARGET_MET"
    assert eng.latest.readiness["pq_ready_pct"] >= eng.target_pct
    # iteration 1 reads the original (read-only) source; later ones read the
    # remediated working copy -- never the other way around
    assert eng.iterations[0].scanned_root == "original"
    assert all(it.scanned_root == "work_root" for it in eng.iterations[1:])
    # readiness is monotonically non-decreasing across iterations
    pcts = [it.readiness["pq_ready_pct"] for it in eng.iterations]
    assert pcts == sorted(pcts)


def test_declining_ends_the_engagement_without_hitting_target(tmp_path):
    eng = _new(tmp_path, target_pct=80.0)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    calls = {"n": 0}

    def decline_after_first(summary, record):
        calls["n"] += 1
        return calls["n"] < 2

    eng = workflow.run_full_loop(eng, accept_fn=decline_after_first, verbose=False)
    assert eng.status == "ENDED_BY_ORG"
    assert eng.iterations[-1].decision == "stop"


def test_max_iterations_stops_the_loop(tmp_path):
    eng = _new(tmp_path, target_pct=99.9, max_iterations=2)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    eng = workflow.run_full_loop(eng, verbose=False)
    assert eng.status == "MAX_ITERATIONS"
    assert len(eng.iterations) == 2


def test_engagement_persists_and_reloads(tmp_path):
    eng = _new(tmp_path)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    workflow.run_iteration(eng)
    reloaded = workflow.load(eng.out_dir)
    assert reloaded.engagement_id == eng.engagement_id
    assert len(reloaded.iterations) == 1
    assert reloaded.consent.accepted_by == "Alice"


def test_vex_marks_fixed_only_after_previously_seen():
    prev = {"MD5": 2, "AES-256": 1}
    cur = {"MD5": 0, "AES-256": 1, "SHA1": 1}
    vex = workflow.build_vex(cur, prev)
    assert vex["MD5"]["status"] == workflow.VEX_FIXED
    assert vex["SHA1"]["status"] == workflow.VEX_AFFECTED
    assert "AES-256" not in vex  # PQ_SAFE is never part of the VEX document


def test_final_artifacts_written_on_target_met(tmp_path):
    eng = _new(tmp_path)
    eng = workflow.give_consent(eng, accepted_by="Alice")
    eng = workflow.run_full_loop(eng, verbose=False)
    final = tmp_path / "out" / "final"
    assert (final / "qbom-engagement-report.pdf").exists()
    assert (final / "qbom-dashboard.html").exists()
    summary = json.loads((final / "engagement-summary.json").read_text())
    assert summary["status"] == "TARGET_MET"
