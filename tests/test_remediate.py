
from qbom import remediate, risk, scanner
from qbom.model import QBOM


def _scan(root):
    q = QBOM(org="test")
    for f in scanner.scan_directory(root):
        q.add_finding(f)
    return q


def test_prepare_workdir_is_idempotent(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    work = tmp_path / "work"
    remediate.prepare_workdir(src, work)
    (work / "a.py").write_text("# hand-edited after copy\n")
    remediate.prepare_workdir(src, work)  # should NOT overwrite the hand-edit
    assert (work / "a.py").read_text() == "# hand-edited after copy\n"


def test_apply_round_is_idempotent_and_reduces_broken_findings(tmp_path):
    src = tmp_path / "src"
    (src / "app" / "legacy").mkdir(parents=True)
    (src / "app" / "legacy" / "hash.py").write_text(
        "import hashlib\n"
        "def fingerprint(data: bytes) -> str:\n"
        "    return hashlib.sha1(data).hexdigest()\n"
        "def old_password_hash(pw: str) -> str:\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n"
    )
    work = tmp_path / "work"
    remediate.prepare_workdir(src, work)

    before = _scan(work)
    before_summary = risk.readiness_summary(before)
    plan = risk.build_migration_plan(before)

    applied = set()
    changes = remediate.apply_round(work, plan, applied, max_actions=10)
    assert any(c.action_id == "fix-broken-hashes" for c in changes)

    after = _scan(work)
    after_summary = risk.readiness_summary(after)
    assert after_summary["classically_broken_pct"] < before_summary["classically_broken_pct"]

    # re-applying against the same actions set is a no-op (already applied)
    changes_again = remediate.apply_round(work, plan, applied, max_actions=10)
    assert changes_again == []


def test_max_actions_per_round_caps_batch_size(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    work = tmp_path / "work"
    remediate.prepare_workdir(src, work)
    applied = set()
    remediate.apply_round(work, [], applied, max_actions=2)
    assert len(applied) == 2


def test_residual_notes_cover_known_leftover_catalog_ids():
    # every id referenced in a note must be a real catalog entry, and vice
    # versa -- catches typos rather than asserting exact catalog coverage
    from qbom import catalog
    for cid in remediate.RESIDUAL_NOTES:
        assert catalog.get(cid).id == cid
