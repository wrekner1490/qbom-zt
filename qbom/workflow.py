"""
The engagement loop: commitment -> scan -> threat analysis -> recommendations
-> (org accepts and continues, or stops) -> infra applies fixes -> rescan ->
repeat until the target post-quantum readiness % is reached or the org
declines to continue.

This module is the orchestration layer on top of everything else in the
package (scanner/risk/report/dashboard/privacy/remediate); it doesn't
introduce new crypto-classification logic of its own. One `Engagement`
covers one organisation's assessment from consent through to however many
rounds it takes; each round is an `IterationRecord`.

State machine (see `Engagement.status`):

    PENDING_CONSENT --consent()--> IN_PROGRESS
    IN_PROGRESS --iteration reaches target-->        TARGET_MET      (terminal)
    IN_PROGRESS --org declines to continue-->         ENDED_BY_ORG    (terminal)
    IN_PROGRESS --max_iterations reached, no target--> MAX_ITERATIONS  (terminal)
    IN_PROGRESS --iteration below target, org accepts--> IN_PROGRESS (loop)

Every iteration writes its own artifacts (qbom.json, CycloneDX CBOM,
markdown + PDF report, HTML dashboard, VEX document, optional zero-trust
attestation) under <out>/iterations/iteration-N/, and the engagement itself
is persisted to <out>/engagement.json after every state change, so a run
can be inspected (or resumed) at any point.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import catalog, dashboard, privacy, remediate, report, risk, scanner
from .model import QBOM, Component

DEFAULT_TARGET_PCT = 80.0
DEFAULT_MAX_ITERATIONS = 8
DEFAULT_MAX_ACTIONS_PER_ROUND = 3


# ---------------------------------------------------------------------------
# VEX-style status tracking, applied to post-quantum migration
# ---------------------------------------------------------------------------
# CERT-In's guideline mandates a VEX (Vulnerability Exploitability eXchange)
# document -- Not Affected / Affected / Fixed / Under Investigation -- for
# vulnerabilities discovered in a QBOM/CBOM (section 8.4.1.6). A Shor- or
# Grover-vulnerable algorithm still in use *is* the vulnerability this
# engagement tracks, so the same four-state vocabulary is reused here across
# iterations rather than inventing a parallel one.
VEX_NOT_AFFECTED, VEX_AFFECTED, VEX_FIXED, VEX_UNDER_INVESTIGATION = (
    "not_affected", "affected", "fixed", "under_investigation",
)


def build_vex(cur_counts: dict, prev_counts: Optional[dict]) -> dict:
    """One VEX entry per catalog_id that is or was a live concern -- i.e.
    excludes algorithms that are PQ_SAFE/HYBRID and were never flagged.
    `prev_counts` is None for iteration 1 (nothing can be "fixed" yet)."""
    prev_counts = prev_counts or {}
    vex = {}
    ids = set(cur_counts) | set(prev_counts)
    for cid in ids:
        alg = catalog.get(cid)
        cur_n = cur_counts.get(cid, 0)
        prev_n = prev_counts.get(cid, 0)
        if alg.threat in (catalog.SAFE, catalog.HYBRID):
            continue  # not a vulnerability; not part of the VEX document
        if cur_n == 0:
            if prev_n > 0:
                status = VEX_FIXED
            else:
                continue  # never seen, nothing to report
        elif alg.threat == catalog.UNKNOWN:
            status = VEX_UNDER_INVESTIGATION
        else:
            status = VEX_AFFECTED
        vex[cid] = {
            "status": status, "label": alg.label, "threat_class": alg.threat,
            "count": cur_n, "previous_count": prev_n, "replacement": alg.replacement,
        }
    return vex


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Consent:
    org: str
    accepted_by: str
    statement: str
    accepted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class IterationRecord:
    index: int
    timestamp: str
    scanned_root: str                 # "original" (read-only source) or "work_root" (post-remediation copy)
    findings_total: int
    readiness: dict                   # risk.readiness_summary() output
    migration_plan: list               # list of dicts (top items, highest score first)
    vex: dict                         # catalog_id -> VEX entry (this iteration)
    remediation_applied: list          # ChangeRecords applied BEFORE this iteration's scan
    target_met: bool
    decision: Optional[str] = None     # "continue" | "stop" | "target_met" | None (pending)
    attestation: Optional[dict] = None  # summary only, not the raw QBOM
    artifacts: dict = field(default_factory=dict)   # filename -> relative path, under this iteration's dir


@dataclass
class Engagement:
    engagement_id: str
    org: str
    source_path: str
    out_dir: str
    manifest_path: Optional[str]
    target_pct: float
    max_iterations: int
    max_actions_per_round: int
    created_at: str
    status: str = "PENDING_CONSENT"
    consent: Optional[Consent] = None
    iterations: list = field(default_factory=list)          # list[IterationRecord]
    remediation_applied_ids: list = field(default_factory=list)  # cumulative action ids, order of application

    # --- persistence ---------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def save(self) -> Path:
        p = Path(self.out_dir) / "engagement.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2))
        return p

    @property
    def work_root(self) -> Path:
        return Path(self.out_dir) / "workdir"

    @property
    def latest(self) -> Optional[IterationRecord]:
        return self.iterations[-1] if self.iterations else None


def load(out_dir: str | Path) -> Engagement:
    d = json.loads((Path(out_dir) / "engagement.json").read_text())
    consent = Consent(**d["consent"]) if d.get("consent") else None
    iterations = [IterationRecord(**it) for it in d.get("iterations", [])]
    d = {**d, "consent": consent, "iterations": iterations}
    return Engagement(**d)


# ---------------------------------------------------------------------------
# Step 1: commitment
# ---------------------------------------------------------------------------
def new_engagement(org: str, source_path: str, out_dir: str, manifest_path: Optional[str] = None,
                    target_pct: float = DEFAULT_TARGET_PCT, max_iterations: int = DEFAULT_MAX_ITERATIONS,
                    max_actions_per_round: int = DEFAULT_MAX_ACTIONS_PER_ROUND) -> Engagement:
    import uuid
    eng = Engagement(
        engagement_id=str(uuid.uuid4()), org=org, source_path=str(source_path), out_dir=str(out_dir),
        manifest_path=str(manifest_path) if manifest_path else None, target_pct=target_pct,
        max_iterations=max_iterations, max_actions_per_round=max_actions_per_round,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    eng.save()
    return eng


def give_consent(eng: Engagement, accepted_by: str,
                  statement: Optional[str] = None) -> Engagement:
    """The organisation's commitment to be assessed. Required before the
    first scan -- mirrors CERT-In's framing of SBOM/QBOM as something
    organisations opt into as standard procurement/development practice,
    not something imposed on them without their knowledge."""
    if eng.status != "PENDING_CONSENT":
        raise ValueError(f"engagement {eng.engagement_id} already has consent (status={eng.status})")
    stmt = statement or (
        f"{accepted_by}, on behalf of {eng.org}, authorises a Quantum Bill of Materials "
        f"assessment of {eng.source_path} against a target post-quantum readiness of "
        f"{eng.target_pct}%, understanding that raw findings never leave the organisation's "
        f"own infrastructure (see the zero-trust attestation layer)."
    )
    eng.consent = Consent(org=eng.org, accepted_by=accepted_by, statement=stmt)
    eng.status = "IN_PROGRESS"
    eng.save()
    return eng


# ---------------------------------------------------------------------------
# Step 2/3: scan + threat analysis + recommendations, one round
# ---------------------------------------------------------------------------
def _load_manifest_components(qbom: QBOM, manifest_path: Optional[str], root_for_matching: Path) -> dict:
    """Returns the path->component map so findings can be tagged."""
    if not manifest_path:
        return {}
    manifest = json.loads(Path(manifest_path).read_text())
    for name, c in manifest.get("components", {}).items():
        qbom.add_component(Component(
            name=name, exposure=c.get("exposure", "internal"),
            data_sensitivity=c.get("data_sensitivity", "medium"),
            data_lifetime_years=c.get("data_lifetime_years", 3.0), owner=c.get("owner", ""),
        ))
    return manifest.get("path_to_component", {})


def run_iteration(eng: Engagement, attest: bool = True) -> IterationRecord:
    if eng.status not in ("IN_PROGRESS",):
        raise ValueError(f"engagement {eng.engagement_id} is not accepting new iterations (status={eng.status})")

    index = len(eng.iterations) + 1
    # iteration 1 scans the original, read-only source; every later
    # iteration scans the working copy remediation has been applied to.
    if index == 1:
        scan_root = Path(eng.source_path)
        scanned_root_label = "original"
    else:
        scan_root = eng.work_root
        scanned_root_label = "work_root"

    findings = scanner.scan_directory(scan_root)
    qbom = QBOM(org=eng.org)
    path_map = _load_manifest_components(qbom, eng.manifest_path, scan_root)
    for f in findings:
        for prefix, comp_name in path_map.items():
            suffix = prefix.split("vulnerable-app/", 1)[-1] if "vulnerable-app/" in prefix else prefix
            if suffix and suffix in f.file_path:
                f.component = comp_name
                break
        qbom.add_finding(f)

    summary = risk.readiness_summary(qbom)
    plan = risk.build_migration_plan(qbom)
    prev_counts = eng.latest.readiness.get("_raw_counts") if eng.latest else None
    cur_counts = qbom.counts()
    vex = build_vex(cur_counts, prev_counts)
    summary_with_raw = {**summary, "_raw_counts": cur_counts}
    eng._last_qbom = qbom  # cached for write_final_summary(); not a dataclass field, never serialised

    iter_dir = Path(eng.out_dir) / "iterations" / f"iteration-{index}"
    iter_dir.mkdir(parents=True, exist_ok=True)
    (iter_dir / "qbom.json").write_text(qbom.to_json())
    (iter_dir / "qbom-cbom.json").write_text(json.dumps(report.to_cyclonedx_cbom(qbom), indent=2))
    (iter_dir / "qbom-report.md").write_text(report.to_markdown_report(qbom))
    report.to_pdf_report(qbom, str(iter_dir / "qbom-report.pdf"))
    (iter_dir / "vex.json").write_text(json.dumps(vex, indent=2))

    attestation_summary = None
    if attest:
        att = privacy.build_attestation(qbom)
        # Prove zero-count for anything that was affected in a *previous*
        # iteration and is fixed as of this one -- the flagship zero-trust
        # claim: "RSA-SUB2048 is now provably absent" without ever
        # publishing the findings themselves.
        for cid, entry in vex.items():
            if entry["status"] == VEX_FIXED:
                privacy.prove_zero(att, cid)
        public = att.to_public_dict()
        (iter_dir / "attestation.public.json").write_text(json.dumps(public, indent=2))
        attestation_summary = {
            "commitments": len(public.get("catalog_commitments", {})),
            "leaves": public.get("leaf_count", len(qbom.findings)),
            "zero_proofs_published": len(public.get("zero_proofs", {})),
            "merkle_root": public.get("merkle_root", "n/a"),
        }

    target_met = summary["pq_ready_pct"] >= eng.target_pct
    record = IterationRecord(
        index=index, timestamp=datetime.now(timezone.utc).isoformat(), scanned_root=scanned_root_label,
        findings_total=summary["total_findings"], readiness=summary_with_raw,
        migration_plan=[asdict(item) for item in plan[:25]], vex=vex,
        remediation_applied=[], target_met=target_met,
        attestation=attestation_summary,
        artifacts={
            "qbom": f"iterations/iteration-{index}/qbom.json",
            "cbom": f"iterations/iteration-{index}/qbom-cbom.json",
            "report_md": f"iterations/iteration-{index}/qbom-report.md",
            "report_pdf": f"iterations/iteration-{index}/qbom-report.pdf",
            "dashboard": f"iterations/iteration-{index}/qbom-dashboard.html",
            "vex": f"iterations/iteration-{index}/vex.json",
            **({"attestation": f"iterations/iteration-{index}/attestation.public.json"} if attest else {}),
        },
    )
    # Append (and resolve target-met status) BEFORE rendering the dashboard,
    # so the engagement timeline panel includes this iteration itself and
    # shows the final status badge, not a stale one from the previous round.
    eng.iterations.append(record)
    if target_met:
        record.decision = "target_met"
        eng.status = "TARGET_MET"
    (iter_dir / "qbom-dashboard.html").write_text(
        dashboard.build_dashboard_html(qbom, attestation_summary=attestation_summary, engagement=eng)
    )
    eng.save()
    return record


# ---------------------------------------------------------------------------
# Step 4: the org's decision gate
# ---------------------------------------------------------------------------
def decide_continue(eng: Engagement, accept: bool) -> Engagement:
    """Record whether the org accepts the current readiness % and wants
    the loop to continue. Only meaningful when the latest iteration did
    NOT already hit the target (that path auto-resolves to TARGET_MET in
    run_iteration)."""
    latest = eng.latest
    if latest is None or latest.decision is not None:
        return eng
    if accept:
        latest.decision = "continue"
        if len(eng.iterations) >= eng.max_iterations:
            eng.status = "MAX_ITERATIONS"
        else:
            eng.status = "IN_PROGRESS"
    else:
        latest.decision = "stop"
        eng.status = "ENDED_BY_ORG"
    eng.save()
    return eng


# ---------------------------------------------------------------------------
# Step 5: infra applies recommendations (simulated for this demo -- see
# remediate.py's module docstring for what a real deployment swaps in here)
# ---------------------------------------------------------------------------
def apply_remediation(eng: Engagement) -> list:
    remediate.prepare_workdir(eng.source_path, eng.work_root)
    applied = set(eng.remediation_applied_ids)
    plan_items = [
        risk.MigrationItem(**{**it, }) for it in (eng.latest.migration_plan if eng.latest else [])
    ] if eng.latest else []
    changes = remediate.apply_round(eng.work_root, plan_items, applied, max_actions=eng.max_actions_per_round)
    eng.remediation_applied_ids = sorted(applied)
    if eng.latest is not None:
        eng.latest.remediation_applied = [asdict(c) for c in changes]
    eng.save()
    return changes


# ---------------------------------------------------------------------------
# The full loop, for CLI / demo convenience
# ---------------------------------------------------------------------------
def run_full_loop(eng: Engagement, accept_fn=None, attest: bool = True, verbose: bool = True) -> Engagement:
    """Drives the whole commitment -> scan -> recommend -> decide ->
    remediate -> rescan cycle to completion.

    `accept_fn(readiness_summary, iteration_record) -> bool` decides
    whether to accept the current readiness % and continue when the target
    hasn't been met yet; defaults to always-accept (full auto-pilot, for a
    non-interactive demo run). Pass a function that calls `input()` for an
    interactive CLI session.
    """
    if accept_fn is None:
        accept_fn = lambda summary, record: True  # noqa: E731

    if eng.status == "PENDING_CONSENT":
        raise ValueError("call give_consent() before run_full_loop()")

    while eng.status == "IN_PROGRESS":
        record = run_iteration(eng, attest=attest)
        if verbose:
            r = record.readiness
            print(f"[iteration {record.index}] scanned {record.scanned_root}: "
                  f"{record.findings_total} findings | PQ-ready {r['pq_ready_pct']}% "
                  f"(target {eng.target_pct}%)")
        if record.target_met:
            if verbose:
                print(f"  target reached -- engagement complete ({eng.status}).")
            break
        accept = accept_fn(record.readiness, record)
        decide_continue(eng, accept)
        if eng.status == "ENDED_BY_ORG":
            if verbose:
                print("  org declined to continue -- engagement ended without reaching target.")
            break
        changes = apply_remediation(eng)
        if verbose:
            for c in changes:
                print(f"  applied: {c.title}")
            if not changes:
                print("  no further automated remediation available for the current top priorities.")
        if eng.status == "MAX_ITERATIONS":
            if verbose:
                print(f"  max iterations ({eng.max_iterations}) reached without hitting target.")
            break

    write_final_summary(eng)
    return eng


def write_final_summary(eng: Engagement) -> Path:
    """A consolidated engagement report spanning every iteration -- the
    thing you'd actually hand to a CISO or a regulator at the end of the
    engagement, as opposed to any single iteration's own report."""
    out = Path(eng.out_dir) / "final"
    out.mkdir(parents=True, exist_ok=True)
    final_qbom = getattr(eng, "_last_qbom", None)
    if final_qbom is None and eng.latest is not None:
        # loaded from disk in a fresh process -- rebuild it from the
        # iteration's own persisted qbom.json rather than re-scanning.
        qbom_path = Path(eng.out_dir) / eng.latest.artifacts["qbom"]
        if qbom_path.exists():
            final_qbom = _qbom_from_dict(json.loads(qbom_path.read_text()))
    report.to_engagement_pdf_report(eng, str(out / "qbom-engagement-report.pdf"), final_qbom=final_qbom)
    (out / "engagement-summary.json").write_text(json.dumps(eng.to_dict(), indent=2))
    if eng.latest is not None:
        latest_dashboard = Path(eng.out_dir) / eng.latest.artifacts["dashboard"]
        if latest_dashboard.exists():
            (out / "qbom-dashboard.html").write_text(latest_dashboard.read_text())
    return out / "qbom-engagement-report.pdf"


def _qbom_from_dict(d: dict) -> QBOM:
    """Rebuild a (secret-less) QBOM from a persisted qbom.json for report
    purposes only -- findings carry no salt (qbom.json never has one; see
    Finding.to_public_dict), which is fine here since nothing downstream of
    this needs it."""
    from .model import Finding
    q = QBOM(org=d["org"], generated_at=d["generated_at"], catalog_version=d["catalog_version"],
              catalog_hash=d["catalog_hash"])
    for name, c in d.get("components", {}).items():
        q.components[name] = Component(**c)
    for fd in d.get("findings", []):
        fd = dict(fd)
        q.findings.append(Finding(**fd))
    return q
