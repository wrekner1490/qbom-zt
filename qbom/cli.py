from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import dashboard, privacy, report, risk, scanner, workflow
from .model import QBOM, Component


def cmd_scan(args):
    findings = scanner.scan_directory(args.path)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    org_secret = _load_or_create_org_secret(out_dir)
    qbom = QBOM(org=args.org, org_secret=org_secret)

    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text())
        for name, c in manifest.get("components", {}).items():
            qbom.add_component(Component(
                name=name, exposure=c.get("exposure", "internal"),
                data_sensitivity=c.get("data_sensitivity", "medium"),
                data_lifetime_years=c.get("data_lifetime_years", 3.0),
                owner=c.get("owner", ""),
            ))
        path_map = manifest.get("path_to_component", {})
        for f in findings:
            for prefix, comp_name in path_map.items():
                if f.file_path.startswith(prefix):
                    f.component = comp_name
                    break

    for f in findings:
        qbom.add_finding(f)

    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "qbom.json").write_text(qbom.to_json())
    (out_dir / "qbom-cbom.json").write_text(json.dumps(report.to_cyclonedx_cbom(qbom), indent=2))
    (out_dir / "qbom-report.md").write_text(report.to_markdown_report(qbom))
    report.to_pdf_report(qbom, str(out_dir / "qbom-report.pdf"))

    summary = risk.readiness_summary(qbom)
    print(f"Scanned {args.path}")
    print(f"  {summary['total_findings']} findings across {summary['distinct_algorithms']} algorithms")
    print(f"  PQ-ready: {summary['pq_ready_pct']}%  |  Shor-vulnerable: {summary['shor_vulnerable_pct']}%  |  "
          f"Grover-weakened: {summary['grover_weakened_pct']}%  |  "
          f"Classically broken: {summary['classically_broken_pct']}%")
    print(f"Wrote: {out_dir}/qbom.json, qbom-cbom.json, qbom-report.md, qbom-report.pdf")

    attestation_summary = None
    if args.attest:
        _write_local_qbom_for_attest(qbom, out_dir)
        att = privacy.build_attestation(qbom)
        proofs_issued = 0
        for cid in args.prove_zero or []:
            privacy.prove_zero(att, cid)
            proofs_issued += 1
        for spec in args.prove_below or []:
            cid, thr = spec.split("<")
            privacy.prove_below_threshold_for_qbom(qbom, att, cid.strip(), int(thr.strip()))
            proofs_issued += 1
        public = att.to_public_dict()
        (out_dir / "attestation.public.json").write_text(json.dumps(public, indent=2))
        print(f"Wrote: {out_dir}/attestation.public.json  (safe to share -- contains no raw findings)")
        attestation_summary = {
            "commitments": len(public.get("catalog_commitments", {})),
            "leaves": public.get("leaf_count", len(qbom.findings)),
            "proofs": proofs_issued,
            "merkle_root": public.get("merkle_root", "n/a"),
        }

    (out_dir / "qbom-dashboard.html").write_text(
        dashboard.build_dashboard_html(qbom, attestation_summary=attestation_summary)
    )
    print(f"Wrote: {out_dir}/qbom-dashboard.html")


def _load_or_create_org_secret(out_dir: Path) -> bytes:
    """The org secret lives ONLY in <out_dir>/LOCAL_ONLY_org_secret.hex, next
    to the other LOCAL_ONLY artifacts -- never in anything published. It
    must stay stable across scans for remediation proofs (see model.py) to
    mean anything; a fresh secret on every run would silently make every
    finding's salt change even when nothing in the code changed."""
    import secrets as _secrets
    secret_path = out_dir / "LOCAL_ONLY_org_secret.hex"
    if secret_path.exists():
        return bytes.fromhex(secret_path.read_text().strip())
    secret = _secrets.token_bytes(32)
    secret_path.write_text(secret.hex())
    return secret


def _write_local_qbom_for_attest(qbom: QBOM, out_dir: Path):
    # findings carry per-item salts needed later for selective disclosure;
    # keep this file OUT of anything meant to be shared externally.
    local = {
        "org": qbom.org,
        "findings_with_salts": [
            {**f.to_public_dict(), "salt": f.salt.hex()} for f in qbom.findings
        ],
    }
    (out_dir / "LOCAL_ONLY_qbom_with_salts.json").write_text(json.dumps(local, indent=2))


def cmd_verify(args):
    public = json.loads(Path(args.attestation).read_text())
    if args.zero:
        print(f"zero({args.zero}):", privacy.verify_zero_proof(public, args.zero))
    if args.below:
        cid, _ = args.below.split("<")
        print(f"below({args.below}):", privacy.verify_threshold_proof(public, cid.strip()))
    if args.disclosure_index is not None:
        print(f"finding_disclosure[{args.disclosure_index}]:",
              privacy.verify_finding_disclosure(public, args.disclosure_index))


def _interactive_accept(summary, record):
    ans = input(f"  Readiness is {summary['pq_ready_pct']}% (target below). Accept and continue "
                f"the loop? [y/N] ").strip().lower()
    return ans in ("y", "yes")


def cmd_engage(args):
    if Path(args.out, "engagement.json").exists() and not args.new:
        eng = workflow.load(args.out)
        print(f"Resuming engagement {eng.engagement_id} (status={eng.status})")
    else:
        eng = workflow.new_engagement(
            org=args.org, source_path=args.path, out_dir=args.out, manifest_path=args.manifest,
            target_pct=args.target, max_iterations=args.max_iterations,
            max_actions_per_round=args.max_actions_per_round,
        )
        eng = workflow.give_consent(eng, accepted_by=args.accepted_by)

    accept_fn = _interactive_accept if args.interactive else (lambda summary, record: True)
    eng = workflow.run_full_loop(eng, accept_fn=accept_fn, attest=not args.no_attest)

    print(f"\nEngagement {eng.engagement_id}: {eng.status} after {len(eng.iterations)} iteration(s)")
    if eng.latest:
        print(f"  Final PQ-readiness: {eng.latest.readiness['pq_ready_pct']}% (target {eng.target_pct}%)")
    print(f"Wrote: {eng.out_dir}/final/qbom-engagement-report.pdf")
    print(f"Wrote: {eng.out_dir}/final/qbom-dashboard.html")
    print(f"Wrote: {eng.out_dir}/engagement.json")


def cmd_engage_status(args):
    eng = workflow.load(args.out)
    print(f"Engagement {eng.engagement_id}  org={eng.org}  status={eng.status}")
    print(f"target={eng.target_pct}%  max_iterations={eng.max_iterations}")
    for it in eng.iterations:
        r = it.readiness
        print(f"  iter {it.index} [{it.scanned_root}]: {it.findings_total} findings, "
              f"PQ-ready {r['pq_ready_pct']}%, decision={it.decision}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="qbom", description="Automated QBOM framework for post-quantum readiness")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a codebase and produce a QBOM + migration plan")
    s.add_argument("path")
    s.add_argument("--org", default="unknown-org")
    s.add_argument("--out", default="./qbom-out")
    s.add_argument("--manifest", help="JSON manifest mapping paths to components (exposure/sensitivity/lifetime)")
    s.add_argument("--attest", action="store_true", help="Also produce a zero-knowledge public attestation")
    s.add_argument("--prove-zero", action="append", help="catalog_id to prove has zero occurrences (repeatable)")
    s.add_argument("--prove-below", action="append", help="e.g. 'RSA-SUB2048<5' (repeatable)")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify", help="Verify claims in a published attestation.public.json")
    v.add_argument("attestation")
    v.add_argument("--zero", help="catalog_id to check a zero-count proof for")
    v.add_argument("--below", help="e.g. 'RSA-SUB2048<5' to check a threshold proof for")
    v.add_argument("--disclosure-index", type=int, help="index into finding_disclosures to verify")
    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("engage", help="Run the full commit -> scan -> recommend -> remediate -> "
                                       "rescan loop until a target PQ-readiness %% is reached")
    e.add_argument("path", help="directory to scan (iteration 1 only; later iterations scan the "
                                 "working copy remediation is applied to)")
    e.add_argument("--org", default="unknown-org")
    e.add_argument("--out", default="./qbom-engagement")
    e.add_argument("--manifest", help="JSON manifest mapping paths to components")
    e.add_argument("--target", type=float, default=workflow.DEFAULT_TARGET_PCT,
                    help="target PQ-readiness %% to stop at (default: %(default)s)")
    e.add_argument("--max-iterations", type=int, default=workflow.DEFAULT_MAX_ITERATIONS)
    e.add_argument("--max-actions-per-round", type=int, default=workflow.DEFAULT_MAX_ACTIONS_PER_ROUND)
    e.add_argument("--accepted-by", default="unspecified", help="name/role recorded as giving consent")
    e.add_argument("--interactive", action="store_true",
                    help="prompt y/N at each accept-and-continue decision instead of auto-accepting")
    e.add_argument("--no-attest", action="store_true", help="skip the zero-trust attestation step")
    e.add_argument("--new", action="store_true", help="start a fresh engagement even if --out already has one")
    e.set_defaults(func=cmd_engage)

    es = sub.add_parser("engage-status", help="Show the status of an existing engagement")
    es.add_argument("--out", default="./qbom-engagement")
    es.set_defaults(func=cmd_engage_status)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
