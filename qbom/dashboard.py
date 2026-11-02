"""
Self-contained HTML dashboard: "under the hood" view of one scan run.

Three things a plain qbom-report.md doesn't show, which this does:

  1. Pipeline: which of the three independent static analysers (Python AST,
     config/text pattern matching, X.509/PEM structural parsing) actually
     fired, how many findings each contributed, and which concrete rule
     inside that analyser matched (see scanner.py's module docstring for
     why there are exactly these three shapes of crypto usage).
  2. Threat-class mix of what was found, as a quick visual read.
  3. The *entire* algorithm/protocol catalog (catalog.py, append-only, fixed
     order) with every entry the scanner is capable of recognising --
     entries actually seen in this codebase are lit up green with their
     occurrence count; everything else is shown dimmed, so "what could we
     have found but didn't" is as visible as "what we found".

No external JS/CSS dependencies -- this file is meant to be opened straight
from disk, offline, next to qbom-report.md/.pdf.
"""
from __future__ import annotations

import html
from collections import Counter, defaultdict

from . import catalog, risk
from .model import QBOM

_ANALYSERS = [
    ("python-ast", "Python AST Analyser",
     "Parses Python source with ast (never executes it) and matches call sites "
     "against known crypto APIs -- hashlib, cryptography, pycryptodome key/cipher constructors."),
    ("regex", "Config &amp; Text Pattern Analyser",
     "Line-oriented pattern extractors for declarative config (sshd, nginx, Apache, "
     "openssl.cnf, Java/Node crypto calls, JWT alg headers) resolved through the same catalog tokenizer."),
    ("x509-cert", "X.509 Certificate Analyser",
     "Structurally parses certificates with the `cryptography` library and reads the "
     "public-key algorithm and signature-hash algorithm directly -- no guessing."),
    ("pem", "PEM Private Key Analyser",
     "Structurally parses PEM private keys and classifies the key type/curve/size."),
]
_ANALYSER_ORDER = {k: i for i, (k, _, _) in enumerate(_ANALYSERS)}

_THREAT_META = {
    "SHOR": ("#DC2626", "Shor-vulnerable", "Existential break under a cryptographically relevant quantum computer."),
    "GROVER": ("#D97706", "Grover-weakened", "Effective security roughly halved; margin fix, not a redesign."),
    "CLASSICAL_BROKEN": ("#991B1B", "Classically broken", "Already exploitable today, no quantum computer needed."),
    "PQ_SAFE": ("#16A34A", "Quantum-safe", "NIST-standardised PQC, or adequate symmetric/hash margin."),
    "HYBRID": ("#0D9488", "Hybrid classical+PQ", "Already combines a classical scheme with a PQ one."),
    "LEGACY_PQ": ("#7C3AED", "Pre-standard PQ", "Right idea, not wire-compatible with the final FIPS standard."),
    "UNKNOWN": ("#6B7280", "Unclassified", "Could not be matched to a known algorithm."),
}
_THREAT_ORDER = ["SHOR", "CLASSICAL_BROKEN", "GROVER", "LEGACY_PQ", "HYBRID", "PQ_SAFE", "UNKNOWN"]


def _analyser_key(source: str) -> str:
    prefix = source.split(":", 1)[0]
    return prefix if prefix in _ANALYSER_ORDER else prefix


def _build_engagement_panel(engagement) -> str:
    """Renders the commitment -> scan -> recommend -> decide -> remediate ->
    rescan loop as a timeline: one step per iteration, readiness % climbing
    toward the target, with the decision and remediation count at each
    step. Pure presentation over qbom.workflow.Engagement -- no new
    scoring logic lives here."""
    iterations = engagement.iterations
    target = engagement.target_pct
    steps = []
    for it in iterations:
        r = it.readiness
        pct = r["pq_ready_pct"]
        met = it.target_met
        decision = it.decision or "pending"
        decision_label = {
            "continue": "Accepted \u2014 continued", "stop": "Declined \u2014 stopped",
            "target_met": "Target reached", "pending": "Awaiting decision",
        }.get(decision, decision)
        bar_color = "#16A34A" if met else ("#3B82F6" if decision == "continue" else "#D97706")
        n_changes = len(it.remediation_applied)
        steps.append(f"""
        <div class="eng-step">
          <div class="eng-step-head">
            <span class="eng-step-badge" style="background:{bar_color}">{it.index}</span>
            <div>
              <div class="eng-step-title">Iteration {it.index} &middot; scanned {html.escape(it.scanned_root)}</div>
              <div class="eng-step-sub">{it.findings_total} findings &middot; {decision_label}
                {f' &middot; {n_changes} remediation action(s) applied next' if n_changes else ''}</div>
            </div>
            <div class="eng-step-pct" style="color:{bar_color}">{pct}%</div>
          </div>
          <div class="eng-step-bar-track">
            <div class="eng-step-bar-fill" style="width:{min(pct,100)}%;background:{bar_color}"></div>
            <div class="eng-step-target-mark" style="left:{min(target,100)}%" title="target {target}%"></div>
          </div>
        </div>""")

    consent_html = ""
    if engagement.consent:
        c = engagement.consent
        consent_html = (f'<p class="panel-desc"><b>Consent:</b> {html.escape(c.accepted_by)} on behalf of '
                         f'{html.escape(c.org)}, {html.escape(c.accepted_at)}.</p>')

    status_meta = {
        "PENDING_CONSENT": ("#6B7280", "Awaiting commitment"),
        "IN_PROGRESS": ("#3B82F6", "In progress"),
        "TARGET_MET": ("#16A34A", "Target reached"),
        "ENDED_BY_ORG": ("#D97706", "Ended by organisation"),
        "MAX_ITERATIONS": ("#D97706", "Max iterations reached"),
    }.get(engagement.status, ("#6B7280", engagement.status))

    return f"""
      <section class="panel eng-panel">
        <h2>0&nbsp;&middot;&nbsp;Engagement loop
          <span class="eng-status" style="background:{status_meta[0]}22;color:{status_meta[0]};border:1px solid {status_meta[0]}55;">{status_meta[1]}</span>
        </h2>
        <p class="panel-desc">Commit &#8594; scan &#8594; threat analysis &amp; recommendations &#8594;
          organisation accepts the readiness % and continues, or stops &#8594; recommendations applied to
          infra &#8594; rescan &#8594; repeat until <b>{target}%</b> post-quantum readiness is reached or the
          organisation ends the loop. Target line shown as a marker on each bar.</p>
        {consent_html}
        <div class="eng-steps">{''.join(steps)}</div>
      </section>"""


def build_dashboard_html(qbom: QBOM, attestation_summary: dict | None = None, engagement=None) -> str:
    findings = qbom.findings
    counts = qbom.counts()
    summary = risk.readiness_summary(qbom)
    total = summary["total_findings"]

    # --- per-analyser stats -------------------------------------------------
    by_analyser: dict[str, list] = defaultdict(list)
    for f in findings:
        by_analyser[_analyser_key(f.source)].append(f)

    analyser_cards = []
    known_keys = {k for k, _, _ in _ANALYSERS}
    ordered_keys = [k for k, _, _ in _ANALYSERS if k in by_analyser] + \
                   sorted(k for k in by_analyser if k not in known_keys)
    meta_by_key = {k: (name, desc) for k, name, desc in _ANALYSERS}
    for key in ordered_keys:
        items = by_analyser[key]
        name, desc = meta_by_key.get(key, (key, "Additional pattern rules."))
        rule_counts = Counter(f.source for f in items)
        top_rules = rule_counts.most_common(6)
        pct = round(100 * len(items) / total, 1) if total else 0.0
        rules_html = "".join(
            f'<li><code>{html.escape(r)}</code><span class="rc">{c}</span></li>'
            for r, c in top_rules
        )
        more = len(rule_counts) - len(top_rules)
        if more > 0:
            rules_html += f'<li class="more">+{more} more rule(s)</li>'
        analyser_cards.append(f"""
        <div class="stage-card">
          <div class="stage-head">
            <span class="stage-badge">{len(items)}</span>
            <h3>{name}</h3>
          </div>
          <p class="stage-desc">{desc}</p>
          <div class="stage-bar-track"><div class="stage-bar-fill" style="width:{pct}%"></div></div>
          <div class="stage-pct">{pct}% of all findings</div>
          <ul class="rule-list">{rules_html or '<li class="more">no findings from this analyser</li>'}</ul>
        </div>""")

    if not findings:
        analyser_cards.append('<div class="stage-card empty">No findings were produced by any analyser.</div>')

    # --- threat-class breakdown ----------------------------------------------
    by_threat = summary["by_threat_class"]
    threat_rows = []
    for t in _THREAT_ORDER:
        n = by_threat.get(t, 0)
        if n == 0 and t not in by_threat:
            continue
        color, label, desc = _THREAT_META[t]
        pct = round(100 * n / total, 1) if total else 0.0
        threat_rows.append(f"""
        <div class="threat-row">
          <div class="threat-label"><span class="dot" style="background:{color}"></span>{label}
            <span class="threat-sub">{desc}</span></div>
          <div class="threat-bar-track"><div class="threat-bar-fill" style="width:{pct}%;background:{color}"></div></div>
          <div class="threat-count">{n} <span class="threat-pct">({pct}%)</span></div>
        </div>""")

    # --- full catalog grid, grouped by threat class, in catalog order -------
    groups: dict[str, list] = defaultdict(list)
    for alg_id in catalog.CATALOG_IDS:
        alg = catalog.get(alg_id)
        groups[alg.threat].append(alg)

    catalog_sections = []
    total_algs = len(catalog.CATALOG_IDS)
    seen_algs = len(counts)
    for t in _THREAT_ORDER:
        algs = groups.get(t)
        if not algs:
            continue
        color, label, _ = _THREAT_META[t]
        tiles = []
        for alg in algs:
            n = counts.get(alg.id, 0)
            found = n > 0
            cls = "tile found" if found else "tile"
            badge = f'<span class="tile-count">{n}</span>' if found else ""
            style = f'style="--tc:{color}"' if found else ""
            tiles.append(
                f'<div class="{cls}" {style} title="{html.escape(alg.label)} '
                f'({html.escape(alg.id)}) &mdash; {"seen " + str(n) + "x" if found else "not observed in this scan"}">'
                f'<span class="tile-name">{html.escape(alg.label)}</span>'
                f'<span class="tile-id">{html.escape(alg.id)}</span>{badge}</div>'
            )
        found_in_group = sum(1 for a in algs if counts.get(a.id, 0) > 0)
        catalog_sections.append(f"""
        <div class="catalog-section">
          <div class="catalog-section-head">
            <span class="dot" style="background:{color}"></span>
            <h4>{label}</h4>
            <span class="catalog-section-sub">{found_in_group}/{len(algs)} seen in this scan</span>
          </div>
          <div class="tile-grid">{''.join(tiles)}</div>
        </div>""")

    # --- optional zero-trust attestation panel -------------------------------
    zt_html = ""
    if attestation_summary:
        zt_html = f"""
      <section class="panel">
        <h2>5&nbsp;&middot;&nbsp;Zero-trust attestation layer</h2>
        <p class="panel-desc">Findings never leave this machine. What can cross the trust boundary is a small
          bundle of Pedersen commitments and a sorted Merkle root, generated with <code>--attest</code>.</p>
        <div class="metrics-grid">
          <div class="metric"><div class="metric-val">{attestation_summary.get('commitments', 0)}</div><div class="metric-label">per-algorithm commitments</div></div>
          <div class="metric"><div class="metric-val">{attestation_summary.get('leaves', 0)}</div><div class="metric-label">Merkle leaves (findings)</div></div>
          <div class="metric"><div class="metric-val">{attestation_summary.get('proofs', 0)}</div><div class="metric-label">zero/threshold proofs issued</div></div>
        </div>
        <div class="mono-box">merkle_root = {html.escape(attestation_summary.get('merkle_root', 'n/a'))}</div>
      </section>"""
    else:
        zt_html = """
      <section class="panel">
        <h2>5&nbsp;&middot;&nbsp;Zero-trust attestation layer</h2>
        <p class="panel-desc">Not run for this scan. Re-run with <code>qbom scan ... --attest</code> to publish a
          Pedersen-commitment + Merkle-root attestation that discloses aggregate proofs
          (e.g. "RSA-SUB2048 count == 0") without ever exposing the underlying findings.</p>
      </section>"""

    # --- optional engagement / iteration-loop panel ---------------------------
    engagement_html = ""
    if engagement is not None:
        engagement_html = _build_engagement_panel(engagement)

    generated_note = qbom.generated_at

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QBOM Dashboard &mdash; {html.escape(qbom.org)}</title>
<style>
  :root {{
    --bg:#0B1220; --panel:#111A2E; --panel2:#0E1626; --border:#22304A;
    --text:#E5EAF3; --muted:#8B9AB8; --accent:#3B82F6;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:28px 32px 20px; border-bottom:1px solid var(--border);
            background:linear-gradient(180deg,#101A30,#0B1220); }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  header .org {{ color:var(--accent); font-weight:600; }}
  header .meta {{ color:var(--muted); font-size:12.5px; margin-top:6px; }}
  main {{ max-width:1180px; margin:0 auto; padding:24px 32px 60px; }}
  .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:14px;
            padding:22px 24px; margin-bottom:26px; }}
  .panel h2 {{ margin:0 0 6px; font-size:16px; }}
  .panel-desc {{ color:var(--muted); font-size:13px; margin:0 0 16px; line-height:1.5; }}
  code {{ background:#0A1122; padding:1px 5px; border-radius:4px; font-size:12px; color:#9DC0FF; }}

  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:4px; }}
  .summary-card {{ background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
  .summary-card .v {{ font-size:24px; font-weight:700; }}
  .summary-card .l {{ font-size:11.5px; color:var(--muted); margin-top:2px; }}

  .pipeline-flow {{ display:flex; align-items:center; gap:6px; margin:6px 0 22px; flex-wrap:wrap; font-size:12.5px; color:var(--muted); }}
  .pipeline-flow .node {{ background:var(--panel2); border:1px solid var(--border); border-radius:8px; padding:6px 12px; color:var(--text); }}
  .pipeline-flow .arrow {{ color:var(--accent); }}

  .stage-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; }}
  .stage-card {{ background:var(--panel2); border:1px solid var(--border); border-radius:12px; padding:16px; }}
  .stage-card.empty {{ color:var(--muted); text-align:center; padding:30px; }}
  .stage-head {{ display:flex; align-items:center; gap:10px; }}
  .stage-badge {{ background:var(--accent); color:white; font-weight:700; font-size:13px;
                  border-radius:8px; padding:3px 9px; }}
  .stage-head h3 {{ margin:0; font-size:14px; }}
  .stage-desc {{ color:var(--muted); font-size:12px; line-height:1.5; margin:8px 0 10px; }}
  .stage-bar-track {{ height:6px; background:#1B2740; border-radius:4px; overflow:hidden; }}
  .stage-bar-fill {{ height:100%; background:var(--accent); }}
  .stage-pct {{ font-size:11px; color:var(--muted); margin:4px 0 10px; }}
  .rule-list {{ list-style:none; margin:0; padding:0; font-size:11.5px; }}
  .rule-list li {{ display:flex; justify-content:space-between; padding:3px 0; border-top:1px solid var(--border); }}
  .rule-list li:first-child {{ border-top:none; }}
  .rule-list .rc {{ color:var(--accent); font-weight:700; }}
  .rule-list .more {{ color:var(--muted); font-style:italic; justify-content:flex-start; }}

  .threat-row {{ display:grid; grid-template-columns:280px 1fr 90px; align-items:center; gap:14px; padding:8px 0; }}
  .threat-label {{ font-size:13px; display:flex; flex-direction:column; }}
  .threat-sub {{ color:var(--muted); font-size:11px; margin-top:2px; }}
  .dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; }}
  .threat-bar-track {{ height:10px; background:#1B2740; border-radius:5px; overflow:hidden; }}
  .threat-bar-fill {{ height:100%; }}
  .threat-count {{ text-align:right; font-weight:700; font-size:13px; }}
  .threat-pct {{ color:var(--muted); font-weight:400; font-size:11px; }}

  .catalog-legend {{ display:flex; gap:18px; font-size:12px; color:var(--muted); margin-bottom:14px; flex-wrap:wrap; }}
  .catalog-legend .sw {{ display:inline-block; width:12px; height:12px; border-radius:3px; margin-right:6px; vertical-align:-1px; }}
  .catalog-section {{ margin-bottom:20px; }}
  .catalog-section-head {{ display:flex; align-items:center; gap:8px; margin-bottom:8px; }}
  .catalog-section-head h4 {{ margin:0; font-size:13.5px; }}
  .catalog-section-sub {{ color:var(--muted); font-size:11.5px; margin-left:auto; }}
  .tile-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:8px; }}
  .tile {{ position:relative; background:#0E1626; border:1px solid var(--border); border-radius:8px;
           padding:8px 10px; opacity:0.42; filter:grayscale(0.6); }}
  .tile.found {{ opacity:1; filter:none; border-color:var(--tc,#16A34A); background:linear-gradient(135deg,rgba(255,255,255,0.02),transparent); box-shadow:0 0 0 1px var(--tc,#16A34A) inset; }}
  .tile-name {{ display:block; font-size:12px; font-weight:600; }}
  .tile-id {{ display:block; font-size:10px; color:var(--muted); margin-top:2px; font-family:monospace; }}
  .tile-count {{ position:absolute; top:6px; right:8px; background:var(--tc,#16A34A); color:#03170A;
                 font-size:10.5px; font-weight:800; border-radius:999px; padding:1px 7px; }}

  .metrics-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:14px; }}
  .metric {{ background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:14px; text-align:center; }}
  .metric-val {{ font-size:22px; font-weight:700; }}
  .metric-label {{ font-size:11px; color:var(--muted); margin-top:4px; }}
  .mono-box {{ font-family:monospace; font-size:11px; color:#9DC0FF; background:#0A1122;
               border:1px solid var(--border); border-radius:8px; padding:10px 12px; word-break:break-all; }}
  footer {{ text-align:center; color:var(--muted); font-size:11px; padding:20px; }}

  .eng-panel {{ border-color:#2A4A7A; background:linear-gradient(180deg,#101C33,#111A2E); }}
  .eng-status {{ font-size:11px; font-weight:700; padding:3px 10px; border-radius:999px; margin-left:10px; vertical-align:2px; }}
  .eng-steps {{ display:flex; flex-direction:column; gap:12px; margin-top:10px; }}
  .eng-step {{ background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:12px 14px; }}
  .eng-step-head {{ display:flex; align-items:center; gap:12px; }}
  .eng-step-badge {{ min-width:22px; height:22px; border-radius:50%; color:#03170A; font-weight:800;
                      font-size:12px; display:flex; align-items:center; justify-content:center; padding:0 5px; }}
  .eng-step-title {{ font-size:13px; font-weight:600; }}
  .eng-step-sub {{ font-size:11.5px; color:var(--muted); margin-top:2px; }}
  .eng-step-pct {{ margin-left:auto; font-size:18px; font-weight:800; }}
  .eng-step-bar-track {{ position:relative; height:8px; background:#1B2740; border-radius:4px; margin-top:8px; overflow:visible; }}
  .eng-step-bar-fill {{ height:100%; border-radius:4px; }}
  .eng-step-target-mark {{ position:absolute; top:-3px; width:2px; height:14px; background:#F8FAFC; opacity:0.85; }}
</style>
</head>
<body>
<header>
  <h1>QBOM Dashboard &mdash; <span class="org">{html.escape(qbom.org)}</span></h1>
  <div class="meta">Generated {html.escape(generated_note)} &middot; catalog v{html.escape(qbom.catalog_version)}
    ({html.escape(qbom.catalog_hash[:16])}...) &middot; {seen_algs}/{total_algs} catalog entries observed</div>
</header>
<main>

  {engagement_html}

  <section class="summary-grid" style="margin-bottom:26px;">
    <div class="summary-card"><div class="v">{total}</div><div class="l">total findings</div></div>
    <div class="summary-card"><div class="v">{summary['distinct_algorithms']}</div><div class="l">distinct algorithms/protocols</div></div>
    <div class="summary-card"><div class="v">{len(ordered_keys)}</div><div class="l">analysers that fired</div></div>
    <div class="summary-card"><div class="v">{summary['pq_ready_pct']}%</div><div class="l">quantum-safe today</div></div>
    <div class="summary-card"><div class="v">{summary['shor_vulnerable_pct']}%</div><div class="l">Shor-vulnerable</div></div>
  </section>

  <section class="panel">
    <h2>1&nbsp;&middot;&nbsp;Pipeline</h2>
    <p class="panel-desc">Every scan runs the same fixed pipeline: no crawling, no execution of target code,
      no network access needed to produce a QBOM.</p>
    <div class="pipeline-flow">
      <span class="node">Directory walk</span><span class="arrow">&#8594;</span>
      <span class="node">3 static analysers (parallel, per-file)</span><span class="arrow">&#8594;</span>
      <span class="node">Catalog token resolution</span><span class="arrow">&#8594;</span>
      <span class="node">Risk scoring (HNDL &times; exposure &times; sensitivity)</span><span class="arrow">&#8594;</span>
      <span class="node">Reports + optional zero-trust attestation</span>
    </div>
    <h2 style="margin-top:4px;">2&nbsp;&middot;&nbsp;Analysers &amp; what each one found</h2>
    <div class="stage-grid">{''.join(analyser_cards)}</div>
  </section>

  <section class="panel">
    <h2>3&nbsp;&middot;&nbsp;Findings by quantum-threat class</h2>
    {''.join(threat_rows) if threat_rows else '<p class="panel-desc">No findings.</p>'}
  </section>

  <section class="panel">
    <h2>4&nbsp;&middot;&nbsp;Crypto asset catalog coverage</h2>
    <p class="panel-desc">The full, fixed catalog this scanner can recognise (append-only &mdash; order is part of
      the zero-trust commitment format). <b style="color:#22C55E;">Lit</b> tiles were observed in this scan
      (occurrence count badge, top-right); dimmed tiles were not.</p>
    <div class="catalog-legend">
      <span><span class="sw" style="background:#16A34A"></span>found in this scan</span>
      <span><span class="sw" style="background:#374151"></span>in catalog, not observed</span>
    </div>
    {''.join(catalog_sections)}
  </section>

  {zt_html}

</main>
<footer>QBOM zero-trust framework &middot; dashboard is a static, offline snapshot of one scan run</footer>
</body>
</html>"""
