"""
report.py: CycloneDX CBOM export, and reports in three shapes:

  * to_markdown_report / to_pdf_report        -- one scan's readiness summary
                                                  + migration plan (existing,
                                                  unchanged behaviour).
  * to_qbom_minimum_elements                   -- this scan's findings,
                                                  reshaped into the *exact*
                                                  table structure CERT-In's
                                                  "Technical Guidelines on
                                                  SBOM | QBOM & CBOM | AIBOM |
                                                  HBOM" (v2.0, 09.07.2025)
                                                  Table 8 (Minimum Elements
                                                  of QBOM & CBOM) and Table 9
                                                  (Minimum Elements pertaining
                                                  to Cryptographic Asset)
                                                  specify.
  * to_engagement_pdf_report                   -- the multi-iteration report
                                                  for a whole qbom.workflow
                                                  Engagement: consent, a
                                                  readiness trend across
                                                  iterations, a VEX document
                                                  per CERT-In section 6/8.4.1.6,
                                                  the CERT-In minimum-elements
                                                  table for the final scan,
                                                  and the full remediation log.
"""
from __future__ import annotations

import uuid

from . import risk
from .model import QBOM


def to_cyclonedx_cbom(qbom: QBOM) -> dict:
    """CycloneDX 1.6 with the cryptographic-asset extension (the closest
    current open standard to CERT-In's QBOM concept for classical+PQ crypto
    inventory; CycloneDX added quantum fields -- nistQuantumSecurityLevel,
    quantumSecurityRelated primitives -- specifically for this purpose)."""
    components = []
    seen = set()
    for f in qbom.findings:
        alg = f.alg()
        key = (f.catalog_id,)
        bom_ref = f"crypto/{f.catalog_id.lower()}"
        if key not in seen:
            seen.add(key)
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": bom_ref,
                "name": alg.label,
                "cryptoProperties": {
                    "assetType": "protocol" if alg.kind == "protocol" else "algorithm",
                    "algorithmProperties": {
                        "primitive": alg.primitive,
                        "nistQuantumSecurityLevel": alg.nist_q_level,
                    } if alg.kind == "algorithm" else None,
                    "oid": None,
                },
                "properties": [
                    {"name": "qbom:threatClass", "value": alg.threat},
                    {"name": "qbom:classicalSecurityBits", "value": str(alg.classical_bits)},
                    {"name": "qbom:recommendedReplacement", "value": alg.replacement},
                    {"name": "qbom:occurrenceCount", "value": str(len(qbom.by_catalog_id().get(f.catalog_id, [])))},
                ],
            })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": qbom.generated_at,
            "component": {"type": "application", "name": qbom.org},
            "properties": [{"name": "qbom:catalogHash", "value": qbom.catalog_hash}],
        },
        "components": components,
    }


def to_qbom_minimum_elements(qbom: QBOM, engagement_meta: dict | None = None) -> dict:
    """Reshape this scan into CERT-In's Table 8 / Table 9 field structure
    verbatim. Where the guideline asks for something this tool genuinely
    tracks (Name, Version, Threat/Primitive classification, occurrence
    count...) the real value is used; where it asks for something this
    static scanner cannot determine (an OID, a certificate's Subject DN, a
    key's activation date...) the field is present but says so explicitly
    -- "not captured by static analysis" -- rather than being invented or
    silently omitted. `engagement_meta`, if given, fills the Table 8
    Vendor/License/Model fields from the engagement (org, consent,
    manifest) instead of generic defaults.
    """
    meta = engagement_meta or {}
    algorithms, keys, protocols, certificates = [], [], [], []
    seen_algs = set()
    for f in qbom.findings:
        alg = f.alg()
        if alg.kind == "protocol":
            protocols.append({
                "Name": alg.label, "Asset Type": "protocol", "Version": alg.id,
                "Cipher Suites": "not captured by static analysis (see per-finding snippet in the QBOM)",
                "OID": "n/a", "Location": f.location_id,
            })
            continue
        if f.source.startswith("x509-cert:"):
            certificates.append({
                "Name": f.file_path, "Asset Type": "certificate",
                "Subject Name": "not parsed by this scanner beyond the public-key/signature algorithm",
                "Issuer Name": "not parsed by this scanner beyond the public-key/signature algorithm",
                "Not Valid Before": "not captured", "Not Valid After": "not captured",
                "Signature Algorithm Reference": alg.label if f.purpose == "SIGNATURE" else "see paired finding",
                "Subject Public Key Reference": alg.label,
                "Certificate Format": "X.509", "Certificate Extension": f.file_path.rsplit(".", 1)[-1],
            })
            continue
        if f.source.startswith("pem:"):
            keys.append({
                "Name": f.file_path, "Asset Type": "key", "id": f.location_id,
                "state": "active (as scanned; not independently verified)",
                "size": f"{alg.classical_bits} bits (classical security strength)" if alg.classical_bits else "n/a",
                "Creation Date": "not captured (not embedded in a PEM private key)",
                "Activation Date": "not captured",
            })
            continue
        if alg.id not in seen_algs:
            seen_algs.add(alg.id)
            algorithms.append({
                "Name": alg.label, "Asset Type": "algorithm", "Primitive": alg.primitive,
                "Mode": "not separately tracked (see individual finding snippets for e.g. GCM/ECB)",
                "Crypto Functions": {"KEY_EXCHANGE": "key generation, key agreement",
                                      "SIGNATURE": "key generation, sign, verify",
                                      "SYMMETRIC": "encryption, decryption",
                                      "HASH": "digest"}.get(f.purpose, "n/a"),
                "Classical security level": f"{alg.classical_bits} bits" if alg.classical_bits else "n/a (broken)",
                "OID": "not tracked by this scanner", "List": alg.id,
                "Occurrence count": len(qbom.by_catalog_id().get(alg.id, [])),
                "Quantum threat class": alg.threat,
                "NIST quantum security level": alg.nist_q_level,
                "Recommended replacement": alg.replacement,
            })

    return {
        "Model Name": meta.get("model_name", f"{qbom.org} -- software & configuration estate"),
        "Version": meta.get("version", f"catalog v{qbom.catalog_version} ({qbom.catalog_hash[:12]}...)"),
        "Vendor & Origin Information": meta.get(
            "vendor", "Internal assessment; component ownership from the org's own manifest, where supplied."),
        "License Information": meta.get("license", "N/A -- this is an internal cryptographic-asset inventory, "
                                                     "not a licensed software component."),
        "Communication Protocol": "see Protocols below",
        "Hardware": "N/A -- this QBOM/CBOM covers software and configuration cryptographic usage. "
                    "A companion HBOM would cover physical/hardware cryptographic modules per CERT-In "
                    "Table 11, which this tool does not scan for.",
        "Software Dependencies": "see the scanned component list in the accompanying CycloneDX CBOM export",
        "Environmental Impact": "not tracked by this scanner",
        "Vulnerabilities": "see the accompanying VEX document (vex.json) for per-algorithm status",
        "Attestations": "see attestation.public.json if this scan was run with zero-trust attestation enabled",
        "Cryptographic Asset": {
            "Algorithms": algorithms, "Keys": keys, "Protocols": protocols, "Certificates": certificates,
        },
        "_generated_at": qbom.generated_at,
    }


def to_markdown_report(qbom: QBOM) -> str:
    summary = risk.readiness_summary(qbom)
    plan = risk.build_migration_plan(qbom)
    lines = []
    lines.append(f"# Quantum Bill of Materials -- {qbom.org}")
    lines.append(f"_Generated {qbom.generated_at} | catalog v{qbom.catalog_version} ({qbom.catalog_hash[:12]}...)_\n")

    lines.append("## Readiness summary")
    lines.append(f"- **Total crypto findings:** {summary['total_findings']} across "
                 f"{summary['distinct_algorithms']} distinct algorithms/protocols")
    lines.append(f"- **Quantum-safe today (PQ_SAFE + HYBRID):** {summary['pq_ready_pct']}%")
    lines.append(f"- **Shor-vulnerable (existential break under a CRQC):** {summary['shor_vulnerable_pct']}%")
    lines.append(f"- **Grover-weakened (margin reduction only):** {summary['grover_weakened_pct']}%")
    lines.append(f"- **Already classically broken/deprecated:** {summary['classically_broken_pct']}%")
    if summary["legacy_pq_pct"]:
        lines.append(f"- **Pre-standard PQ (needs a swap to final FIPS algorithms):** {summary['legacy_pq_pct']}%")
    lines.append("")

    lines.append("## Prioritised migration plan")
    lines.append("| Priority | Algorithm | Threat class | Count | Max exposure | Data lifetime | Score | Replacement |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, item in enumerate(plan, 1):
        lines.append(f"| {i} | {item.label} (`{item.catalog_id}`) | {item.threat} | {item.count} | "
                      f"{item.max_exposure} | {item.max_data_lifetime:.0f}y | {item.score} | {item.replacement} |")
    lines.append("")

    lines.append("## Detail per item")
    for i, item in enumerate(plan, 1):
        lines.append(f"### {i}. {item.label} (`{item.catalog_id}`) -- score {item.score}")
        lines.append(f"{item.rationale}")
        lines.append(f"- Occurrences: {item.count}")
        if item.components:
            lines.append(f"- Affected components: {', '.join(item.components)}")
        lines.append(f"- Recommended replacement: {item.replacement}")
        shown = item.locations[:8]
        lines.append(f"- Locations{' (first 8)' if len(item.locations) > 8 else ''}: " + ", ".join(shown))
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PDF report (same content as the Markdown report, laid out for printing/
# sharing with people who won't open qbom-report.md).
# ---------------------------------------------------------------------------
_THREAT_COLORS = {
    "SHOR": "#DC2626", "GROVER": "#D97706", "CLASSICAL_BROKEN": "#991B1B",
    "PQ_SAFE": "#16A34A", "HYBRID": "#0D9488", "LEGACY_PQ": "#7C3AED", "UNKNOWN": "#6B7280",
}


def to_pdf_report(qbom: QBOM, out_path: str) -> None:
    """Render the same readiness summary / migration plan / detail sections
    as to_markdown_report(), but as a paginated PDF via reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    summary = risk.readiness_summary(qbom)
    plan = risk.build_migration_plan(qbom)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("QTitle", parent=styles["Title"], fontSize=20, spaceAfter=4))
    styles.add(ParagraphStyle("QMeta", parent=styles["Normal"], textColor=colors.grey, fontSize=9))
    styles.add(ParagraphStyle("QH2", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8,
                               textColor=colors.HexColor("#1E3A8A")))
    styles.add(ParagraphStyle("QH3", parent=styles["Heading3"], spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle("QBody", parent=styles["BodyText"], fontSize=9, leading=12))
    styles.add(ParagraphStyle("QCell", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle("QMono", parent=styles["BodyText"], fontSize=7.5, leading=9,
                               fontName="Courier", textColor=colors.HexColor("#374151")))

    story = []
    story.append(Paragraph("Quantum Bill of Materials", styles["QTitle"]))
    story.append(Paragraph(qbom.org, styles["Heading3"]))
    story.append(Paragraph(
        f"Generated {qbom.generated_at} &middot; catalog v{qbom.catalog_version} "
        f"({qbom.catalog_hash[:12]}...)", styles["QMeta"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB"), spaceBefore=8, spaceAfter=12))

    # --- Readiness summary -------------------------------------------------
    story.append(Paragraph("Readiness summary", styles["QH2"]))
    metrics = [
        ("Total crypto findings", f"{summary['total_findings']} across "
                                   f"{summary['distinct_algorithms']} distinct algorithms/protocols"),
        ("Quantum-safe today (PQ_SAFE + HYBRID)", f"{summary['pq_ready_pct']}%"),
        ("Shor-vulnerable (existential break under a CRQC)", f"{summary['shor_vulnerable_pct']}%"),
        ("Grover-weakened (margin reduction only)", f"{summary['grover_weakened_pct']}%"),
        ("Already classically broken/deprecated", f"{summary['classically_broken_pct']}%"),
    ]
    if summary["legacy_pq_pct"]:
        metrics.append(("Pre-standard PQ (needs swap to final FIPS algorithms)", f"{summary['legacy_pq_pct']}%"))
    mt = Table([[Paragraph(f"<b>{k}</b>", styles["QBody"]), Paragraph(v, styles["QBody"])] for k, v in metrics],
               colWidths=[3.6 * inch, 2.9 * inch])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(mt)

    # --- Migration plan table -----------------------------------------------
    story.append(Paragraph("Prioritised migration plan", styles["QH2"]))
    header = ["#", "Algorithm", "Threat", "Count", "Exposure", "Lifetime", "Score", "Replacement"]
    rows = [[Paragraph(f"<b>{h}</b>", styles["QCell"]) for h in header]]
    for i, item in enumerate(plan, 1):
        rows.append([
            Paragraph(str(i), styles["QCell"]),
            Paragraph(f"{item.label}<br/><font face='Courier' size=6.5>{item.catalog_id}</font>", styles["QCell"]),
            Paragraph(item.threat, styles["QCell"]),
            Paragraph(str(item.count), styles["QCell"]),
            Paragraph(item.max_exposure, styles["QCell"]),
            Paragraph(f"{item.max_data_lifetime:.0f}y", styles["QCell"]),
            Paragraph(str(item.score), styles["QCell"]),
            Paragraph(item.replacement, styles["QCell"]),
        ])
    col_widths = [0.25 * inch, 1.25 * inch, 0.75 * inch, 0.45 * inch, 0.65 * inch, 0.55 * inch, 0.5 * inch, 2.1 * inch]
    pt = Table(rows, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, item in enumerate(plan, 1):
        c = colors.HexColor(_THREAT_COLORS.get(item.threat, "#6B7280"))
        style_cmds.append(("TEXTCOLOR", (2, i), (2, i), c))
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F9FAFB")))
    pt.setStyle(TableStyle(style_cmds))
    story.append(pt)

    # --- Detail per item ------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Detail per item", styles["QH2"]))
    for i, item in enumerate(plan, 1):
        c = _THREAT_COLORS.get(item.threat, "#6B7280")
        story.append(Paragraph(
            f"{i}. {item.label} <font face='Courier' size=8>({item.catalog_id})</font> "
            f"&mdash; <font color='{c}'><b>score {item.score}</b></font>", styles["QH3"]))
        story.append(Paragraph(item.rationale, styles["QBody"]))
        story.append(Paragraph(f"<b>Occurrences:</b> {item.count}", styles["QBody"]))
        if item.components:
            story.append(Paragraph(f"<b>Affected components:</b> {', '.join(item.components)}", styles["QBody"]))
        story.append(Paragraph(f"<b>Recommended replacement:</b> {item.replacement}", styles["QBody"]))
        shown = item.locations[:8]
        label = "Locations (first 8)" if len(item.locations) > 8 else "Locations"
        story.append(Paragraph(f"<b>{label}:</b> " + ", ".join(shown), styles["QMono"]))
        story.append(Spacer(1, 8))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(0.75 * inch, 0.5 * inch, f"QBOM \u2013 {qbom.org}")
        canvas.drawRightString(LETTER[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(out_path, pagesize=LETTER,
                             leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                             topMargin=0.75 * inch, bottomMargin=0.75 * inch,
                             title=f"QBOM - {qbom.org}")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


# ---------------------------------------------------------------------------
# Multi-iteration engagement report (qbom.workflow.Engagement), in the
# CERT-In minimum-elements table structure (Table 8 / Table 9) plus a VEX
# document and a full remediation log across every iteration of the loop.
# ---------------------------------------------------------------------------
_VEX_COLORS = {"affected": "#DC2626", "fixed": "#16A34A", "under_investigation": "#D97706",
               "not_affected": "#6B7280"}
_VEX_LABELS = {"affected": "Affected", "fixed": "Fixed", "under_investigation": "Under Investigation",
               "not_affected": "Not Affected"}


def to_engagement_pdf_report(engagement, out_path: str, final_qbom: QBOM | None = None) -> None:
    """The document you hand to a CISO/regulator at the end of an
    engagement: consent, the readiness trend across every iteration of the
    commit -> scan -> recommend -> remediate -> rescan loop, a VEX document
    (CERT-In section 6 / 8.4.1.6, applied here to post-quantum migration
    status rather than a single CVE), the full remediation log, and --
    if `final_qbom` is supplied -- the CERT-In Table 8/9 minimum-elements
    breakdown of the final scan."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        ListFlowable,
        ListItem,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("QTitle", parent=styles["Title"], fontSize=20, spaceAfter=4))
    styles.add(ParagraphStyle("QMeta", parent=styles["Normal"], textColor=colors.grey, fontSize=9))
    styles.add(ParagraphStyle("QH2", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8,
                               textColor=colors.HexColor("#1E3A8A")))
    styles.add(ParagraphStyle("QH3", parent=styles["Heading3"], spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle("QBody", parent=styles["BodyText"], fontSize=9, leading=12))
    styles.add(ParagraphStyle("QCell", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle("QMono", parent=styles["BodyText"], fontSize=7.5, leading=9,
                               fontName="Courier", textColor=colors.HexColor("#374151")))

    iterations = engagement.iterations
    latest = iterations[-1] if iterations else None
    first_pct = iterations[0].readiness["pq_ready_pct"] if iterations else 0.0
    final_pct = latest.readiness["pq_ready_pct"] if latest else 0.0

    story = []
    story.append(Paragraph("Quantum Bill of Materials \u2014 Engagement Report", styles["QTitle"]))
    story.append(Paragraph(engagement.org, styles["Heading3"]))
    story.append(Paragraph(
        f"Engagement {engagement.engagement_id} &middot; created {engagement.created_at} &middot; "
        f"status {engagement.status}", styles["QMeta"]))
    story.append(Paragraph(
        "Prepared in the format recommended by CERT-In's Technical Guidelines on SBOM | QBOM &amp; CBOM | "
        "AIBOM | HBOM, Version 2.0 (09.07.2025), Section 8 (Quantum BOM &amp; Cryptographic BOM) and "
        "Section 6 (Vulnerability Tracking and Analysis / VEX).", styles["QMeta"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB"), spaceBefore=8, spaceAfter=12))

    # --- Consent / commitment ------------------------------------------------
    story.append(Paragraph("1 &middot; Engagement commitment", styles["QH2"]))
    if engagement.consent:
        c = engagement.consent
        story.append(Paragraph(f"<b>Accepted by:</b> {c.accepted_by}, on behalf of {c.org}", styles["QBody"]))
        story.append(Paragraph(f"<b>Accepted at:</b> {c.accepted_at}", styles["QBody"]))
        story.append(Paragraph(f"<b>Statement:</b> {c.statement}", styles["QBody"]))
    else:
        story.append(Paragraph("No consent on record.", styles["QBody"]))
    story.append(Paragraph(
        f"<b>Target post-quantum readiness:</b> {engagement.target_pct}% &nbsp;&nbsp; "
        f"<b>Max iterations:</b> {engagement.max_iterations}", styles["QBody"]))

    # --- Executive summary -----------------------------------------------------
    story.append(Paragraph("2 &middot; Executive summary", styles["QH2"]))
    outcome = {
        "TARGET_MET": "Target reached and engagement completed successfully.",
        "ENDED_BY_ORG": "Ended at the organisation's request before the target was reached.",
        "MAX_ITERATIONS": "Reached the configured iteration limit before the target was met.",
        "IN_PROGRESS": "Still in progress as of this report.",
    }.get(engagement.status, engagement.status)
    summary_rows = [
        ("Iterations run", str(len(iterations))),
        ("Starting PQ-readiness", f"{first_pct}%"),
        ("Final PQ-readiness", f"{final_pct}%"),
        ("Target", f"{engagement.target_pct}%"),
        ("Outcome", outcome),
    ]
    st = Table([[Paragraph(f"<b>{k}</b>", styles["QBody"]), Paragraph(v, styles["QBody"])] for k, v in summary_rows],
               colWidths=[2.3 * inch, 4.2 * inch])
    st.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(st)

    # --- Readiness trend across iterations -------------------------------------
    story.append(Paragraph("3 &middot; Readiness trend across iterations", styles["QH2"]))
    story.append(Paragraph(
        "Each iteration: (1) scan, (2) threat analysis &amp; recommendations, (3) the organisation "
        "reviews the readiness % and either accepts and continues or stops, (4) if continuing, the "
        "recommended fixes are applied, and the estate is rescanned.", styles["QBody"]))
    header = ["#", "Scanned", "Findings", "PQ-ready", "Shor-vuln.", "Grover-weak.", "Broken", "Decision"]
    rows = [[Paragraph(f"<b>{h}</b>", styles["QCell"]) for h in header]]
    for it in iterations:
        r = it.readiness
        rows.append([
            Paragraph(str(it.index), styles["QCell"]),
            Paragraph(it.scanned_root, styles["QCell"]),
            Paragraph(str(it.findings_total), styles["QCell"]),
            Paragraph(f"{r['pq_ready_pct']}%", styles["QCell"]),
            Paragraph(f"{r['shor_vulnerable_pct']}%", styles["QCell"]),
            Paragraph(f"{r['grover_weakened_pct']}%", styles["QCell"]),
            Paragraph(f"{r['classically_broken_pct']}%", styles["QCell"]),
            Paragraph(it.decision or "\u2014", styles["QCell"]),
        ])
    tt = Table(rows, colWidths=[0.3*inch, 0.85*inch, 0.7*inch, 0.8*inch, 0.85*inch, 0.95*inch, 0.7*inch, 0.85*inch],
               repeatRows=1)
    tt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tt)

    # --- VEX document (latest iteration) ---------------------------------------
    if latest and latest.vex:
        story.append(Paragraph("4 &middot; Vulnerability Exploitability eXchange (VEX)", styles["QH2"]))
        story.append(Paragraph(
            "Per CERT-In Section 6 / 8.4.1.6, applied here to post-quantum migration status: each "
            "at-risk algorithm is Not Affected, Affected, Fixed, or Under Investigation, as of the "
            "latest iteration.", styles["QBody"]))
        vheader = ["Algorithm", "Status", "Threat class", "Count", "Was", "Recommended replacement"]
        vrows = [[Paragraph(f"<b>{h}</b>", styles["QCell"]) for h in vheader]]
        for cid, entry in sorted(latest.vex.items(), key=lambda kv: (kv[1]["status"] != "affected", kv[0])):
            color = _VEX_COLORS.get(entry["status"], "#6B7280")
            vrows.append([
                Paragraph(f"{entry['label']}<br/><font face='Courier' size=6.5>{cid}</font>", styles["QCell"]),
                Paragraph(f"<font color='{color}'><b>{_VEX_LABELS.get(entry['status'], entry['status'])}</b></font>",
                          styles["QCell"]),
                Paragraph(entry["threat_class"], styles["QCell"]),
                Paragraph(str(entry["count"]), styles["QCell"]),
                Paragraph(str(entry["previous_count"]), styles["QCell"]),
                Paragraph(entry["replacement"], styles["QCell"]),
            ])
        vt = Table(vrows, colWidths=[1.5*inch, 1.0*inch, 0.9*inch, 0.5*inch, 0.5*inch, 2.35*inch], repeatRows=1)
        vt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(vt)

    # --- Remediation log across all iterations ----------------------------------
    story.append(PageBreak())
    story.append(Paragraph("5 &middot; Remediation log", styles["QH2"]))
    any_changes = False
    for it in iterations:
        if not it.remediation_applied:
            continue
        any_changes = True
        story.append(Paragraph(f"Applied before iteration {it.index + 1}:", styles["QH3"]))
        items = []
        for c in it.remediation_applied:
            items.append(ListItem(Paragraph(
                f"<b>{c['title']}</b> \u2014 {c['summary']}<br/>"
                f"<font face='Courier' size=7>{', '.join(c['files_changed'])}</font>", styles["QBody"])))
        story.append(ListFlowable(items, bulletType="bullet"))
    if not any_changes:
        story.append(Paragraph("No remediation was applied during this engagement.", styles["QBody"]))

    # --- Residual / known-limitation items --------------------------------------
    from . import remediate as _remediate
    if latest and any(cid in _remediate.RESIDUAL_NOTES for cid in latest.vex):
        story.append(Paragraph("6 &middot; Residual items and known limitations", styles["QH2"]))
        story.append(Paragraph(
            "Findings still open at the end of this engagement that are not simply unaddressed -- "
            "each has a specific, documented reason automated remediation did not apply:", styles["QBody"]))
        items = []
        for cid, note in _remediate.RESIDUAL_NOTES.items():
            if cid in latest.vex and latest.vex[cid]["status"] == "affected":
                items.append(ListItem(Paragraph(f"<b>{latest.vex[cid]['label']}</b> ({cid}): {note}",
                                                 styles["QBody"])))
        if items:
            story.append(ListFlowable(items, bulletType="bullet"))

    # --- CERT-In Table 8 / Table 9 minimum elements -----------------------------
    if final_qbom is not None:
        story.append(PageBreak())
        story.append(Paragraph("7 &middot; CERT-In minimum elements (Table 8 &amp; Table 9)", styles["QH2"]))
        elements = to_qbom_minimum_elements(
            final_qbom, engagement_meta={
                "model_name": f"{engagement.org} \u2014 {engagement.source_path}",
                "version": f"engagement {engagement.engagement_id}, iteration {len(iterations)}",
            })
        top_fields = [(k, v) for k, v in elements.items()
                      if k not in ("Cryptographic Asset", "_generated_at")]
        et = Table([[Paragraph(f"<b>{k}</b>", styles["QBody"]), Paragraph(str(v), styles["QBody"])]
                    for k, v in top_fields], colWidths=[2.0 * inch, 4.5 * inch])
        et.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(et)

        asset = elements["Cryptographic Asset"]
        for section, rows_data, cols in (
            ("Algorithms", asset["Algorithms"],
             ["Name", "Primitive", "Classical security level", "Quantum threat class", "Occurrence count",
              "Recommended replacement"]),
            ("Keys", asset["Keys"], ["Name", "id", "state", "size"]),
            ("Protocols", asset["Protocols"], ["Name", "Version", "Location"]),
            ("Certificates", asset["Certificates"],
             ["Name", "Signature Algorithm Reference", "Subject Public Key Reference", "Certificate Format"]),
        ):
            if not rows_data:
                continue
            story.append(Paragraph(f"7.{['Algorithms','Keys','Protocols','Certificates'].index(section)+1} "
                                    f"&middot; {section}", styles["QH3"]))
            hdr = [Paragraph(f"<b>{c}</b>", styles["QCell"]) for c in cols]
            trows = [hdr]
            for row in rows_data:
                trows.append([Paragraph(str(row.get(c, "")), styles["QCell"]) for c in cols])
            width = 6.5 / len(cols)
            ct = Table(trows, colWidths=[width * inch] * len(cols), repeatRows=1)
            ct.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(ct)
            story.append(Spacer(1, 6))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(0.75 * inch, 0.5 * inch, f"QBOM Engagement Report \u2013 {engagement.org}")
        canvas.drawRightString(LETTER[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(out_path, pagesize=LETTER,
                             leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                             topMargin=0.75 * inch, bottomMargin=0.75 * inch,
                             title=f"QBOM Engagement Report - {engagement.org}")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
