"""
Prioritisation engine.

The scoring is deliberately built from a small number of *quantum
principles* rather than a big opaque weighted checklist, because those
principles are what actually determine urgency:

1. Harvest-Now-Decrypt-Later (HNDL): traffic or data encrypted today with a
   Shor-breakable scheme can be recorded now and decrypted the moment a
   sufficiently large quantum computer exists. Urgency scales with how long
   the data must stay confidential (`data_lifetime_years`) -- a scheme
   protecting data that must stay secret for 15 years is far more urgent
   than one protecting a 6-month session token, even if both use RSA-2048
   today.
2. Break class: SHOR (public-key) is an existential break -- the *entire*
   scheme falls, including anything already recorded. GROVER (symmetric/hash)
   only *weakens* margins and is fixed by using bigger keys, not a protocol
   redesign, so it is real but far less urgent per-instance.
3. Exposure: an internet-facing endpoint is attackable by anyone recording
   traffic today; an air-gapped internal batch job is not exposed to HNDL
   in the same way (still worth fixing, just not to the front of the queue).
4. Blast radius: how many distinct locations use this catalog entry --
   a widely-used broken primitive (e.g. MD5 in twelve places) is a bigger
   remediation project and a bigger risk surface than a one-off.

Score = HNDL urgency x exposure multiplier x sensitivity multiplier,
folded per catalog_id (not per finding) because migration is planned and
executed per algorithm, not per line of code.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import catalog
from .model import QBOM

# Years until a "cryptographically relevant quantum computer" (CRQC) capable
# of running Shor's algorithm against today's key sizes is a *conservative
# planning* assumption -- deliberately not a prediction, just a planning
# horizon consistent with NIST/NSA CNSA 2.0 and BSI guidance to migrate
# well before any such date, given HNDL risk starts today, not on that date.
CRQC_PLANNING_HORIZON_YEARS = 10

EXPOSURE_MULTIPLIER = {"internet_facing": 3.0, "internal": 1.5, "air_gapped": 1.0}
SENSITIVITY_MULTIPLIER = {"critical": 3.0, "high": 2.0, "medium": 1.2, "low": 1.0}


@dataclass
class MigrationItem:
    catalog_id: str
    label: str
    threat: str
    count: int
    components: list
    max_data_lifetime: float
    max_exposure: str
    hndl_years_exposed: float   # how far past "safe" the data lifetime already reaches
    score: float
    replacement: str
    rationale: str
    locations: list = field(default_factory=list)


def _score_one(alg: catalog.Alg, count: int, exposures: list, sensitivities: list,
               lifetimes: list) -> tuple[float, str]:
    max_exposure = max(exposures, key=lambda e: EXPOSURE_MULTIPLIER.get(e, 1.0)) if exposures else "internal"
    max_sensitivity = max(sensitivities, key=lambda s: SENSITIVITY_MULTIPLIER.get(s, 1.0)) if sensitivities else "medium"
    max_lifetime = max(lifetimes) if lifetimes else 1.0
    exp_mult = EXPOSURE_MULTIPLIER.get(max_exposure, 1.0)
    sens_mult = SENSITIVITY_MULTIPLIER.get(max_sensitivity, 1.0)

    if alg.threat == "SHOR":
        hndl_overhang = max(0.0, max_lifetime - 0.0)  # any positive lifetime is at risk under HNDL
        # urgency rises sharply as data lifetime approaches/exceeds the CRQC horizon
        base = 40 + 60 * min(1.5, max_lifetime / CRQC_PLANNING_HORIZON_YEARS)
        rationale = (f"Shor-breakable: an attacker recording traffic/data today can decrypt it once a "
                     f"CRQC exists. Data here must stay confidential {max_lifetime:.0f}y, against a "
                     f"~{CRQC_PLANNING_HORIZON_YEARS}y conservative planning horizon.")
    elif alg.threat == "GROVER":
        base = 15
        hndl_overhang = 0.0
        rationale = "Grover-weakened: effective security roughly halves under a large quantum computer; raise key/output size, no protocol redesign needed."
    elif alg.threat == "CLASSICAL_BROKEN":
        base = 35  # already exploitable today, independent of quantum timeline
        hndl_overhang = 0.0
        rationale = "Already broken or deprecated against classical attackers today -- fix regardless of quantum timeline."
    elif alg.threat == "LEGACY_PQ":
        base = 20
        hndl_overhang = 0.0
        rationale = "Pre-standardisation PQ algorithm; not wire-compatible with the final FIPS standard -- plan a swap, not an emergency."
    elif alg.threat == "HYBRID":
        base = 5
        hndl_overhang = 0.0
        rationale = "Already hybrid classical+PQ; low urgency, monitor for pure-PQ migration once policy allows."
    else:
        base = 2
        hndl_overhang = 0.0
        rationale = "Already quantum-safe with adequate margin."

    score = base * exp_mult * sens_mult * (1 + min(count, 50) / 100)
    return score, rationale, hndl_overhang, max_exposure


def build_migration_plan(qbom: QBOM) -> list[MigrationItem]:
    by_id = qbom.by_catalog_id()
    items: list[MigrationItem] = []
    for cid, findings in by_id.items():
        alg = catalog.get(cid)
        exposures, sensitivities, lifetimes, comp_names = [], [], [], set()
        for f in findings:
            comp = qbom.components.get(f.component) if f.component else None
            exposures.append(comp.exposure if comp else "internal")
            sensitivities.append(comp.data_sensitivity if comp else "medium")
            lifetimes.append(comp.data_lifetime_years if comp else 1.0)
            if f.component:
                comp_names.add(f.component)
        score, rationale, hndl_overhang, max_exposure = _score_one(alg, len(findings), exposures, sensitivities, lifetimes)
        items.append(MigrationItem(
            catalog_id=cid, label=alg.label, threat=alg.threat, count=len(findings),
            components=sorted(comp_names), max_data_lifetime=max(lifetimes) if lifetimes else 0.0,
            max_exposure=max_exposure, hndl_years_exposed=hndl_overhang, score=round(score, 1),
            replacement=alg.replacement, rationale=rationale,
            locations=[f.location_id for f in findings],
        ))
    items.sort(key=lambda i: (-i.score, i.catalog_id))
    return items


def readiness_summary(qbom: QBOM) -> dict:
    counts = qbom.counts()
    total = sum(counts.values()) or 1
    by_threat = {}
    for cid, n in counts.items():
        t = catalog.get(cid).threat
        by_threat[t] = by_threat.get(t, 0) + n
    pq_safe = by_threat.get("PQ_SAFE", 0) + by_threat.get("HYBRID", 0)
    at_risk_shor = by_threat.get("SHOR", 0)
    weakened_grover = by_threat.get("GROVER", 0)
    broken = by_threat.get("CLASSICAL_BROKEN", 0)
    legacy_pq = by_threat.get("LEGACY_PQ", 0)
    return {
        "total_findings": total,
        "by_threat_class": by_threat,
        "pq_ready_pct": round(100 * pq_safe / total, 1),
        "shor_vulnerable_pct": round(100 * at_risk_shor / total, 1),
        "grover_weakened_pct": round(100 * weakened_grover / total, 1),
        "classically_broken_pct": round(100 * broken / total, 1),
        "legacy_pq_pct": round(100 * legacy_pq / total, 1),
        "distinct_algorithms": len(counts),
    }
