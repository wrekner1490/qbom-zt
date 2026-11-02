from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import catalog


@dataclass
class Finding:
    """One occurrence of a cryptographic asset at one location.

    `salt` starts as a random placeholder at construction time but is
    normally overwritten by QBOM.add_finding() with a value derived
    deterministically from the org's local secret key plus
    (catalog_id, location_id). That determinism matters: a remediation
    proof (see privacy.prove_remediated) claims "the finding I disclosed
    last quarter, at this exact salt, is gone from this new scan." If the
    salt were freshly randomised on every scan -- even for a finding that
    never changed -- that claim would trivially "verify" for findings that
    are still there, because the new scan's leaf would never match the old
    salt in the first place. A stable, org-secret-derived salt is what
    makes across-scan remediation claims mean anything.
    """
    catalog_id: str
    purpose: str            # KEY_EXCHANGE | SIGNATURE | SYMMETRIC | HASH | PROTOCOL | UNKNOWN_ASYM | ...
    file_path: str
    line: int
    snippet: str
    source: str              # scanner rule name, e.g. "python-cryptography-ast", "sshd_config", "x509-cert"
    component: Optional[str] = None   # owning service/component name, if known from a manifest
    confidence: str = "high"          # high | medium | low
    salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    @property
    def location_id(self) -> str:
        return f"{self.file_path}:{self.line}"

    def alg(self) -> catalog.Alg:
        return catalog.get(self.catalog_id)

    def to_public_dict(self) -> dict:
        """Everything except the salt (salt is local-only, used for ZK commitments)."""
        d = asdict(self)
        d.pop("salt", None)
        return d


def derive_salt(org_secret: bytes, catalog_id: str, location_id: str) -> bytes:
    """HMAC-SHA256(org_secret, catalog_id|location_id), truncated to 16
    bytes. Deterministic given the same secret and (catalog_id, location),
    so the same finding gets the same salt on every rescan -- but
    unguessable/unlinkable to anyone without org_secret, which never
    leaves the org (see privacy.py)."""
    return hmac.new(org_secret, f"{catalog_id}|{location_id}".encode(), hashlib.sha256).digest()[:16]


@dataclass
class Component:
    name: str
    exposure: str = "internal"      # internet_facing | internal | air_gapped
    data_sensitivity: str = "medium"  # critical | high | medium | low
    data_lifetime_years: float = 3.0  # how long data must stay confidential -> HNDL urgency
    owner: str = ""


@dataclass
class QBOM:
    org: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    catalog_version: str = catalog.CATALOG_VERSION
    catalog_hash: str = catalog.CATALOG_HASH
    components: dict = field(default_factory=dict)     # name -> Component
    findings: list = field(default_factory=list)        # list[Finding]
    org_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def add_component(self, c: Component):
        self.components[c.name] = c

    def add_finding(self, f: Finding):
        # overwrite the placeholder random salt with a deterministic one so
        # the same (catalog_id, location_id) gets the same salt on every
        # scan run with this org's secret -- see Finding's docstring and
        # model.derive_salt.
        f.salt = derive_salt(self.org_secret, f.catalog_id, f.location_id)
        self.findings.append(f)

    def by_catalog_id(self) -> dict:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.catalog_id, []).append(f)
        return out

    def counts(self) -> dict:
        return {cid: len(fs) for cid, fs in self.by_catalog_id().items()}

    def to_dict(self) -> dict:
        return {
            "org": self.org,
            "generated_at": self.generated_at,
            "catalog_version": self.catalog_version,
            "catalog_hash": self.catalog_hash,
            "components": {k: asdict(v) for k, v in self.components.items()},
            "findings": [f.to_public_dict() for f in self.findings],
        }

    def to_json(self, indent=2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
