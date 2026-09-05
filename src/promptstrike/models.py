"""Core domain models for promptstrike.

These are the data contracts shared across the scope registry, probe harness, finding pipeline, and
report generator. Everything is a pydantic model so it (de)serializes cleanly to/from YAML + SQLite
and validates at the boundary.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

from promptstrike.cvss import Severity, parse_v40_vector, score_v31
from promptstrike.taxonomy import OwaspLLM, default_cwes

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _slug(value: str, *, field: str) -> str:
    v = value.strip().lower()
    if not _SLUG_RE.match(v):
        raise ValueError(f"{field} must be a slug matching [a-z0-9-] (got {value!r})")
    return v


class Platform(str, Enum):
    """The bug-bounty platform a finding is destined for.

    This selects the report profile (:mod:`promptstrike.report.profiles`), which drives both the
    submission template and the readiness checklist — platforms disagree about what a report must
    contain, so the platform is a behavioural field, not a label.
    """

    google_ai_vrp = "google_ai_vrp"
    openai_h1 = "openai_h1"
    anthropic_h1 = "anthropic_h1"
    msrc = "msrc"
    bugcrowd = "bugcrowd"
    hackerone = "hackerone"
    other = "other"


class AssetType(str, Enum):
    """How a scope asset's value is matched against a candidate target.

    Security-relevant rather than descriptive: the type selects the matching rule in
    :func:`promptstrike.scope.asset_matches`. ``domain`` matches subdomains, ``endpoint`` matches a
    normalized host+path prefix on a "/" boundary, and ``host``/``model`` match exactly. Choosing a
    broader type than intended widens what may be tested.
    """

    endpoint = "endpoint"  # a URL / API endpoint
    model = "model"        # a named model id
    host = "host"          # hostname
    domain = "domain"      # domain (wildcard-capable)
    other = "other"


class FindingStatus(str, Enum):
    """Where a finding sits in the operator's manual submission workflow.

    ``submitted`` and everything after it are recorded by the operator *after* they submit by hand.
    promptstrike never advances a finding past ``ready`` on its own, because it never submits —
    see the no-auto-submission invariant in the division's CLAUDE.md.
    """

    draft = "draft"
    ready = "ready"
    submitted = "submitted"
    accepted = "accepted"
    rejected = "rejected"
    duplicate = "duplicate"


class ScopeAsset(BaseModel):
    """A single in-scope or out-of-scope asset within a program definition.

    ``value`` is validated non-empty on purpose: an empty asset matches nothing under
    :func:`promptstrike.scope.asset_matches`, but reads like a wildcard to a human editing the YAML
    by hand. Rejecting it at the boundary keeps that misreading from ever reaching a scope check.
    """

    value: str
    type: AssetType = AssetType.endpoint
    note: str = ""

    @field_validator("value")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("scope asset value must be non-empty")
        return v


class Program(BaseModel):
    """An authorized bug-bounty program and its scope. The safety spine reads from this."""

    name: str  # slug, unique key
    display_name: str = ""
    platform: Platform = Platform.other
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)
    allows_ai_testing: bool = False
    rate_limit_rps: float | None = None
    safe_harbor: bool = False
    contact: str = ""
    notes: str = ""

    @field_validator("name")
    @classmethod
    def _name_slug(cls, v: str) -> str:
        return _slug(v, field="program name")

    @model_validator(mode="after")
    def _defaults(self) -> Program:
        if not self.display_name:
            self.display_name = self.name
        return self


class Probe(BaseModel):
    """A declarative probe: attack prompt(s) + the detector that decides whether the model failed."""

    id: str  # slug
    name: str
    category: OwaspLLM
    description: str = ""
    prompts: list[str] = Field(default_factory=list)
    detector: str  # name registered in probes.detectors
    detector_args: dict = Field(default_factory=dict)
    severity_hint: Severity = Severity.medium
    cwe: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_slug(cls, v: str) -> str:
        return _slug(v, field="probe id")

    @model_validator(mode="after")
    def _fill_cwe(self) -> Probe:
        if not self.cwe:
            self.cwe = default_cwes(self.category)
        return self


class Evidence(BaseModel):
    """One request/response exchange captured during a probe run — the reproducibility artifact."""

    prompt: str
    response: str
    model: str = ""
    model_version: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)
    latency_ms: int | None = None
    metadata: dict = Field(default_factory=dict)


class ProbeResult(BaseModel):
    """The complete record of one probe run against one target — whether or not it triggered.

    Every run is persisted, not only the ones that fired: a probe that did not trigger is the
    evidence that the category was tested and held. ``dry_run`` defaults to ``True`` so a result
    that never went near the network can never be mistaken for a live one.
    """

    run_id: str
    probe_id: str
    program: str
    target: str
    category: OwaspLLM
    triggered: bool
    detector: str
    dry_run: bool = True
    evidence: list[Evidence] = Field(default_factory=list)
    detail: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    """A confirmed, reportable finding. Setting a CVSS v3.1 vector recomputes score + severity."""

    id: int | None = None
    run_id: str | None = None
    program: str
    platform: Platform = Platform.other
    title: str
    category: OwaspLLM
    severity: Severity = Severity.medium
    cwe: list[str] = Field(default_factory=list)
    target: str = ""
    model: str = ""
    model_version: str = ""
    summary: str = ""
    description: str = ""
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cvss_v31_vector: str = ""
    cvss_v31_score: float | None = None
    cvss_v40_vector: str = ""  # validated + recorded; scored via FIRST calculator (see cvss.py)
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    #: Related framework entry ids, keyed by knowledge-pack framework ("atlas", "llmsvs", ...).
    #: Derived from the category when empty. A dict rather than one field per framework so adding a
    #: framework to the pack stays a data change.
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.draft
    created_at: datetime = Field(default_factory=_utcnow)

    def refs(self, framework: str) -> list[str]:
        """Related entry ids in one knowledge-pack framework; empty if none apply."""
        return list(self.framework_refs.get(framework, []))

    @model_validator(mode="after")
    def _derive(self) -> Finding:
        if self.cvss_v31_vector:
            score, sev = score_v31(self.cvss_v31_vector)
            self.cvss_v31_score = score
            self.severity = sev
        if self.cvss_v40_vector:
            parse_v40_vector(self.cvss_v40_vector)  # validate; raises on malformed
        if not self.cwe:
            self.cwe = default_cwes(self.category)
        if not self.framework_refs:
            # Deferred so that importing promptstrike.models does not load the pack; the pack loads
            # (once, cached) on first Finding construction. There is no import cycle to avoid here —
            # promptstrike.knowledge imports taxonomy only, never models.
            from promptstrike import knowledge

            self.framework_refs = knowledge.refs_for(self.category)
        # NOTE: `remediation` is deliberately NOT auto-filled from the pack. It feeds the
        # submission-readiness checklist (report.profiles._has_remediation); filling it here would
        # make that check pass for every finding. See knowledge.suggest_remediation.
        return self
