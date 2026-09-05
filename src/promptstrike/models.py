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

# Slug grammar for program names and probe ids: lower-case alphanumerics and hyphens, and it must
# START with an alphanumeric. Program names become filenames in the scope registry, so keeping
# dots, slashes and whitespace out of a REGISTERED name is what makes those filenames well-formed.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _utcnow() -> datetime:
    # Timezone-aware UTC for every default timestamp, so records from different machines are
    # directly comparable and serialize with an explicit offset.
    return datetime.now(UTC)


def _slug(value: str, *, field: str) -> str:
    # Normalize before validating so "  Example " and "example" are the same program, and the
    # stored form is the one used as the registry filename.
    normalized = value.strip().lower()
    # Reject anything outside the grammar at the model boundary, not at lookup time.
    if not _SLUG_RE.match(normalized):
        # Quote the ORIGINAL value in the error so the operator sees what they actually typed.
        raise ValueError(f"{field} must be a slug matching [a-z0-9-] (got {value!r})")
    # Hand back the normalized slug; the validator returns it as the field value.
    return normalized


class Platform(str, Enum):
    """The bug-bounty platform a finding is destined for.

    This selects the report profile (:mod:`promptstrike.report.profiles`), which drives both the
    submission template and the readiness checklist — platforms disagree about what a report must
    contain, so the platform is a behavioural field, not a label.
    """

    # The VALUE (not the member name) is what the report profile registry is keyed on and
    # what is persisted to YAML/SQLite, so these strings are part of the on-disk contract.
    google_ai_vrp = "google_ai_vrp"    # Google AI Vulnerability Reward Program
    openai_h1 = "openai_h1"            # OpenAI, via HackerOne
    anthropic_h1 = "anthropic_h1"      # Anthropic, via HackerOne
    msrc = "msrc"                      # Microsoft Security Response Center
    bugcrowd = "bugcrowd"              # Bugcrowd-hosted program
    hackerone = "hackerone"            # generic HackerOne-hosted program
    other = "other"                    # fallback profile; also the default for a finding


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

    draft = "draft"          # created by the tool; not yet checked against the profile
    ready = "ready"          # passed the readiness checklist - as far as the TOOL goes
    # Everything below is recorded by the operator after submitting by hand. The tool
    # never sets these, because it never submits.
    submitted = "submitted"  # operator has sent it to the program
    accepted = "accepted"    # program accepted the report
    rejected = "rejected"    # program rejected the report
    duplicate = "duplicate"  # program closed it as a duplicate of an existing report


class ScopeAsset(BaseModel):
    """A single in-scope or out-of-scope asset within a program definition.

    ``value`` is validated non-empty on purpose: an empty asset matches nothing under
    :func:`promptstrike.scope.asset_matches`, but reads like a wildcard to a human editing the YAML
    by hand. Rejecting it at the boundary keeps that misreading from ever reaching a scope check.
    """

    # The asset itself - a URL, hostname, domain or model id, interpreted per ``type`` below.
    value: str
    # Defaults to the NARROWEST useful rule (host+path prefix) rather than a wildcard type, so
    # an operator who omits the type does not accidentally widen what may be tested.
    type: AssetType = AssetType.endpoint
    # Free-text provenance for the operator (e.g. "from the program page, 2026-01"); unused by
    # the matching logic.
    note: str = ""

    # Runs on every construction, including when a program YAML is loaded from the registry.
    @field_validator("value")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        # Trim first, so a whitespace-only value is caught rather than stored.
        v = v.strip()
        # See the class docstring: an empty value matches NOTHING but reads like a wildcard, so
        # it is refused here rather than being allowed to reach a scope check.
        if not v:
            raise ValueError("scope asset value must be non-empty")
        # Store the trimmed form; asset_matches lower-cases it at comparison time.
        return v


class Program(BaseModel):
    """An authorized bug-bounty program and its scope. The safety spine reads from this."""

    name: str  # slug, unique key
    # Human-readable label for reports; defaults to ``name`` via _defaults() below.
    display_name: str = ""
    # Which platform profile a report drafted for this program should follow.
    platform: Platform = Platform.other
    # Assets that MAY be tested. An empty list authorizes nothing, because scope.check
    # falls through to its default deny.
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    # Carve-outs, evaluated BEFORE in_scope by scope.check, so these always win on overlap.
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)
    # The master authorization switch. Default False, so a program transcribed without this
    # line authorizes nothing - scope.check refuses it before looking at any asset.
    allows_ai_testing: bool = False
    # Per-program rate cap when the program publishes one; None falls back to the setting.
    rate_limit_rps: float | None = None
    # Whether the program publishes a safe-harbor statement. Recorded for the operator and
    # deliberately NOT wired to any gate - the gate is allows_ai_testing.
    safe_harbor: bool = False
    # Security-contact address, so the operator can reach the program to submit by hand.
    contact: str = ""
    # Free-text operator notes (scope caveats, dates, a link to the program page).
    notes: str = ""

    # Enforced on load as well as on creation, so a hand-edited registry file is checked too.
    @field_validator("name")
    @classmethod
    def _name_slug(cls, v: str) -> str:
        # The name becomes the registry filename, so it must satisfy the slug grammar.
        return _slug(v, field="program name")

    # Runs after every field is set, so it can fill one field from another.
    @model_validator(mode="after")
    def _defaults(self) -> Program:
        # Only fill the label when the operator left it out; never overwrite their wording.
        if not self.display_name:
            self.display_name = self.name
        # An "after" validator mutates and returns the instance itself.
        return self


class Probe(BaseModel):
    """A declarative probe: attack prompt(s) + the detector that decides whether the model failed."""

    id: str  # slug
    # Human-readable probe title, shown in run output and copied into drafted reports.
    name: str
    # OWASP-LLM category tested; also what derives the default CWEs and framework refs.
    category: OwaspLLM
    # What the probe is looking for, in prose, for the report and the run listing.
    description: str = ""
    # The attack prompt(s). Each is sent via TargetClient.send, so each is scope-checked.
    prompts: list[str] = Field(default_factory=list)
    detector: str  # name registered in probes.detectors
    # Keyword arguments handed to that detector, so one detector serves many YAML probes.
    detector_args: dict = Field(default_factory=dict)
    # Starting severity for a finding drafted from this probe; a CVSS vector overrides it.
    severity_hint: Severity = Severity.medium
    # CWE ids to cite. Usually left empty in the pack; _fill_cwe derives them below.
    cwe: list[str] = Field(default_factory=list)
    # Free-form labels used to select a subset of the pack at run time.
    tags: list[str] = Field(default_factory=list)

    # Probe ids are referenced from ProbeResult and the CLI, so they get the same grammar.
    @field_validator("id")
    @classmethod
    def _id_slug(cls, v: str) -> str:
        # Same slug rule as a program name, quoted as "probe id" in the error message.
        return _slug(v, field="probe id")

    # Runs after the model is fully populated, so ``category`` is available here.
    @model_validator(mode="after")
    def _fill_cwe(self) -> Probe:
        # Only derive when the pack author listed none - an explicit list always wins.
        if not self.cwe:
            self.cwe = default_cwes(self.category)
        # Return the (possibly enriched) instance, as an "after" validator must.
        return self


class Evidence(BaseModel):
    """One request/response exchange captured during a probe run — the reproducibility artifact."""

    # What was sent, verbatim. Stored in full here - unlike the auth log, which only hashes
    # it - because a finding is not reproducible without the exact prompt.
    prompt: str
    # What came back. Empty on a dry run, where nothing was sent.
    response: str
    # Model the target reported answering with, falling back to the configured one.
    model: str = ""
    # Finer-grained build/version when the target reports one; most targets do not.
    model_version: str = ""
    # When the exchange was captured, in UTC - see _utcnow.
    timestamp: datetime = Field(default_factory=_utcnow)
    # Round-trip time; None on a dry run, which never measured one.
    latency_ms: int | None = None
    # Transport details plus the "dry_run" flag and the target, which TargetClient.send passes
    # through redact_target first. That removes userinfo, secret-bearing query and fragment
    # values, and path segments carrying a known credential prefix - it is not a guarantee
    # against an unrecognised secret embedded in an arbitrary path segment.
    metadata: dict = Field(default_factory=dict)


class ProbeResult(BaseModel):
    """The complete record of one probe run against one target — whether or not it triggered.

    Every run is persisted, not only the ones that fired: a probe that did not trigger is the
    evidence that the category was tested and held. ``dry_run`` defaults to ``True`` so a result
    that never went near the network can never be mistaken for a live one.
    """

    # Groups every probe result produced by one `promptstrike test` invocation.
    run_id: str
    # Which probe produced this result (the Probe.id slug).
    probe_id: str
    # Program the run was authorized under - the same name the auth log records.
    program: str
    # Target this probe was aimed at, as the operator supplied it.
    target: str
    # OWASP-LLM category, copied from the probe so a stored result reads standalone.
    category: OwaspLLM
    # Whether the detector judged the model to have failed. False results are persisted
    # too - they are the evidence that the category was tested and held.
    triggered: bool
    # Which detector made that call, so the judgement stays auditable after the fact.
    detector: str
    # Defaults True so a result that never went near the network cannot read as a live one.
    dry_run: bool = True
    # The captured exchanges backing this result - one per prompt the probe sent.
    evidence: list[Evidence] = Field(default_factory=list)
    # Detector-supplied explanation of WHY it triggered, or did not.
    detail: str = ""
    # UTC creation time, used to order runs in the findings database.
    created_at: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    """A confirmed, reportable finding. Setting a CVSS v3.1 vector recomputes score + severity."""

    # SQLite row id; None until the finding has been persisted.
    id: int | None = None
    # The probe run this came out of, when there was one. None for a hand-written finding.
    run_id: str | None = None
    # Program slug - which authorization this finding was discovered under.
    program: str
    # Destination platform, which selects the report profile and readiness checklist.
    platform: Platform = Platform.other
    # One-line headline; becomes the report title.
    title: str
    # OWASP-LLM category, and the key _derive() uses to fill cwe and framework_refs.
    category: OwaspLLM
    # Working severity. Recomputed from the CVSS v3.1 vector by _derive() when one is set.
    severity: Severity = Severity.medium
    # CWE ids cited in the report; derived from the category when left empty.
    cwe: list[str] = Field(default_factory=list)
    # The affected endpoint/host/model, carried over from ProbeResult.target and redacted at
    # promotion (see finding.promote), along with every other field derived from it - title,
    # description and reproduction steps - because this object is rendered into the report that
    # is submitted to a third party.
    target: str = ""
    # Model that exhibited the issue, and its build if the target reported one.
    model: str = ""
    model_version: str = ""
    # Short abstract for the top of the report.
    summary: str = ""
    # Full technical write-up.
    description: str = ""
    # Ordered reproduction steps - what makes the report actionable for the program.
    steps_to_reproduce: list[str] = Field(default_factory=list)
    # Why it matters, in the program's terms.
    impact: str = ""
    # Suggested fix. Operator-written on purpose - see the NOTE at the end of _derive().
    remediation: str = ""
    # CVSS v3.1 vector string; setting it drives the two derived values below.
    cvss_v31_vector: str = ""
    # Computed from the vector by _derive(); never set by hand.
    cvss_v31_score: float | None = None
    cvss_v40_vector: str = ""  # validated + recorded; scored via FIRST calculator (see cvss.py)
    # The captured exchanges that prove the finding - the reproducibility artifact.
    evidence: list[Evidence] = Field(default_factory=list)
    # Source URLs cited in the report (advisories, docs, the program page).
    references: list[str] = Field(default_factory=list)
    #: Related framework entry ids, keyed by knowledge-pack framework ("atlas", "llmsvs", ...).
    #: Derived from the category when empty. A dict rather than one field per framework so adding a
    #: framework to the pack stays a data change.
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)
    # Workflow state. Starts at draft; the tool never advances it past ready, because it
    # never submits - the operator records everything after that by hand.
    status: FindingStatus = FindingStatus.draft
    # UTC creation time, used to order findings in the database and the CLI listing.
    created_at: datetime = Field(default_factory=_utcnow)

    def refs(self, framework: str) -> list[str]:
        """Related entry ids in one knowledge-pack framework; empty if none apply."""
        # Copy the list rather than handing out the stored one, so a template or a caller
        # cannot mutate the finding's refs by accident. An unknown framework yields [].
        return list(self.framework_refs.get(framework, []))

    # Runs on every construction AND on every re-validation, so a finding loaded back from
    # the database gets the same derived values as one just created.
    @model_validator(mode="after")
    def _derive(self) -> Finding:
        # A CVSS v3.1 vector is authoritative: it overrides whatever severity was passed in,
        # so the score and the label in a report can never disagree.
        if self.cvss_v31_vector:
            # score_v31 returns both the numeric score and the band it falls in.
            score, sev = score_v31(self.cvss_v31_vector)
            self.cvss_v31_score = score
            self.severity = sev
        # v4.0 is recorded but not scored here (see cvss.py); parsing it is a validity check.
        if self.cvss_v40_vector:
            parse_v40_vector(self.cvss_v40_vector)  # validate; raises on malformed
        # Derive CWEs from the category only when the caller supplied none.
        if not self.cwe:
            self.cwe = default_cwes(self.category)
        # Same for the knowledge-pack cross-references.
        if not self.framework_refs:
            # Deferred so that importing promptstrike.models does not load the pack; the pack loads
            # (once, cached) on first Finding construction. There is no import cycle to avoid here —
            # promptstrike.knowledge imports taxonomy only, never models.
            from promptstrike import knowledge

            # Map the OWASP-LLM category onto each framework the pack ships.
            self.framework_refs = knowledge.refs_for(self.category)
        # NOTE: `remediation` is deliberately NOT auto-filled from the pack. It feeds the
        # submission-readiness checklist (report.profiles._has_remediation); filling it here would
        # make that check pass for every finding. See knowledge.suggest_remediation.
        return self
