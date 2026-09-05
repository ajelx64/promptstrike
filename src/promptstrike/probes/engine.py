"""Probe harness: load the declarative pack and run probes against an authorized target.

Every prompt goes through :class:`TargetClient`, so scope enforcement + rate-limiting + logging are
inherited automatically. In a dry run, responses are empty and detectors naturally do not trigger —
the run still records exactly which prompts *would* be sent.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml

from promptstrike.llm.target import TargetClient, redact_target
from promptstrike.models import Evidence, Probe, ProbeResult
from promptstrike.probes.detectors import run_detector


def builtin_pack_dir() -> Path:
    """Directory holding the probe pack shipped with the package (``probes/pack/*.yaml``)."""
    # The pack shipped inside the package itself, resolved relative to this module's location.
    return Path(__file__).parent / "pack"


def load_pack(pack_dir: str | Path) -> list[Probe]:
    """Load every ``*.yaml`` in ``pack_dir`` into Probe models (a file may hold one probe or a list)."""
    # Accept either a str or Path uniformly from here on.
    directory = Path(pack_dir)
    # Accumulates every Probe parsed out of the pack directory, in filename order.
    probes: list[Probe] = []
    # Sorted glob so pack load order (and therefore probe order) is deterministic.
    for pack_file in sorted(directory.glob("*.yaml")):
        # Parse the YAML file's raw structure before validating it against the Probe model.
        data = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
        # A pack file may hold a single probe mapping or a list of them — normalize to a list.
        items = data if isinstance(data, list) else [data]
        # Validate each raw item into a Probe model, failing loudly on a malformed probe.
        for item in items:
            probes.append(Probe.model_validate(item))
    # Every probe found across every file in the pack directory.
    return probes


def get_probe(probes: list[Probe], probe_id: str) -> Probe | None:
    """Find a probe by id within an already-loaded pack, or ``None`` if it defines no such id."""
    # Linear scan by id; pack sizes are small enough that this needs no index structure.
    return next((probe for probe in probes if probe.id == probe_id), None)


async def run_probe(
    client: TargetClient,
    probe: Probe,
    target: str,
    *,
    live: bool,
    run_id: str | None = None,
) -> ProbeResult:
    """Run every prompt in ``probe`` against ``target``; a triggered detector marks the run."""
    # Generate a short run id when the caller doesn't supply one, so evidence files stay unique.
    run_id = run_id or uuid.uuid4().hex[:12]
    # Collects one Evidence entry per prompt sent, in send order.
    evidence: list[Evidence] = []
    # Whether ANY prompt in this probe triggered its detector — a probe fails if any turn does.
    triggered = False
    # Collects the detail string from every triggering prompt, joined for the run's summary.
    details: list[str] = []

    # Send every prompt the probe defines, in declared order (multi-turn probes rely on this).
    for prompt in probe.prompts:
        # TargetClient owns scope enforcement, rate-limiting, and dry-run behavior for this send.
        evidence_entry = await client.send(prompt, target, live=live)
        # Run the probe's declared detector against whatever came back (empty string on dry run).
        verdict = run_detector(probe.detector, evidence_entry.response, probe.detector_args)
        # Fold the verdict into the evidence's own metadata so it travels with the record.
        evidence_entry.metadata["detector_triggered"] = verdict.triggered
        evidence_entry.metadata["detector_detail"] = verdict.detail
        # Keep this turn's evidence regardless of verdict — passing turns are evidence too.
        evidence.append(evidence_entry)
        if verdict.triggered:
            # Mark the whole probe as triggered and remember why, for the run-level detail string.
            triggered = True
            details.append(verdict.detail)

    if triggered:
        # Summarize every triggering detail across all turns into one run-level string.
        detail = "; ".join(details)
    elif not live:
        # Dry runs never send real traffic, so "no trigger" here just means nothing was tried.
        detail = "dry run (rendered only, nothing sent)"
    else:
        # A live run that never triggered any detector is a genuine clean result.
        detail = "no detector trigger"

    # Package the run's inputs, verdict, and full evidence trail for storage/promotion.
    return ProbeResult(
        run_id=run_id,
        probe_id=probe.id,
        program=client.program.name,
        # Redacted here because RunStore writes this straight to <run_id>.json, and the
        # evidence directory is durable - it is the directory an operator is most likely to
        # archive or attach. Every other consumer of a target redacts; this path did not.
        target=redact_target(target),
        category=probe.category,
        triggered=triggered,
        detector=probe.detector,
        dry_run=not live,
        evidence=evidence,
        detail=detail,
    )
