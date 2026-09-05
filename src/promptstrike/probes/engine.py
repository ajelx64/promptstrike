"""Probe harness: load the declarative pack and run probes against an authorized target.

Every prompt goes through :class:`TargetClient`, so scope enforcement + rate-limiting + logging are
inherited automatically. In a dry run, responses are empty and detectors naturally do not trigger —
the run still records exactly which prompts *would* be sent.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml

from promptstrike.llm.target import TargetClient
from promptstrike.models import Evidence, Probe, ProbeResult
from promptstrike.probes.detectors import run_detector


def builtin_pack_dir() -> Path:
    """Directory holding the probe pack shipped with the package (``probes/pack/*.yaml``)."""
    return Path(__file__).parent / "pack"


def load_pack(pack_dir: str | Path) -> list[Probe]:
    """Load every ``*.yaml`` in ``pack_dir`` into Probe models (a file may hold one probe or a list)."""
    directory = Path(pack_dir)
    probes: list[Probe] = []
    for f in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else [data]
        for item in items:
            probes.append(Probe.model_validate(item))
    return probes


def get_probe(probes: list[Probe], probe_id: str) -> Probe | None:
    """Find a probe by id within an already-loaded pack, or ``None`` if it defines no such id."""
    return next((p for p in probes if p.id == probe_id), None)


async def run_probe(
    client: TargetClient,
    probe: Probe,
    target: str,
    *,
    live: bool,
    run_id: str | None = None,
) -> ProbeResult:
    """Run every prompt in ``probe`` against ``target``; a triggered detector marks the run."""
    run_id = run_id or uuid.uuid4().hex[:12]
    evidence: list[Evidence] = []
    triggered = False
    details: list[str] = []

    for prompt in probe.prompts:
        ev = await client.send(prompt, target, live=live)
        verdict = run_detector(probe.detector, ev.response, probe.detector_args)
        ev.metadata["detector_triggered"] = verdict.triggered
        ev.metadata["detector_detail"] = verdict.detail
        evidence.append(ev)
        if verdict.triggered:
            triggered = True
            details.append(verdict.detail)

    if triggered:
        detail = "; ".join(details)
    elif not live:
        detail = "dry run (rendered only, nothing sent)"
    else:
        detail = "no detector trigger"

    return ProbeResult(
        run_id=run_id,
        probe_id=probe.id,
        program=client.program.name,
        target=target,
        category=probe.category,
        triggered=triggered,
        detector=probe.detector,
        dry_run=not live,
        evidence=evidence,
        detail=detail,
    )
