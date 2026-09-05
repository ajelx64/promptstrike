"""Scope registry + rules-of-engagement enforcement — the safety spine.

Every action that could send traffic to a target MUST pass ``check()``/``enforce()`` first. Decision
precedence is intentionally conservative:

1. If the program does not set ``allows_ai_testing`` -> DENY.
2. If the target matches ANY out-of-scope asset -> DENY (out-of-scope wins over in-scope).
3. If the target matches an in-scope asset -> ALLOW.
4. Otherwise -> DENY (default deny).

Programs are stored as human-editable YAML (one file per program) so the operator can review and edit
scope by hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from promptstrike.models import AssetType, Program, ScopeAsset


class ScopeError(Exception):
    """Raised when an action targets an asset outside an authorized program's scope."""


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of one scope evaluation, and why.

    ``reason`` is surfaced to the operator and copied verbatim into the authorization log, so it
    names the asset that decided the outcome rather than only saying yes or no. ``matched`` is the
    asset value that produced the decision, or ``None`` when nothing matched at all — which is a
    default deny, not an error.
    """

    allowed: bool
    reason: str
    matched: str | None = None


def _split_target(target: str) -> tuple[str | None, str, str]:
    """Return ``(host, path, raw)`` for a URL, ``host/path`` string, or bare host/model token."""
    raw = target.strip()
    if "://" in raw:
        u = urlparse(raw)
        return (u.hostname.lower() if u.hostname else None), (u.path or ""), raw
    if "/" in raw:
        host, _, path = raw.partition("/")
        return (host.lower() or None), "/" + path, raw
    return raw.lower(), "", raw


def _norm_endpoint(value: str) -> str:
    """Strip scheme + query/fragment, lowercase, drop trailing slash — for host+path prefix compare.

    Query strings are dropped so an in-scope endpoint still matches when invoked with params
    (e.g. Azure-hosted models' ``?api-version=...``).
    """
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("?", 1)[0].split("#", 1)[0]
    return v.rstrip("/")


def asset_matches(asset: ScopeAsset, target: str) -> bool:
    """Does ``target`` fall under ``asset`` given the asset's type? Boundary-safe (no over-match).

    Endpoint matching is intentionally scheme- and port-agnostic (http/https collapse; an explicit
    port is not matched against a portless asset). Both are the fail-closed direction for an
    authorization gate — when in doubt, deny.
    """
    host, _path, raw = _split_target(target)
    val = asset.value.strip().lower()

    if asset.type == AssetType.model:
        token = raw.strip().lower()
        return token == val or token == f"model:{val}"

    if asset.type == AssetType.host:
        return host == val if host else raw.strip().lower() == val

    if asset.type == AssetType.domain:
        base = val.removeprefix("*.")
        return bool(host) and (host == base or host.endswith("." + base))

    # endpoint (default): normalized host+path prefix match with a "/" boundary.
    a = _norm_endpoint(val)
    t = _norm_endpoint(raw)
    return t == a or t.startswith(a + "/")


def check(program: Program, target: str) -> ScopeDecision:
    """Evaluate scope for ``target`` against ``program`` using default-deny precedence."""
    if not program.allows_ai_testing:
        return ScopeDecision(False, f"program '{program.name}' does not authorize AI testing")
    for a in program.out_of_scope:
        if asset_matches(a, target):
            return ScopeDecision(False, f"target matches OUT-OF-SCOPE asset '{a.value}'", a.value)
    for a in program.in_scope:
        if asset_matches(a, target):
            return ScopeDecision(True, f"in scope via '{a.value}'", a.value)
    return ScopeDecision(False, f"target not in '{program.name}' in-scope list")


def enforce(program: Program, target: str) -> ScopeDecision:
    """Like ``check`` but raises :class:`ScopeError` when the target is not allowed."""
    decision = check(program, target)
    if not decision.allowed:
        raise ScopeError(decision.reason)
    return decision


class ProgramStore:
    """YAML-backed store of authorized programs (one ``<name>.yaml`` per program)."""

    def __init__(self, programs_dir: Path) -> None:
        self.dir = Path(programs_dir)

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.yaml"

    def exists(self, name: str) -> bool:
        """Is a program with this name already registered?"""
        return self._path(name).exists()

    def add(self, program: Program, *, overwrite: bool = False) -> Path:
        """Write ``program`` to ``<name>.yaml`` in the registry and return the path.

        Refuses to clobber an existing definition unless ``overwrite=True``. A program file *is* the
        authorization record for live testing, so replacing one silently could widen scope without
        the operator ever seeing it change.
        """
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(program.name)
        if path.exists() and not overwrite:
            raise FileExistsError(f"program '{program.name}' already exists at {path}")
        path.write_text(
            yaml.safe_dump(program.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        return path

    def get(self, name: str) -> Program | None:
        """Load one registered program by name, or ``None`` if there is no such program.

        Returning ``None`` rather than raising lets callers treat "not registered" as a denial:
        an unknown program authorizes nothing, which is the fail-closed reading.
        """
        path = self._path(name)
        if not path.exists():
            return None
        return Program.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def list(self) -> list[Program]:
        """Every registered program, name-sorted. A missing programs dir is empty, not an error."""
        if not self.dir.exists():
            return []
        programs: list[Program] = []
        for p in sorted(self.dir.glob("*.yaml")):
            programs.append(Program.model_validate(yaml.safe_load(p.read_text(encoding="utf-8"))))
        return programs

    @staticmethod
    def load_yaml(path: str | Path) -> Program:
        """Parse a program definition from an arbitrary path WITHOUT registering it.

        Used by ``program add --file`` to validate the operator's YAML before it enters the
        registry, so a malformed or over-broad definition fails at the boundary rather than at
        probe time when traffic is about to be sent.
        """
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return Program.model_validate(data)
