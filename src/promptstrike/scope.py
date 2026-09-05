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
from urllib.parse import unquote, urlparse

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


# Ports that carry no meaning because they are the scheme's default; "example.com:443" and
# "example.com" are the same origin, so the gate must not treat them as different assets.
_DEFAULT_PORTS = {"http": "80", "https": "443"}

# How many times a percent-decode is retried before giving up. Double-encoding ("%2561dmin")
# decodes to "%61dmin", which some servers decode a second time; one pass would leave the gate
# comparing a different string than the server resolves. The cap stops a decode bomb.
_MAX_PERCENT_DECODE_PASSES = 3


def _decode_percent_escapes(path: str) -> str:
    """Percent-decode ``path`` until it stops changing, bounded by the pass cap."""
    # Track the value across passes so we can stop as soon as decoding is a no-op.
    decoded = path
    # Bounded loop: repeated decoding handles multiply-encoded input without unbounded work.
    for _ in range(_MAX_PERCENT_DECODE_PASSES):
        # Decode one layer of %XX escapes.
        once = unquote(decoded)
        # A pass that changes nothing means we have reached the fully decoded form.
        if once == decoded:
            break
        # Otherwise keep the decoded value and try again.
        decoded = once
    # Return the most-decoded form we reached.
    return decoded


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.`` and ``..`` segments, per RFC 3986 section 5.2.4."""
    # Accumulates the surviving segments in order.
    resolved: list[str] = []
    # Split on "/" and walk each segment; empty strings here are the duplicate-slash case.
    for segment in path.split("/"):
        # "." means "this directory" and contributes nothing.
        if segment == ".":
            continue
        # ".." pops the previous segment, which is how traversal is normally written.
        if segment == "..":
            # Only pop if there is something to pop; escaping above the root is clamped, not an
            # error, so a target cannot climb out of the comparison entirely.
            if resolved:
                resolved.pop()
            continue
        # An empty segment comes from "//" - drop it so duplicate slashes collapse.
        if segment == "":
            continue
        # Anything else is a real segment and is kept.
        resolved.append(segment)
    # Re-join with a single leading slash; the caller strips the leading slash for hosts.
    return "/".join(resolved)


def _norm_endpoint(value: str) -> str:
    """Reduce a URL or ``host/path`` string to the exact form the transport will request.

    The gate compares strings; the transport (httpx) canonicalizes before sending. If the two
    disagree, an out-of-scope carve-out can be walked around by spelling the same resource
    differently — ``/v1/x/../admin``, ``/v1//admin``, ``/v1/%61dmin`` and ``host:443/v1/admin``
    all reach ``/v1/admin`` on the wire. Both the asset and the target go through this function,
    so the comparison happens in one canonical space rather than on raw operator input.

    Query strings are still dropped, so an in-scope endpoint keeps matching when invoked with
    params (e.g. Azure-hosted models' ``?api-version=...``).
    """
    # Normalize whitespace and case up front; hosts are case-insensitive and paths are compared
    # case-insensitively here on purpose, because a carve-out spelled /admin must also catch
    # /ADMIN rather than failing open on capitalisation.
    working = value.strip().lower()
    # Remember the scheme before removing it - it decides which port counts as default.
    scheme = ""
    # A scheme is present only when "://" appears; bare "host/path" assets have none.
    if "://" in working:
        # Split once so a "://" later in the path cannot be mistaken for the scheme separator.
        scheme, working = working.split("://", 1)
    # Drop the query string and fragment; neither identifies the resource for scope purposes.
    working = working.split("?", 1)[0].split("#", 1)[0]
    # Separate authority (host[:port]) from path at the first slash.
    authority, slash, path = working.partition("/")
    # Userinfo ("user:secret@host") is credentials, not identity - strip it so it cannot be used
    # to make an out-of-scope host look like a different string.
    if "@" in authority:
        # Take the part after the LAST "@", since userinfo may itself contain one.
        authority = authority.rsplit("@", 1)[1]
    # Remove the port when it is the scheme's default, so host and host:443 compare equal.
    if ":" in authority:
        # Split the port off the host.
        host_only, _, port = authority.rpartition(":")
        # Only strip when we know the scheme and the port is that scheme's default.
        if host_only and port == _DEFAULT_PORTS.get(scheme):
            authority = host_only
    # Restore the leading slash that partition() consumed, when there was a path at all.
    path = slash + path
    # Decode percent-escapes so %61dmin is compared as admin.
    path = _decode_percent_escapes(path)
    # Strip RFC 3986 path parameters (";sid=1") from each segment; servers ignore them for
    # routing, so leaving them in would let ";" hide a carve-out.
    path = "/".join(segment.split(";", 1)[0] for segment in path.split("/"))
    # Resolve dot-segments and collapse duplicate slashes.
    path = _remove_dot_segments(path)
    # Re-assemble; the path is empty for a bare host, in which case no slash is added.
    canonical = authority + ("/" + path if path else "")
    # Drop any trailing slash so "/v1/" and "/v1" are the same asset.
    return canonical.rstrip("/")


def asset_matches(asset: ScopeAsset, target: str) -> bool:
    """Does ``target`` fall under ``asset`` given the asset's type? Boundary-safe (no over-match).

    Endpoint matching is intentionally scheme- and port-agnostic (http/https collapse; an explicit
    port is not matched against a portless asset). Both are the fail-closed direction for an
    authorization gate — when in doubt, deny.
    """
    # Split the target into the pieces each asset type needs; raw keeps the original spelling.
    host, _path, raw = _split_target(target)
    # The asset's own value, normalized for case so comparisons are case-insensitive.
    asset_value = asset.value.strip().lower()

    if asset.type == AssetType.model:
        token = raw.strip().lower()
        return token == asset_value or token == f"model:{asset_value}"

    if asset.type == AssetType.host:
        return host == asset_value if host else raw.strip().lower() == asset_value

    if asset.type == AssetType.domain:
        # An explicit "*." prefix means subdomains ONLY. Bug-bounty scope grammars treat the apex
        # as a separate asset that is frequently excluded, so letting the wildcard cover it would
        # silently widen scope inside the deny-by-default control.
        wildcard_only = asset_value.startswith("*.")
        # The domain itself, with any wildcard prefix removed.
        base_domain = asset_value.removeprefix("*.")
        # No host means there is nothing to compare against.
        if not host:
            return False
        # A subdomain match is valid for both spellings, and the leading dot keeps it
        # boundary-safe so example.com.evil.net cannot match example.com.
        if host.endswith("." + base_domain):
            return True
        # The apex matches only when the asset was written WITHOUT a wildcard.
        return host == base_domain and not wildcard_only

    # endpoint (default): both sides are reduced to the form the transport will actually
    # request, then compared as a host+path prefix on a "/" boundary so /v1 cannot match
    # /v1administrator while /v1/administrator still does.
    canonical_asset = _norm_endpoint(asset_value)
    canonical_target = _norm_endpoint(raw)
    return canonical_target == canonical_asset or canonical_target.startswith(canonical_asset + "/")


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
