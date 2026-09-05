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

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml

from promptstrike.models import AssetType, Program, ScopeAsset

# Program names become filenames in the registry directory, so they are restricted to a plain
# slug. Mirrors the validator on Program.name, but applies to RAW operator input too.
_PROGRAM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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

    # The gate's verdict. False is the default outcome of every path that did not explicitly
    # match an in-scope asset, so a new code path that forgets to decide denies rather than allows.
    allowed: bool
    reason: str
    matched: str | None = None


def _split_target(target: str) -> tuple[str | None, str, str]:
    """Return ``(host, path, raw)`` for a URL, ``host/path`` string, or bare host/model token."""
    # Keep the operator's original spelling intact; model assets are matched against it verbatim.
    raw = target.strip()
    # A scheme means this is a full URL, so let urlparse do the authority/path split for us.
    if "://" in raw:
        # urlparse gives us .hostname with the port and any userinfo already stripped off.
        parsed_url = urlparse(raw)
        # Lower-case the host (DNS is case-insensitive); a URL with no host stays None, not "".
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else None
        # Hand back the host and path separately; host/domain rules use one, endpoint rules both.
        return hostname, (parsed_url.path or ""), raw
    # No scheme but a slash: treat the leading token as the host and the rest as the path.
    if "/" in raw:
        # partition on the FIRST slash so the path keeps any further slashes intact.
        host, _, path = raw.partition("/")
        # An empty host becomes None so host/domain rules see "no host" rather than "".
        return (host.lower() or None), "/" + path, raw
    # Bare token: a hostname or a model id, with no path to speak of.
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

    # A model asset names a model id, not a network location, so it is matched on the whole token.
    if asset.type == AssetType.model:
        # Compare the raw token case-insensitively; model ids are not URLs and are not normalized.
        token = raw.strip().lower()
        # Accept the bare id and the explicit "model:" spelling; exact only, never a prefix, so
        # an asset of "gpt-x" cannot silently authorize "gpt-x-turbo".
        return token == asset_value or token == f"model:{asset_value}"

    # A host asset matches one exact hostname - no subdomains, which is what makes it narrower
    # than a domain asset.
    if asset.type == AssetType.host:
        # When the target parsed as a URL compare its host; otherwise the target IS the hostname.
        return host == asset_value if host else raw.strip().lower() == asset_value

    # A domain asset is the only wildcard-capable type, so its boundary handling is what keeps
    # scope from silently widening.
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
    # Canonicalize the operator-authored asset the same way the target is canonicalized, so the
    # comparison never depends on how either side happened to be spelled.
    canonical_asset = _norm_endpoint(asset_value)
    # Canonicalize the candidate target into that same space.
    canonical_target = _norm_endpoint(raw)
    # Exact match, or a descendant path - the "+ /" is the boundary guard, without it "/v1" would
    # match "/v1administrator" and an out-of-scope carve-out could be walked around.
    return canonical_target == canonical_asset or canonical_target.startswith(canonical_asset + "/")


def check(program: Program, target: str) -> ScopeDecision:
    """Evaluate scope for ``target`` against ``program`` using default-deny precedence."""
    # Precedence rule 1: a program that has not declared AI testing permitted authorizes nothing,
    # regardless of what its in-scope list says. Checked first so no asset can override it.
    if not program.allows_ai_testing:
        # Deny before any asset is even consulted.
        return ScopeDecision(False, f"program '{program.name}' does not authorize AI testing")
    # Precedence rule 2: exclusions are evaluated BEFORE inclusions, so out-of-scope always wins
    # over an overlapping in-scope entry (e.g. /v1 in scope but /v1/admin carved out).
    for excluded_asset in program.out_of_scope:
        # First carve-out that covers the target ends the evaluation.
        if asset_matches(excluded_asset, target):
            # Name the deciding asset in the reason so the operator can see WHICH rule refused.
            return ScopeDecision(
                False,
                f"target matches OUT-OF-SCOPE asset '{excluded_asset.value}'",
                excluded_asset.value,
            )
    # Precedence rule 3: only now may an in-scope asset authorize the target.
    for allowed_asset in program.in_scope:
        # First inclusion that covers the target wins.
        if asset_matches(allowed_asset, target):
            # Record which asset granted authorization; this is copied into the auth log.
            return ScopeDecision(True, f"in scope via '{allowed_asset.value}'", allowed_asset.value)
    # Precedence rule 4: nothing matched, so deny. Default-deny is the whole point of the gate -
    # an unlisted target is refused rather than treated as unknown-but-probably-fine.
    return ScopeDecision(False, f"target not in '{program.name}' in-scope list")


def enforce(program: Program, target: str) -> ScopeDecision:
    """Like ``check`` but raises :class:`ScopeError` when the target is not allowed."""
    # Same evaluation as check(); this wrapper only changes how a denial is delivered.
    decision = check(program, target)
    # Turn a denial into an exception so a caller cannot ignore it by forgetting to test .allowed.
    if not decision.allowed:
        # The reason carries the deciding asset, so the error message is self-explaining.
        raise ScopeError(decision.reason)
    # Allowed: hand back the full decision so the caller can log which asset authorized it.
    return decision


class ProgramStore:
    """YAML-backed store of authorized programs (one ``<name>.yaml`` per program)."""

    def __init__(self, programs_dir: Path) -> None:
        # Accept a str or Path; the directory itself is created lazily on the first add().
        self.dir = Path(programs_dir)

    @staticmethod
    def _validated_name(name: str) -> str:
        """Reject a program name that could escape the registry directory.

        ``Program.name`` is slug-validated by pydantic, but ``get`` and ``exists`` take a raw
        string straight from ``--program``, so this method - not the model - is what stands
        between operator input and the filesystem. Low severity on a single-user CLI, but a
        security tool should not build a path out of unvalidated input.
        """
        # Anything that is not a plain slug is refused outright rather than sanitised, so a
        # surprising name fails loudly instead of silently resolving somewhere unexpected.
        if not _PROGRAM_NAME_RE.match(name):
            raise ValueError(
                f"invalid program name {name!r}: expected a slug matching [a-z0-9-]"
            )
        # The validated name is safe to join onto the registry directory.
        return name

    def _path(self, name: str) -> Path:
        # One file per program, named by the program's slug. add() always passes a Program.name,
        # which the model has already validated against the slug grammar; get()/exists() take a
        # raw operator-supplied string, so this is not itself a path-traversal guard.
        # Validate before the join; this is the only place a name becomes a path.
        return self.dir / f"{self._validated_name(name)}.yaml"

    def exists(self, name: str) -> bool:
        """Is a program with this name already registered?"""
        # Presence of the YAML file IS the registration; there is no separate index to fall out
        # of sync with it.
        return self._path(name).exists()

    def add(self, program: Program, *, overwrite: bool = False) -> Path:
        """Write ``program`` to ``<name>.yaml`` in the registry and return the path.

        Refuses to clobber an existing definition unless ``overwrite=True``. A program file *is* the
        authorization record for live testing, so replacing one silently could widen scope without
        the operator ever seeing it change.
        """
        # Create the registry directory on demand so a fresh install works with no setup step.
        self.dir.mkdir(parents=True, exist_ok=True)
        # Destination file for this program's authorization record.
        path = self._path(program.name)
        # Refuse to overwrite an authorization record unless the caller asked for it explicitly -
        # a silent replacement could widen scope without the operator seeing the change.
        if path.exists() and not overwrite:
            # Raise rather than return a flag; the CLI turns this into an operator-facing error.
            raise FileExistsError(f"program '{program.name}' already exists at {path}")
        # Serialize in JSON mode so enums/paths become plain scalars, and keep declaration order
        # (sort_keys=False) so the file stays readable and reviewable by hand.
        path.write_text(
            yaml.safe_dump(program.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        # Return the path so the caller can show the operator exactly what was written.
        return path

    def get(self, name: str) -> Program | None:
        """Load one registered program by name, or ``None`` if there is no such program.

        Returning ``None`` rather than raising lets callers treat "not registered" as a denial:
        an unknown program authorizes nothing, which is the fail-closed reading.
        """
        # Where this program's record would live if it were registered.
        path = self._path(name)
        # Unregistered is a normal state, not an error - see the docstring's fail-closed reading.
        if not path.exists():
            return None
        # safe_load refuses arbitrary Python tags, and model_validate re-checks the scope fields,
        # so a hand-edited or malformed file fails here rather than at probe time.
        return Program.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def list(self) -> list[Program]:
        """Every registered program, name-sorted. A missing programs dir is empty, not an error."""
        # No registry directory yet means nothing has been registered - an empty list, not a crash.
        if not self.dir.exists():
            return []
        # Accumulates the parsed programs in the order their files were walked.
        programs: list[Program] = []
        # Sorting the glob makes the listing deterministic (filenames are the program slugs).
        for program_path in sorted(self.dir.glob("*.yaml")):
            # Validate each file as it is read, so a corrupt record surfaces on `program list`.
            text = program_path.read_text(encoding="utf-8")
            programs.append(Program.model_validate(yaml.safe_load(text)))
        # Hand back the validated programs; the caller renders them for the operator.
        return programs

    @staticmethod
    def load_yaml(path: str | Path) -> Program:
        """Parse a program definition from an arbitrary path WITHOUT registering it.

        Used by ``program add --file`` to validate the operator's YAML before it enters the
        registry, so a malformed or over-broad definition fails at the boundary rather than at
        probe time when traffic is about to be sent.
        """
        # safe_load only, even for an operator-supplied path: a program file is untrusted input
        # until validated, and full YAML loading would let it construct arbitrary Python objects.
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        # Validate into a Program - this is the boundary check the docstring describes; nothing
        # is written to the registry here, so a rejected file never becomes an authorization.
        return Program.model_validate(data)
