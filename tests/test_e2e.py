"""End-to-end offline integration test.

Drives the REAL pipeline — including the live httpx transport — against a local mock LLM endpoint:
scope-check -> live probe -> evidence -> promote -> CVSS -> report render -> dedup. Proves the
`--live` path works without any external network.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from promptstrike.llm.target import AuthLog, RateLimiter, TargetClient
from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.probes.engine import builtin_pack_dir, get_probe, load_pack, run_probe
from promptstrike.report.generator import ReportGenerator
from promptstrike.report.profiles import get_profile
from promptstrike.scope import ScopeError, check
from promptstrike.storage import FindingStore, RunStore
from promptstrike.triage import dedupe

_CANARY = "PWNED123"


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps(
            {"model": "mock", "choices": [{"message": {"content": _CANARY}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # silence the test server
        pass


@pytest.fixture
def mock_endpoint():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/v1/chat"
    finally:
        server.shutdown()


def _program() -> Program:
    return Program(
        name="mock",
        platform=Platform.google_ai_vrp,
        allows_ai_testing=True,
        in_scope=[ScopeAsset(value="127.0.0.1", type=AssetType.host)],
    )


async def test_full_pipeline_live_against_mock(mock_endpoint, data_dir) -> None:
    program = _program()

    # 1. Scope: the mock endpoint is in-scope; an unrelated host is not.
    assert check(program, mock_endpoint).allowed is True
    assert check(program, "https://evil.test/").allowed is False

    # 2. Fire the prompt-injection probe LIVE at the mock (real httpx transport).
    client = TargetClient(
        program,
        rate_limiter=RateLimiter(rps=0),
        auth_log=AuthLog(data_dir / "auth.jsonl"),
        # Live path under test; production defaults this to False so a caller must opt in.
        allow_live=True,
    )
    probe = get_probe(load_pack(builtin_pack_dir()), "prompt-injection-direct")
    result = await run_probe(client, probe, mock_endpoint, live=True)
    assert result.triggered is True
    assert result.dry_run is False
    assert any(_CANARY in ev.response for ev in result.evidence)

    # 3. Persist the run, promote to a scored Finding.
    RunStore(data_dir / "evidence").save(result)
    from promptstrike.finding import promote

    finding = promote(
        result,
        program=program,
        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    with FindingStore(data_dir / "findings.db") as store:
        fid = store.add(finding)
    assert fid == 1
    assert finding.cvss_v31_score == 9.8

    # 4. Render a Google-AI-VRP report; the canary evidence must appear.
    md = ReportGenerator().render_markdown(finding, get_profile("google_ai_vrp"))
    assert _CANARY in md

    # 5. Dedup excludes the finding itself.
    assert dedupe(finding, [finding]).duplicates == []


async def test_out_of_scope_target_never_fires(mock_endpoint, data_dir) -> None:
    program = _program()  # only 127.0.0.1 is in scope
    client = TargetClient(
        program,
        rate_limiter=RateLimiter(rps=0),
        auth_log=AuthLog(data_dir / "auth.jsonl"),
        # Live path under test; production defaults this to False so a caller must opt in.
        allow_live=True,
    )
    probe = get_probe(load_pack(builtin_pack_dir()), "prompt-injection-direct")
    with pytest.raises(ScopeError):
        await run_probe(client, probe, "https://evil.test/v1/chat", live=True)
