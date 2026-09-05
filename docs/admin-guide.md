# promptstrike — System Administrator Guide

Installation, configuration, state, and operations for `promptstrike`. For day-to-day usage, see the
[User How-To Guide](how-to-guide.md).

`promptstrike` is a single-user, CLI-only Python tool. There is no server, daemon, database service, or
network listener to run — "operating" it means installing it, configuring an out-of-repo secrets file,
knowing where its local state lives, and keeping it backed up.

## Contents

- [Requirements & installation](#requirements--installation)
- [Configuration reference](#configuration-reference)
- [Data & state layout](#data--state-layout)
- [PDF rendering setup](#pdf-rendering-setup)
- [Live-mode safety preconditions](#live-mode-safety-preconditions)
- [Compliance & audit](#compliance--audit)
- [Maintenance](#maintenance)

## Requirements & installation

- **Python ≥ 3.11** (`pyproject.toml`).
- **Core runtime deps** (`requirements.txt`, no system libraries needed): `typer`, `jinja2`, `pydantic`,
  `pydantic-settings`, `httpx`, `pyyaml`.

Install into a virtualenv:

```powershell
git clone https://github.com/ajelx64/promptstrike.git ; cd promptstrike
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt    # runtime + test deps
pip install -e .                        # installs the `promptstrike` console script
```

`pip install -e .` registers the `promptstrike` entry point (`promptstrike.cli:app`).

### Optional extras

The core CLI is fully functional without any of these; install only what you need:

| Extra | Install | Enables | Notes |
|---|---|---|---|
| `pdf` | `pip install -r requirements-pdf.txt` or `pip install 'promptstrike[pdf]'` | PDF report output (WeasyPrint) | **Requires system GTK/Pango libraries** — see [PDF rendering setup](#pdf-rendering-setup). Soft-fails to HTML if absent. |
| `draft` | `pip install 'promptstrike[draft]'` (or `pip install anthropic`) | `report --ai` Claude-drafted narrative | Needs `ANTHROPIC_API_KEY`. Fully offline-mockable in tests. |
| `tui` | `pip install 'promptstrike[tui]'` | `promptstrike tui` workbench | `textual`. CLI works without it. |

> **Note on `requirements-dev.txt`:** it pulls in `textual` unguarded (not just via the `tui` extra),
> on purpose — the test suite imports `textual` at module scope so the no-target-traffic hard-gate tests
> cannot silently skip. This only affects the dev/test environment, not a runtime install.

## Configuration reference

Configuration comes from `PROMPTSTRIKE_*` environment variables, optionally loaded from an env file that
lives **outside the repo** (secrets never belong in the tree). Settings are defined in
`src/promptstrike/config.py`.

### Env-file resolution order

The active env file is resolved (`config.py` `_default_env_file()`), first match wins:

1. `PROMPTSTRIKE_ENV_FILE` — explicit path override.
2. `$PROMPTSTRIKE_SECRETS_DIR/.env` — a directory outside the repo that you nominate, used
   only if that file exists.
3. `~/.promptstrike/.env` — home fallback (if it exists).
4. None — rely on the process environment only.

Copy `.env.example` to whichever location above you use, and fill in values.
**Never commit real secrets** — keep the file outside the repo.

### Environment variables

| Variable | Purpose | Default | Read at |
|---|---|---|---|
| `PROMPTSTRIKE_DRY_RUN` | Global safety switch. When true, no live target traffic is ever sent (probes render only). Live *also* requires the `--live` CLI flag. | `true` | `config.py` (`dry_run`) |
| `PROMPTSTRIKE_RATE_LIMIT_RPS` | No-DoS cap: requests/sec across all target traffic. A program's own `rate_limit_rps` overrides this when set. | `1.0` | `config.py` (`rate_limit_rps`) |
| `PROMPTSTRIKE_DATA_DIR` | Root directory for all local state (DB, programs, evidence, reports, authlog). | `~/.promptstrike/data` | `config.py` (`data_dir`) |
| `PROMPTSTRIKE_ENV_FILE` | Explicit override of the env-file location (highest precedence). Warns if the named file does not exist. | unset | `config.py` (`_default_env_file`) |
| `PROMPTSTRIKE_SECRETS_DIR` | Directory holding a `.env`, used only if that file exists. Must be an absolute path. | unset | `config.py` (`_default_env_file`) |
| `ANTHROPIC_API_KEY` | Auth for AI-assisted report drafting (`report --ai`). Read by the anthropic SDK. | unset | `llm/draft.py` |
| `PROMPTSTRIKE_TARGET_MODEL` | Model name sent in the OpenAI-compatible chat payload to the live target. | `gpt-4o-mini` | `llm/target.py` |
| `PROMPTSTRIKE_TARGET_API_KEY` | Bearer token for the live target endpoint. Only used on `--live`; no `Authorization` header is sent if unset. | unset | `llm/target.py` |

`PROMPTSTRIKE_TARGET_MODEL` and `PROMPTSTRIKE_TARGET_API_KEY` are required to test an authenticated
target endpoint live. They are read directly from the process environment by the default transport (not
via the `Settings` object), so they belong in the same env file as the rest.

## Data & state layout

All local state is rooted at `PROMPTSTRIKE_DATA_DIR` (default `~/.promptstrike/data`). The directory
tree is created on demand (`Settings.ensure_dirs()`):

| Path | Contents | Written by |
|---|---|---|
| `<data_dir>/promptstrike.db` | SQLite findings database (single `findings` table: indexed columns + full model JSON). | `storage.py` (`FindingStore`) |
| `<data_dir>/programs/` | Registered program definitions (one file per program). | `scope.py` (`ProgramStore`) |
| `<data_dir>/evidence/<run-id>.json` | Probe run evidence transcripts (one file per run) — the reproducibility artifact. | `storage.py` (`RunStore`) |
| `<data_dir>/reports/finding-<id>-<profile>.{md,html,pdf}` | Generated reports. | `commands/report.py` |
| `<data_dir>/authlog.jsonl` | Append-only authorization log (see [Compliance & audit](#compliance--audit)). | `llm/target.py` (`AuthLog`) |

> **This data is sensitive.** Program definitions, evidence transcripts, and reports can contain target
> details and working proofs-of-concept. The repo gitignores the entire local-state surface (`data/`,
> `reports/`, `*.db`, `*.sqlite3`, `*.pdf`); if you relocate `PROMPTSTRIKE_DATA_DIR`, make sure the new
> location is not inside a tracked tree and is covered by your backup/retention policy.

## PDF rendering setup

PDF output uses WeasyPrint, which links against the system **GTK/Pango** stack.

1. Install the Python package: `pip install -r requirements-pdf.txt` (or the `pdf` extra).
2. Install the system libraries WeasyPrint needs (GTK/Pango/cairo) per the
   [WeasyPrint platform instructions](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

**Soft-fail behavior (by design):** if the WeasyPrint package or its system libraries are missing,
`report --format pdf` does not error — it writes an `.html` file instead and prints
`WeasyPrint unavailable — wrote HTML instead of PDF.`. The fallback is implemented in two lazy layers
(`report/generator.py` `render_pdf()` returns `None`; `commands/report.py` `_emit()` writes HTML). This
means a box without the GTK stack can still produce Markdown and HTML reports; only native PDF requires
the extra setup.

## Live-mode safety preconditions

Live target traffic is gated by four independent conditions that must **all** hold — this is defense in
depth, enforced in code (`config.py`, `commands/test.py`, `llm/target.py`):

1. `PROMPTSTRIKE_DRY_RUN` is `false`. The global default is `true`, and while it is true every
   live send is refused at `TargetClient.send` (exit 2 from the CLI) rather than downgraded.
2. The operator passes `--live` to `test` (its absence is always a dry run).
3. The per-call scope check passes for that exact target (out-of-scope → `ScopeError`, request never made).
4. The rate limiter admits the send.

Operationally, live testing against an authenticated endpoint also needs `PROMPTSTRIKE_TARGET_MODEL` and
`PROMPTSTRIKE_TARGET_API_KEY` set. Keep `PROMPTSTRIKE_RATE_LIMIT_RPS` conservative (or set a per-program
`rate_limit_rps`) to respect program rules and avoid load. `promptstrike` never auto-submits a finding
to any platform — that step is always manual.

## Compliance & audit

`<data_dir>/authlog.jsonl` is an append-only JSONL record written on **every** send attempt — allowed or
denied, live or dry (`llm/target.py` `AuthLog.record()`). Each line records: timestamp, program, target,
a SHA-256 prefix of the prompt plus its length, `requested_live` (what the operator asked for) vs `live`
(what actually happened — a denied `--live` attempt logs `live=false`), the `allowed` flag, and the
scope-decision `reason`.

Treat this log as your safe-harbor evidence: it demonstrates that every request was scope-checked and
that denied attempts never fired. Include it in your backup and retention policy alongside the evidence
transcripts.

## Maintenance

Development / CI-style checks (from the division `CLAUDE.md`):

```powershell
python -m pytest          # tests
python -m compileall src  # import/syntax check
ruff check .              # lint (config in ruff.toml)
```

- **Knowledge pack refresh.** The vendored AI-security frameworks under
  `src/promptstrike/knowledge/data/` are refreshed by a deliberate, human-reviewed operation (there is
  intentionally no runtime network fetch). A human-gated `knowledge update` ingest command is a tracked
  follow-up; until then, refreshes are manual and reviewed.
- **Backup & rollback.** Back up `PROMPTSTRIKE_DATA_DIR` (findings DB, programs, evidence, reports,
  authlog) on your normal schedule. For rolling back a tool upgrade, see
  [`docs/rollback/2026-07-06-promptstrike-mvp.md`](rollback/2026-07-06-promptstrike-mvp.md).
