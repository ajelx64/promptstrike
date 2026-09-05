# CLAUDE.md — promptstrike division deltas

Inherits the workspace's canonical development ruleset — approval gates, branch/commit naming,
the review gate, dry-run defaults, rollback docs. Only the deltas below are specific to this
project.

**That ruleset is deliberately NOT vendored into this repo, and must not be re-added.** This
repo is public; the canon names other projects and records which security controls are and are
not wired into their CI, so committing it here would disclose posture about repos other than
this one. Cloud sessions receive the process via account-enabled skills instead. The workspace's
canon-sync tooling enforces this: it excludes public repos, and its tests assert this repo is one.

## What this is

A personal, CLI-only Python tool for **authorized** AI/LLM bug-bounty testing and report generation.
It is authorized/defensive security tooling — it exists to find and *responsibly report* vulnerabilities
to programs that invite testing, then help write high-quality reports. It is **not** a scanner and must
never become a mass-targeting or auto-submitting tool.

## Division-specific gates (in addition to the Command canon)

- **Authorized-programs-only (hard gate).** No probe traffic may target an asset that is not registered
  in the scope registry for a program flagged `allows_ai_testing = true`. The scope check runs *before*
  any request leaves the process. Do not add code paths that bypass `scope.scope_check()`.
- **No auto-submission (hard gate).** The tool must never POST a finding to a bug-bounty platform's API.
  It produces reports for the operator to submit manually. Human-in-the-loop is a design invariant.
- **`DRY_RUN=true` is the default.** Live target traffic requires an explicit `--live` flag *and* a
  passing scope check *and* active rate-limiting. Never hardcode `dry_run=False`.
- **No-DoS.** All target traffic is rate-limited (`PROMPTSTRIKE_RATE_LIMIT_RPS`); abort on error spikes.
- **Sensitive local state never committed.** `data/` (program defs, evidence transcripts, findings DB,
  generated reports) is gitignored — it can contain target details and working PoCs.
- **Attribution.** CVSS / CWE / OWASP-LLM references in generated reports cite their sources.

## Commands (run in PowerShell, from this division)

```powershell
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt ; pip install -e .
python -m pytest                     # tests
python -m compileall src             # what CI-style checks run
ruff check .                         # lint
```

Core workflow (the gates above apply to every one of these):

```powershell
promptstrike program add --file program.yaml                     # register an authorized program + scope
promptstrike test --program X --probe all                        # DRY RUN by default; --live to fire
promptstrike report draft --finding N --platform google_ai_vrp   # MD/HTML/PDF
```

## Reuse note

The report engine is a port-and-extend of an earlier internal report generator — Jinja2 with
autoescape on + `asyncio.to_thread` for the CPU-bound PDF render. Our port makes the WeasyPrint
import **lazy** so a missing GTK stack soft-fails to HTML/Markdown instead of breaking the tool.
