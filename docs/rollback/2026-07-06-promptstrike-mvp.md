# Rollback — promptstrike MVP (2026-07-06)

## What shipped
Initial MVP of the `promptstrike` division: scope registry + enforcement, rate-limited/scope-locked
LLM target client with authorization logging, OWASP-LLM probe harness + pack, evidence→Finding
pipeline (CVSS v3.1 scoring), platform-native report generator (Jinja2/WeasyPrint), and
triage/dedup + checklist linter. CLI: `program`, `test`, `finding`, `report`, `triage`.

## Blast radius
**None external.** This is a self-contained local tool:
- `DRY_RUN=true` is the default; nothing is sent to any target without an explicit `--live` flag,
  a passing scope check, and rate-limiting.
- No auto-submission to any bug-bounty platform (a hard design gate).
- No deploys, no shared infrastructure, no customer data. All state is local under the gitignored
  `data/` dir. No secrets are committed (`.env` is gitignored; template is `.env.example`).

## How to roll back
Because nothing external was touched, rollback is purely local:

1. **Discard uncommitted work:** `git reset --hard` from the repo root (if committed,
   `git revert <sha>` or reset to the prior commit).
2. **Remove the project entirely (nuclear):** delete the repo directory. Nothing
   else in the Command references it.
3. **Local state:** delete the data dir (`~/.promptstrike/data` or `PROMPTSTRIKE_DATA_DIR`) to clear
   any registered programs, evidence, findings DB, and generated reports.

## Verify after rollback
Nothing to verify externally. If keeping the code, `python -m pytest` should remain green.
