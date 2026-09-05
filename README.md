# promptstrike

**An AI/LLM bug-bounty testing & reporting assistant — for authorized security testing only.**

`promptstrike` is a personal, CLI-only tool that helps you find, evidence, and *report* LLM/agent
vulnerabilities to bug-bounty programs that authorize AI testing (e.g. Google AI VRP, OpenAI &
Anthropic via HackerOne, Microsoft MSRC for Copilot). It is deliberately **not a scanner**: scanning
is a solved, commoditized problem, and the ecosystem now penalizes autonomous scan-and-spam tooling.
`promptstrike` owns the unsolved, higher-value layer above scanning:

- **Scope / rules-of-engagement enforcement** — the safety spine. You can only act against assets you
  registered as in-scope for a program that explicitly permits AI testing.
- **A curated LLM/agent probe pack** (OWASP LLM Top 10) that captures reproducible evidence transcripts.
- **High-quality, platform-native report generation** (draft → final, Markdown / HTML / PDF), with
  optional AI-assisted narrative drafting — the part that actually drives report acceptance and payout.

## Safety model (read this first)

- **`DRY_RUN=true` is the default.** No live network request is sent to any target until you
  lift the global switch (`PROMPTSTRIKE_DRY_RUN=false`) *and* pass `--live`, *and* the target
  passes a scope check, *and* rate-limiting is applied. The switch is enforced in
  `TargetClient.send`, the single point every prompt passes through - not only in the CLI.
- **Authorized programs only.** A target that is not in your scope registry (and flagged
  `allows_ai_testing`) is rejected *before* any request is sent — your CFAA / safe-harbor protection.
- **No auto-submission.** `promptstrike` never submits to a platform. It produces a report *you*
  review and submit. Human-in-the-loop, always.
- **Every run is logged** (program, scope asserted, targets, rate, timestamps) as a compliance artifact.

You own the authorization decision. Only register programs you are genuinely permitted to test.

## Install

```powershell
git clone https://github.com/ajelx64/promptstrike.git ; cd promptstrike
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt        # runtime + test deps
pip install -e .                           # installs the `promptstrike` CLI entry point
# optional: pip install -r requirements-pdf.txt   # PDF output (needs system GTK/Pango)
# optional: pip install anthropic                 # AI-assisted report drafting
```

Secrets are read from an env file **outside the repo**, resolved in this order:
`PROMPTSTRIKE_ENV_FILE` (an exact file) -> `PROMPTSTRIKE_SECRETS_DIR`/.env (a directory you
nominate) -> `~/.promptstrike/.env`.
See `.env.example` for the variables, and the
[Administrator Guide](docs/admin-guide.md) for the full configuration reference.

## Quickstart

```powershell
promptstrike program add --file my-program.yaml     # register an authorized program + scope
promptstrike program scope-check https://api.example.com/v1/chat -p example
promptstrike test --program example --probe prompt-injection-direct   # DRY_RUN: renders, sends nothing
$env:PROMPTSTRIKE_DRY_RUN='false'                                     # lift the global switch
promptstrike test --program example --probe prompt-injection-direct --live
promptstrike finding promote <run-id>
promptstrike report draft  --finding 1 --platform google_ai_vrp
promptstrike triage --finding 1
```

## Documentation

- **[User How-To Guide](docs/how-to-guide.md)** — full workflow, the program-definition schema, a
  reference for every command, the probe pack, report profiles, the TUI, and troubleshooting.
- **[Architecture](docs/architecture.md)** — the code map: how a probe becomes a report, where
  each safety invariant is enforced, the module reference, and the extension seams. Start here if
  you are reading the source or auditing the safety model.
- **[System Administrator Guide](docs/admin-guide.md)** — installation, configuration and environment
  variables, data & state layout, PDF/GTK setup, live-mode safety preconditions, and compliance/audit.

## Layout

```
src/promptstrike/
  config.py        settings (DRY_RUN, rate limit, data dir)
  models.py        Program, ScopeAsset, Probe, ProbeResult/Evidence, Finding
  scope.py         program registry + scope enforcement (the safety spine)
  finding.py       promote evidence -> Finding, CVSS 3.1 scoring + 4.0 vector validation,
                   CWE/OWASP-LLM mapping
  triage.py        dedup vs local history + pre-submission checklist linter
  llm/             target.py (in-scope, rate-limited client) + draft.py (Claude narrative)
  probes/          engine.py, detectors.py, pack/*.yaml (the probe library)
  report/          generator.py (Jinja2+WeasyPrint), profiles/*, templates/report/*
  knowledge/       vendored offline AI-security reference pack (OWASP, ATLAS, ...)
  storage.py       run evidence (JSON files) + findings (SQLite)
  taxonomy.py      OWASP LLM Top 10 ids, titles, CWE defaults
  commands/        one module per CLI command group
  tui/             optional Textual triage/report workbench
data/              gitignored: findings DB, program defs, evidence transcripts, reports
```

Development conventions for this project live in `CLAUDE.md`.

## License

[Apache-2.0](LICENSE).

## Status

A personal tool, developed in the open. Issues and questions are welcome; it is not a supported
product and there is no release cadence.

**Use it only against systems you are authorized to test.** You own that authorization decision —
registering a program in the scope registry is an assertion that you are permitted to test it.

## Security

Found a vulnerability **in this tool**? See [SECURITY.md](SECURITY.md) — please use GitHub's private
vulnerability reporting rather than a public issue.

Found a vulnerability in a **target** using this tool? That belongs to that program's disclosure
process, not here.
