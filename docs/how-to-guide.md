# promptstrike — User How-To Guide

A practical, end-to-end guide to using `promptstrike` for **authorized** AI/LLM bug-bounty testing and
report generation. For installation, configuration, and operations, see the
[System Administrator Guide](admin-guide.md).

> **Authorized testing only.** `promptstrike` will not send a single request to a target that you have
> not registered as in-scope for a program you have flagged as permitting AI testing. You own that
> authorization decision. Only register programs you are genuinely permitted to test.

## Contents

- [The mental model](#the-mental-model)
- [The safety model in practice](#the-safety-model-in-practice)
- [Defining an authorized program](#defining-an-authorized-program)
- [End-to-end workflow](#end-to-end-workflow)
- [Command reference](#command-reference)
- [The probe pack](#the-probe-pack)
- [Reports & platform profiles](#reports--platform-profiles)
- [The TUI workbench](#the-tui-workbench)
- [Troubleshooting](#troubleshooting)

## The mental model

`promptstrike` is a **testing + reporting** assistant, deliberately *not* a scanner. It owns the
higher-value layer above scanning: scope enforcement, reproducible evidence capture, and
platform-native report generation. The data flows in one direction:

```
program (authorized scope)  →  test (probe → evidence)  →  finding (evidenced + scored)
                                                              →  triage (dedup + lint)
                                                              →  report (draft → final)  →  you submit
```

Each stage produces a durable artifact under your data directory (see the admin guide for exact
paths): program YAML, evidence transcripts, a findings database, and generated reports. Nothing is
ever auto-submitted — the final step is always you, by hand.

## The safety model in practice

Four independent gates must all align before any request leaves the process. This is defense in depth
— disabling one does not open the door:

1. **`DRY_RUN` default.** The tool defaults to dry-run globally (`PROMPTSTRIKE_DRY_RUN=true`). In dry
   run, probes render and record what *would* be sent, but nothing hits the network.
2. **The `--live` flag.** Even with dry-run disabled, `test` only fires when you explicitly pass
   `--live`. Its absence is a dry run.
3. **Per-call scope check.** Every single send is scope-checked *before* the transport is touched. An
   out-of-scope target raises a `ScopeError` and is skipped — the request is never made.
4. **Rate limiting.** Live sends pass through a requests-per-second limiter (no-DoS guard), configurable
   globally or per-program.

On top of these: a program's probes stay **blocked** until you set `allows_ai_testing: true` on it, and
**every** attempt — allowed or denied, live or dry — is appended to an authorization log
(`authlog.jsonl`) as a compliance/safe-harbor artifact.

## Defining an authorized program

A program is the unit of authorization. You register one (usually from a YAML file) before you can test
anything. The full schema (from `src/promptstrike/models.py` — `Program` and `ScopeAsset`):

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string (slug) | — (required) | Unique key; must match `[a-z0-9][a-z0-9-]*`. |
| `display_name` | string | = `name` | Human-friendly label. |
| `platform` | enum | `other` | One of `google_ai_vrp`, `openai_h1`, `anthropic_h1`, `msrc`, `bugcrowd`, `hackerone`, `other`. |
| `in_scope` | list of asset | `[]` | Assets you may test (see below). Only `endpoint`-type assets are auto-targeted by `test`. |
| `out_of_scope` | list of asset | `[]` | Explicit exclusions. |
| `allows_ai_testing` | bool | `false` | **Must be `true` or all probes are blocked.** Your attestation that the program permits AI testing. |
| `rate_limit_rps` | float or null | `null` | Per-program request/sec cap; overrides the global default when set. |
| `safe_harbor` | bool | `false` | Records whether the program offers safe-harbor terms. |
| `contact` | string | `""` | Program/security contact. |
| `notes` | string | `""` | Free text. |

Each **scope asset** (`in_scope` / `out_of_scope` entry) is:

| Field | Type | Default | Notes |
|---|---|---|---|
| `value` | string | — (required) | The endpoint URL, model id, host, or domain. |
| `type` | enum | `endpoint` | One of `endpoint`, `model`, `host`, `domain`, `other`. |
| `note` | string | `""` | Free text. |

### Example `my-program.yaml`

```yaml
name: example
display_name: Example AI VRP
platform: google_ai_vrp
allows_ai_testing: true          # required — probes stay blocked without this
rate_limit_rps: 0.5              # optional; overrides the global cap for this program
safe_harbor: true
contact: security@example.com
in_scope:
  - value: https://api.example.com/v1/chat
    type: endpoint
    note: production chat completions endpoint
out_of_scope:
  - value: https://api.example.com/v1/internal
    type: endpoint
```

Register it with `promptstrike program add --file my-program.yaml`. You can also create a minimal
program purely from flags — see [`program`](#program) below.

## End-to-end workflow

The full cycle, with the commands you actually type. This example stays in **dry run** except where
noted; drop the safety rails only when you are ready to send real traffic to an authorized target.

```bash
# 1. Register an authorized program + its in-scope endpoints
promptstrike program add --file my-program.yaml

# 2. Confirm a specific target resolves in-scope (exit 0 = ALLOW, 2 = DENY)
promptstrike program scope-check https://api.example.com/v1/chat -p example

# 3. Dry-run a probe — renders the attack prompts, records intent, sends nothing
promptstrike test --program example --probe prompt-injection-direct

# 4. Go live — real, rate-limited, scope-checked requests (out-of-scope targets are skipped)
promptstrike test --program example --probe prompt-injection-direct --live

# 5. Promote a triggered run into a draft finding, scoring it with a CVSS v3.1 vector
promptstrike finding promote <run-id> \
    --title "Prompt injection overrides system instruction" \
    --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
    --platform google_ai_vrp

# 6. Triage before you write it up — local dedup + platform checklist gaps
promptstrike triage --finding 1

# 7. Draft the report (Markdown by default; add --ai for a Claude-drafted narrative)
promptstrike report draft --finding 1 --platform google_ai_vrp

# 8. Finalize — runs the submission checklist; marks the finding "ready" when clean
promptstrike report final --finding 1 --platform google_ai_vrp
```

### Reading `test` output

Each probe run against each target prints one line and saves an evidence transcript with a `run=<id>`:

- `[TRIGGERED] <probe> @ <target>  run=<id> :: <detail>` — the detector fired (a likely vulnerability).
- `[dry] <probe> @ <target>  run=<id>` — dry run; nothing was sent.
- `[clean] <probe> @ <target>  run=<id>` — live run, detector did not fire.
- `SKIP <probe> @ <target>: <reason>` — the target was out of scope; nothing was sent.

After a live run with triggers, the tool tells you the next step: `promptstrike finding promote <run-id>`.
(Dry runs are saved too and *can* be promoted, but a dry-run transcript has no captured response — real
evidence only comes from a `--live` run.)

## Command reference

Entry point: the `promptstrike` console script (`src/promptstrike/cli.py`). Running any group with no
subcommand prints its help.

### `program`

Manage authorized programs and their scope — the safety spine's front door.

| Subcommand | Purpose | Key flags |
|---|---|---|
| `add` | Register a program from YAML or minimal flags. | `--file/-f <yaml>`; or `--name <slug>` `--platform <enum>` `--in-scope <endpoint>` (repeatable) `--allows-ai-testing/--no-ai-testing` `--overwrite` |
| `list` | List registered programs (AI-OK flag + in-scope count). | — |
| `show <name>` | Print a program's full YAML definition. | — |
| `scope-check <target>` | Is `<target>` in scope for a program? Exit **0** allow, **2** deny, **1** unknown program. | `--program/-p <name>` (required) |

If you register a program with `allows_ai_testing` false, `add` warns you that probes will stay blocked.

### `test`

Run probes against a program's target(s). **Dry run by default.**

| Flag | Purpose |
|---|---|
| `--program/-p <name>` | Authorized program (required). |
| `--probe <id>` | A probe id, or `all` (default) to run the whole pack. |
| `--target/-t <url>` | Override the endpoint (still scope-checked). Otherwise every `endpoint`-type in-scope asset is targeted. |
| `--live` / `--dry-run` | Actually send vs. render only. Default `--dry-run`. |

### `finding`

Promote probe runs into findings and manage them.

| Subcommand | Purpose | Key flags |
|---|---|---|
| `promote <run-id>` | Turn a saved run into a draft finding. | `--title <str>` `--cvss "<v3.1 vector>"` (sets score + severity) `--platform <enum>` `--severity <level>` (manual, if no CVSS) |
| `list` | List findings (id, severity, category, program, status, title). | — |
| `show <id>` | Print a finding's full YAML. | — |

Setting a CVSS v3.1 vector recomputes the finding's numeric score **and** its severity automatically.
CWE and cross-framework references are derived from the OWASP-LLM category if you don't supply them.

### `report`

Generate platform-native reports (`draft` → `final`).

| Subcommand | Purpose | Key flags |
|---|---|---|
| `draft` | Generate a draft report. | `--finding <id>` (required) `--platform <profile>` (defaults to the finding's) `--format md\|html\|pdf` (default `md`) `--ai/--no-ai` |
| `final` | Generate a final report; runs the submission checklist and marks the finding **ready** when every item is satisfied (warns + lists gaps otherwise). | same as `draft` |

Reports are written to your reports directory as `finding-<id>-<profile>.<ext>`. `--ai` uses Claude to
draft the summary/impact/remediation narrative; if the `anthropic` package or an API key is missing, the
step is skipped with a warning and never fails the command. Requesting `--format pdf` without WeasyPrint
installed soft-fails to an `.html` file.

### `triage`

Lint a finding before you submit.

| Flag | Purpose |
|---|---|
| `--finding <id>` | Finding to triage (required). |
| `--platform <profile>` | Profile whose checklist to lint against (defaults to the finding's). |

Reports **duplicates** (another finding with the same category + target), **variants** (same category,
same host), and any **platform checklist gaps**.

### `knowledge`

Read-only inspection of the vendored AI-security knowledge pack (OWASP LLM/Agentic Top 10, MITRE ATLAS,
LLMSVS, AIDEFEND) that reports cite.

| Subcommand | Purpose |
|---|---|
| `sources` | List frameworks with provenance, license, and verified state. |
| `show <framework> [--id <entry>]` | List a framework's entries, or one entry's detail. |
| `search <query> [--framework/-f <key>]` | Substring search across ids/titles/descriptions. |
| `map <LLMxx>` | Resolve an OWASP-LLM category to cross-framework references + a draft remediation. |

### `tui`

Launch the interactive triage & report workbench (see [below](#the-tui-workbench)). Flag: `--db <path>`
to open a specific findings database (defaults to the configured data dir).

### `version`

Print the installed `promptstrike` version.

## The probe pack

Probes are declarative YAML (`src/promptstrike/probes/pack/*.yaml`): an id, an OWASP-LLM category, one or
more attack `prompts`, and a `detector` that decides whether the model failed. Six ship today, covering
OWASP LLM01/02/06/07:

| Probe id | OWASP | Detector | Severity hint |
|---|---|---|---|
| `prompt-injection-direct` | LLM01 | `contains_any` (canary `PWNED123`) | high |
| `indirect-injection` | LLM01 | `contains_any` | high |
| `jailbreak-guardrail-bypass` | LLM01 | `refusal_absent` | medium |
| `sensitive-info-disclosure` | LLM02 | `regex_any` | high |
| `excessive-agency-tool` | LLM06 | `contains_any` | high |
| `system-prompt-leak` | LLM07 | `regex_any` | medium |

The three detectors are `contains_any` (a canary/needle appears in the response), `regex_any` (a pattern
matches), and `refusal_absent` (the model did *not* refuse). Select one probe with `--probe <id>` or run
the whole pack with `--probe all` (the default). An unknown id prints the available list and exits 1.

## Reports & platform profiles

A **profile** maps a finding to one venue's severity taxonomy and its required-field checklist. The same
checklist drives both the report's readiness section and the `triage` linter. Six profiles ship:

| Profile key | Venue | Severity scheme | Extra checklist items (beyond the common set) |
|---|---|---|---|
| `google_ai_vrp` | Google AI VRP | named | Valid attack scenario (impact + steps) |
| `openai_h1` | OpenAI (HackerOne) | named | CWE mapped; remediation suggested |
| `anthropic_h1` | Anthropic (HackerOne) | named | CWE mapped; remediation suggested |
| `msrc` | Microsoft MSRC | named | Product + version / model identified |
| `bugcrowd` | Bugcrowd | VRT (P1–P5) | CWE mapped |
| `generic` | Generic | named | — |

The **common checklist** (every profile) requires: a specific descriptive title (≥8 chars), steps to
reproduce, an evidence/PoC transcript, a stated impact, and a CVSS v3.1 score. `report final` only marks
a finding `ready` when all items for the chosen profile pass; otherwise it lists exactly what's missing.
An unknown/blank profile key falls back to `generic`.

## The TUI workbench

`promptstrike tui` opens a Textual terminal workbench over the same engine — a second front-end for
triage and reporting with three tabs:

- **Findings** — a table of all findings.
- **Detail** — a markdown summary + the platform readiness checklist + an editable remediation field
  (with unsaved-draft stashing).
- **Report** — the live-rendered markdown report.

Key bindings: `q` quit, `r` reload, `i` insert the pack's suggested remediation, `s` / `Ctrl+S` save. By
design the workbench has **no code path that sends traffic** — probing stays on the CLI.

`textual` is an optional extra. If it isn't installed, `tui` prints an actionable message and exits
without breaking the rest of the CLI:

```bash
pip install 'promptstrike[tui]'
```

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `unknown probe '<x>'. Available: ...` | Typo in `--probe`. Use one of the listed ids or `all`. |
| `SKIP <probe> @ <target>: ...` during `test` | The target is out of scope for the program. Add it to `in_scope`, or check with `program scope-check`. |
| `no endpoint target: pass --target or add an endpoint asset` | The program has no `endpoint`-type in-scope asset. Add one, or pass `--target`. |
| Probes do nothing / everything is `[dry]` | You're in a dry run. Pass `--live` (and ensure the program has `allows_ai_testing: true`). |
| `report --format pdf` produced an `.html` file | WeasyPrint (and its system GTK/Pango libs) isn't installed — see the admin guide. Output soft-fails to HTML. |
| `tui` exits telling you to install something | `textual` isn't installed: `pip install 'promptstrike[tui]'`. |
| `--ai` says "AI drafting skipped" | The `anthropic` package or `ANTHROPIC_API_KEY` is missing. Drafting is optional; the report is still produced. |
| `scope-check` exits non-zero | Exit 2 = target denied (out of scope); exit 1 = unknown program. This is expected, not an error. |

For install, configuration, environment variables, data locations, and PDF/GTK setup, continue to the
[System Administrator Guide](admin-guide.md).
