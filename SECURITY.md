# Security Policy

## Reporting a vulnerability **in promptstrike itself**

Use GitHub's [private vulnerability reporting](https://github.com/ajelx64/promptstrike/security/advisories/new)
— the **Report a vulnerability** button on this repository's Security tab. That keeps the report
private until a fix exists, which is the same courtesy this tool is built to extend to others.

Please include what you'd want to receive yourself: what you did, what happened, what you expected,
and the smallest reproduction you can manage.

This is a personal project with no service-level commitment. Expect an acknowledgement within about
a week. If a report is valid, I'd rather fix it slowly than dispute it quickly.

## Please do **not** report findings about *targets* here

If you used this tool and found a vulnerability in someone else's LLM or agent system, that finding
belongs to **their** disclosure process — the bug-bounty program you were authorized under. Do not
open an issue or advisory here containing another party's vulnerability details, working
proof-of-concept prompts, or evidence transcripts. This repository is the wrong venue and posting it
here may breach the program's terms and your own safe harbour.

## What I consider a vulnerability in this tool

The tool's value is a set of safety properties, so anything that breaks one is in scope:

- **A scope bypass.** Any target string that is ALLOWED when the authorized program's rules should
  deny it — particularly out-of-scope carve-outs, since those are the assets a program has
  explicitly told you not to touch. URL-normalization evasion counts.
- **Live traffic escaping a gate.** Any path that reaches a target while `PROMPTSTRIKE_DRY_RUN` is
  true, without `--live`, without a passing scope check, or without the rate limiter.
- **Anything that submits.** The tool must never POST a finding to a bug-bounty platform.
- **Secret or evidence leakage.** Credentials, prompts, or target responses reaching somewhere they
  should not — logs, reports, telemetry, stdout.
- **Code execution or injection reachable from target output.** Target responses are
  attacker-controlled; treat anything they can drive as a finding.

Reports that a probe fails to detect a given vulnerability class are welcome, but as feature
requests rather than security reports.

## Scope of this repository

`promptstrike` is offensive-security tooling for **authorized** testing only. It is scope-gated and
dry-run by default, it never mass-targets, and it never auto-submits. Registering a program in the
scope registry is an assertion that you are permitted to test it — you own that decision, and no
part of this tool verifies it on your behalf.

The bundled probe pack is deliberately canary-based: probes assert on benign markers such as
`PWNED123`, and none elicits harmful content or performs a destructive action.

## Supported versions

The latest release on `main`. There are no maintained release branches.
