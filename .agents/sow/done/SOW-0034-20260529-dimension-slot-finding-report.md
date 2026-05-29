# SOW-0034 - Dimension Slot Finding Report

## Status

Status: completed

Sub-state: corrected maintainer-facing vulnerability report created.

## Requirements

### Purpose

Create a Markdown report for the validated Netdata Agent `DIMENSION SLOT` issue that is accurate, reproducible in a lab, and does not overclaim unproven RCE.

### User Request

The user asked to create a Markdown report with `Summary`, `Details`, `PoC`, and `Impact`, including the corrected step-by-step sequence and reproduction guidance.

### Assistant Understanding

Facts:

- SOW-0032 validated authenticated remote heap corruption and parent-process DoS in the streaming `DIMENSION SLOT` path.
- SOW-0032 also found the RCE claim in the v2 branch overstates the evidence.
- `security-audit/ADVISORY-DOS.md` and other audit files are untracked and treated as user-owned.

Inferences:

- The new report should be a separate corrected artifact to avoid overwriting existing user work.
- The PoC section can document lab-only crash/ASan reproduction, but must not provide an RCE chain.

Unknowns:

- The final disclosure destination is not known. The report will be portable Markdown.

### Acceptance Criteria

- Create a new Markdown report under `security-audit/`.
- Include the requested four sections.
- Include the corrected "How it works" sequence.
- Include lab-only reproduction instructions with placeholders for credentials.
- State validated and unproven impact accurately.

## Analysis

Sources checked:

- SOW-0032 validation record.
- `security-audit/ADVISORY-DOS.md`.
- `security-audit/REPORT.md`.
- `src/plugins.d/pluginsd_internals.h`.
- `src/plugins.d/pluginsd_parser.c`.
- `src/database/rrdset-pluginsd-array.h`.
- `src/streaming/stream.conf`.

Current state:

- Existing branch report overclaims "RCE proven end-to-end".
- Existing untracked advisory focuses on DoS and contains useful structure, but the user asked for a fresh report with a specific template.

Risks:

- Overly operational reproduction text could be misused against non-lab systems.
- Understating impact would hide the real authenticated remote heap corruption risk.

## Pre-Implementation Gate

Status: ready

Problem / root-cause model:

- A streaming peer can send a very large `DIMENSION SLOT` value.
- The parent uses that value as a PRD array size and performs unchecked flexible-array allocation arithmetic.
- The allocation can wrap to a tiny physical buffer while the logical wanted size remains huge.
- The grow-path initialization loop writes beyond the allocation before publishing the array.

Evidence reviewed:

- SOW-0032 local harness results and source citations.
- Existing branch PoCs and reports.
- Streaming configuration examples in `src/streaming/stream.conf`.

Affected contracts and surfaces:

- Security report content under `security-audit/`.
- Maintainer understanding of PLUGINSD streaming risk.
- No source behavior changes in this SOW.

Existing patterns to reuse:

- Report sections requested by the user.
- SOW-0032 wording for validated vs unproven impact.
- Placeholder credential handling from the sensitive-data discipline.

Risk and blast radius:

- Documentation-only change.
- The report must avoid raw keys, UUIDs, customer identifiers, private endpoints, and local absolute paths.
- The report must not include RCE escalation steps.

Sensitive data handling plan:

- Use `${LAB_STREAMING_API_KEY}` and other placeholders instead of literal keys or UUIDs.
- Use loopback-only lab examples.
- Avoid real hostnames, non-loopback IPs, usernames, and local absolute paths.

Implementation plan:

1. Add `security-audit/DIMENSION-SLOT-FINDING.md` as the corrected report.
2. Validate Markdown content for sensitive-data patterns and overclaims.
3. Close this SOW with validation evidence.

Validation plan:

- Run `git diff --check`.
- Run `.agents/sow/audit.sh`.
- Review report for the requested sections and corrected sequence.

Artifact impact plan:

- AGENTS.md: no update expected.
- Runtime project skills: no update expected.
- Specs: no product behavior changed.
- End-user/operator docs: no published docs changed; this is a security-audit artifact.
- End-user/operator skills: no update expected.
- SOW lifecycle: complete this SOW with the report in one commit.

Open-source reference evidence:

- No external open-source references were needed; this is local Netdata source behavior and prior SOW validation.

Open decisions:

- None blocking.

## Implications And Decisions

No user decision is required to create the corrected report.

## Plan

1. Add the report.
2. Validate artifact safety and SOW consistency.
3. Commit the report and SOW lifecycle update together.

## Execution Log

### 2026-05-29

- Started SOW-0034 for corrected finding report authoring.
- Added `security-audit/DIMENSION-SLOT-FINDING.md`.
- Validated that the report contains the requested sections and the corrected step-by-step sequence.

## Validation

Acceptance criteria evidence:

- Report created at `security-audit/DIMENSION-SLOT-FINDING.md`.
- The report contains `Summary`, `Details`, `PoC`, and `Impact` sections.
- The report includes the corrected "How It Works Step By Step" sequence.
- The report includes standalone local harness reproduction and isolated loopback streaming lab reproduction with credential placeholders.
- The report states authenticated remote heap corruption and parent-process DoS as validated, and states RCE as plausible but unproven.

Tests or equivalent validation:

- `git diff --check` passed.
- `.agents/sow/audit.sh` was run before close; it reported only the expected open-SOW validation-gate warning for SOW-0034 and pre-existing non-project skill classification warnings.

Real-use evidence:

- No live Netdata parent was attacked in this SOW. The report documents lab-only reproduction procedures based on SOW-0032 validation and existing local harnesses.

Reviewer findings:

- Self-review: avoided editing existing untracked `security-audit/ADVISORY-DOS.md` and `security-audit/REPORT.md`.
- Self-review: avoided claiming proven RCE or including RCE chaining instructions.

Same-failure scan:

- Same-failure source scan was completed in SOW-0032. This report SOW did not change source code and did not require a new source scan.

Sensitive data gate:

- Durable artifacts use `${LAB_STREAMING_API_KEY}` placeholder instead of a literal streaming key or UUID.
- The report uses loopback-only examples and contains no raw credentials, bearer tokens, customer identifiers, private endpoints, non-loopback customer IPs, personal data, or local absolute paths.

Artifact maintenance gate:

- AGENTS.md: no update needed; workflow and sensitive-data requirements were already sufficient.
- Runtime project skills: no update needed; no repository workflow changed.
- Specs: no update needed; no product behavior changed.
- End-user/operator docs: no published end-user/operator docs changed; `security-audit/DIMENSION-SLOT-FINDING.md` is a security-audit artifact for maintainer review.
- End-user/operator skills: no update needed; no public skill behavior changed.
- SOW lifecycle: SOW-0034 is completed and moved to `.agents/sow/done/` with the report.

Specs update:

- No spec update was needed because the SOW only authored a report. SOW-0033 remains the place to record any slot-limit contract introduced by remediation.

Project skills update:

- No project skill update was needed.

End-user/operator docs update:

- No published docs update was needed; the report is scoped to `security-audit/`.

End-user/operator skills update:

- No public skill update was needed.

Lessons:

- For security reports, explicitly separate validated impact from plausible-but-unproven exploitability so the maintainer can trust the severity claim.

Follow-up mapping:

- Implemented: corrected report created.
- Rejected: replacing the existing overclaiming report in this SOW, to avoid overwriting user-owned untracked work.
- Tracked: source remediation remains in SOW-0033.

## Outcome

Completed. The corrected Markdown report is available at `security-audit/DIMENSION-SLOT-FINDING.md`.

## Lessons Extracted

- Security report artifacts should include lab reproduction and indicators, but must not turn simulated primitives into claimed end-to-end RCE.

## Followup

None yet.

## Regression Log

None yet.
