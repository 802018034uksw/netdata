# SOW-0032 - Dimension Slot Overflow Validation

## Status

Status: completed

Sub-state: validation complete; remediation tracked separately in SOW-0033.

## Requirements

### Purpose

Validate the reported Netdata Agent `DIMENSION SLOT` vulnerability from code evidence, assess exploitability in a controlled way, and identify a remediation path without producing a weaponized RCE chain.

### User Request

The user asked to fetch the public fork branch `security/dimension-slot-overflow-v2`, validate the vulnerability, and help with RCE research.

### Assistant Understanding

Facts:

- The current checkout tracks the same public fork and is on `security/dimension-slot-overflow`.
- The requested branch exists as `origin/security/dimension-slot-overflow-v2`.
- The v2 branch adds `security-audit/REPORT.md`, `security-audit/poc_rce_chain.c`, and `security-audit/test_slot_overflow_regression.c` on top of the current branch.
- The affected local code path is the PLUGINSD metric ingestion path for `DIMENSION` commands.

Inferences:

- A malicious or compromised streaming child with valid streaming credentials is inside the parent/child trust boundary but still a remote peer. Parser and allocation paths must treat it as untrusted input.
- Safe validation should prove memory-corruption impact and reject/limit conditions locally, not provide operational RCE instructions.

Unknowns:

- The exact maximum slot count maintainers want as a compatibility/resource contract. This blocks source remediation, not vulnerability validation.

### Acceptance Criteria

- Fetch and identify the requested branch and delta.
- Validate or refute the root-cause model using source citations.
- Validate exploitability impact using non-weaponized local evidence.
- Identify affected contracts, blast radius, and a defensible remediation path.
- Avoid writing secrets, private endpoints, customer identifiers, or weaponized exploit instructions to durable artifacts.

## Analysis

Sources checked:

- `.agents/sow/current/` and `.agents/sow/pending/` for overlap; no existing SOW covers this security issue.
- `.agents/sow/specs/sensitive-data-discipline.md`.
- `.agents/skills/project-writing-collectors/SKILL.md`, because PLUGINSD is the collector metric protocol path.
- `802018034uksw/netdata @ b4b940db8` branch metadata and `security-audit/REPORT.md`.
- `src/plugins.d/pluginsd_internals.h`.
- `src/database/rrdset-pluginsd-array.h`.
- `src/plugins.d/pluginsd_parser.c`.
- `src/database/rrdset-slots.c`.

Current state:

- `pluginsd_parse_rrd_slot()` parses a `SLOT:` value into `ssize_t` with only negative-value clamping.
- `pluginsd_rrddim_put_to_slot()` treats `slot >= 1` as the wanted dimension-cache size and calls `prd_array_create(wanted_size)`.
- `prd_array_create()` computes `sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim)` without an overflow guard.
- The chart-slot path has an existing guard rejecting invalid or very large chart slots before allocation.

Risks:

- Memory corruption in the streaming receive path can crash a parent or corrupt adjacent heap objects.
- A large non-overflowing slot can force excessive allocation and terminate the parent through allocation failure.
- A too-low slot cap could break legitimate high-cardinality charts; a too-high cap leaves resource exhaustion risk.

## Pre-Implementation Gate

Status: completed for validation; source remediation is split to SOW-0033.

Problem / root-cause model:

- The root issue is unchecked conversion of remote PLUGINSD `DIMENSION SLOT` input into a flexible-array allocation count.
- The untrusted slot is parsed in `src/plugins.d/pluginsd_internals.h:372`, passed through `src/plugins.d/pluginsd_parser.c:572`, used as `wanted_size` in `src/plugins.d/pluginsd_internals.h:159`, and allocated in `src/database/rrdset-pluginsd-array.h:51`.
- Multiplication overflow makes the physical allocation smaller than the logical `arr->size`. Subsequent initialization or slot writes can walk past the allocated object.
- Non-overflowing but very large slot values can request excessive memory and terminate the process because Netdata allocation helpers fatal on allocation failure.

Evidence reviewed:

- Public branch diff from `origin/security/dimension-slot-overflow-v2`.
- Local source lines for `pluginsd_parse_rrd_slot()`, `pluginsd_rrddim_put_to_slot()`, `prd_array_create()`, `pluginsd_dimension()`, chart-slot guarding, and PRD cleanup users.
- Existing project guidance for collector hot-path and cardinality discipline.
- Sensitive-data spec for durable artifact redaction.

Affected contracts and surfaces:

- PLUGINSD `DIMENSION SLOT` parsing for local plugins and streaming children.
- Streaming parent receive path on the network listener when a child is authenticated and allowed.
- RRDSET dimension cache allocation, cleanup, and memory accounting.
- Potential health, storage, ML, streaming, Cloud fanout, and dashboard behavior if dimension slot semantics are changed.

Existing patterns to reuse:

- The chart-slot guard in `pluginsd_rrdset_cache_put_to_slot()` rejects invalid and very large slots before resizing.
- Central allocation overflow checks should live at the allocation helper when the helper owns flexible-array size computation.
- Collector cardinality should be bounded with explicit operator-safe limits rather than unbounded remote input.

Risk and blast radius:

- Security risk is high for parent deployments that accept streaming children with shared keys.
- Compatibility risk depends on the selected maximum slot. Existing normal collectors generally use compact slots or no explicit dimension slots; pathological or malicious cardinality must not be supported.
- Performance risk is positive if extreme slots are rejected early; logging must avoid flood behavior.
- Memory-accounting risk exists if `rrd_slot_memory_added()` or removal sees wrapped sizes; allocation-size computation should be shared or guarded.

Sensitive data handling plan:

- Durable SOW content will cite public branch names, commit short hashes, repo-relative file paths, and sanitized impact summaries only.
- No raw streaming API keys, bearer tokens, UUIDs, customer hostnames, customer IPs, private endpoints, or local absolute paths will be written.
- RCE proof details will be summarized as controlled memory-corruption evidence, not copied as operational exploit instructions.
- Code comments, if added, will explain bounds and overflow safety without embedding payload strings or real environment data.

Implementation plan:

1. Complete validation by checking every parser/slot consumer and PRD allocation user for same-failure patterns.
2. If patching is in scope, add an input guard for dimension slots and an allocation overflow guard in `prd_array_create()`, reusing local style.
3. Add focused tests or a small local validation harness that asserts dangerous slot values are rejected without running RCE behavior.

Validation plan:

- Run branch-provided non-network regression logic if safe, or reproduce equivalent arithmetic checks locally.
- Compile any changed C code or focused harness with the repo's narrowest available command.
- Search for other `pluginsd_parse_rrd_slot()` consumers and `prd_array_create()` callers.
- Run same-failure grep for unchecked flexible-array allocation size arithmetic in nearby code if patching.

Artifact impact plan:

- AGENTS.md: no expected change; security workflow rules are already present.
- Runtime project skills: likely no change; existing collector guidance already covers cardinality and remote parser discipline.
- Specs: likely no change unless a new public PLUGINSD maximum-slot contract is introduced.
- End-user/operator docs: likely no change for a validation-only task; a shipped remediation may need release notes/security advisory, handled outside this SOW unless requested.
- End-user/operator skills: no expected change.
- SOW lifecycle: this SOW tracks validation and any directly requested remediation; no merge with existing topology SOWs is needed.

Open-source reference evidence:

- Public fork evidence is from `802018034uksw/netdata @ b4b940db8`; checked files are under `security-audit/`.
- No external non-Netdata open-source projects are needed because the defect is in Netdata-specific PLUGINSD parsing and allocation logic.

Open decisions:

- Source patching requires a maintained slot cap decision. Tracked in SOW-0033.

## Implications And Decisions

No user decisions are blocking validation. I will not provide a weaponized RCE chain; validation will focus on root-cause evidence, controlled memory-safety proof, and remediation.

## Plan

1. Inspect all slot parser consumers and PRD array callers. Completed.
2. Validate arithmetic overflow and resource exhaustion conditions without running network or RCE payloads. Completed.
3. Produce a concise validation result and recommend a fix strategy. Completed.

## Execution Log

### 2026-05-29

- Fetched `origin/security/dimension-slot-overflow-v2`.
- Confirmed the branch adds report and PoC material only, not a source fix.
- Confirmed the dimension-slot path lacks the chart-slot path's upper-bound guard.
- Ran the v2 branch arithmetic regression harness locally; it confirmed overflow-class slots and large resource-exhaustion-class slots are not safely handled by the unpatched dimension path.
- Ran a local ASan harness for the PRD allocation/initialization path; it reported heap-buffer-overflow immediately after a tiny wrapped allocation.
- Ran a local non-ASan heap-corruption harness; it showed an adjacent heap object being zeroed before the process fault.
- Reviewed the v2 RCE-chain PoC and found it simulates an already-installed huge logical array. In real code, `prd_array_replace()` happens only after the initialization loop, so that PoC does not prove an end-to-end RCE chain.
- Created pending remediation SOW-0033 for the fix and slot-cap decision.

## Validation

Acceptance criteria evidence:

- Branch fetched: `origin/security/dimension-slot-overflow-v2` at short commit `b4b940db8`.
- Root cause validated in source:
  - `src/plugins.d/pluginsd_internals.h:372` parses `SLOT:` with only negative clamping.
  - `src/plugins.d/pluginsd_parser.c:572` calls `pluginsd_rrddim_put_to_slot()` for `DIMENSION`.
  - `src/plugins.d/pluginsd_internals.h:159` uses `slot` as `wanted_size`.
  - `src/database/rrdset-pluginsd-array.h:51` allocates a flexible array with unchecked `size * sizeof(struct pluginsd_rrddim)`.
- Current upstream `master` was fetched at short commit `4b4599484`; the affected code is unchanged there.
- Exploitability classification:
  - Confirmed: remote authenticated streaming child can trigger heap-buffer-overflow or allocation-failure DoS through `DIMENSION SLOT`.
  - Confirmed: local modeled heap corruption can smash adjacent heap objects before crash.
  - Not proven by the v2 branch: reliable end-to-end RCE. The branch's RCE-chain PoC skips the real initialization-loop/publication ordering.

Tests or equivalent validation:

- Non-network arithmetic regression harness from the v2 branch compiled and passed with 12 cases, confirming overflow-class and large non-overflowing slot classes.
- ASan PRD overflow harness compiled and exited with AddressSanitizer `heap-buffer-overflow`, writing immediately after the wrapped allocation.
- Non-ASan heap corruption harness compiled and exited successfully after catching the fault and observing adjacent object corruption.
- The network PoC and RCE-chain PoC were not run.

Real-use evidence:

- No live Netdata parent was attacked. Real-use validation was intentionally limited because it would require streaming credentials and would crash or corrupt a running parent.
- The local harnesses mirror the affected parser/allocation arithmetic and initialization loop closely enough to validate memory-safety impact without using secrets or a live target.

Reviewer findings:

- Self-review finding: the v2 branch report overstates RCE as "proven end-to-end." The included RCE-chain source itself documents that it directly simulates a post-overflow huge logical array state, which the real `DIMENSION` grow path does not publish before the crashing initialization loop.
- Self-review finding: a remediation that only adds the chart-path `INT32_MAX` style guard to dimensions would fix overflow-class values but would not address large non-overflowing resource-exhaustion values.

Same-failure scan:

- `pluginsd_parse_rrd_slot()` consumers were reviewed. The unsafe allocation growth is isolated to `DIMENSION` through `pluginsd_rrddim_put_to_slot()`; `BEGIN`, `SET`, v2, and replay paths index existing caches and are dangerous after a corrupted PRD array exists, but do not create the overflowed array themselves.
- `prd_array_create()` callers were reviewed. Production growth is from `pluginsd_rrddim_put_to_slot()`; remaining callers are local PRD lifecycle stress-test paths using small bounded sizes.
- A targeted grep for unchecked flexible-array allocation arithmetic found other generic patterns, but no identical untrusted PLUGINSD slot-to-PRD allocation path. Broader allocation-hardening is outside this validation SOW.
- Chart-slot receive path avoids integer overflow with `slot >= INT32_MAX` but still has a related very-large-slot resource-exhaustion shape; SOW-0033 tracks fixing both chart and dimension slot caps together.

Sensitive data gate:

- Durable artifacts contain no raw streaming API keys, bearer tokens, customer identifiers, private endpoints, non-loopback customer IPs, UUIDs, or local absolute paths.
- Evidence uses public branch names, short public commit hashes, repo-relative paths, and sanitized impact summaries.
- RCE payload instructions and live-target details are not included.

Artifact maintenance gate:

- AGENTS.md: no update needed; existing SOW/security/root-cause rules covered the workflow.
- Runtime project skills: no update needed for validation-only work; `project-writing-collectors` already covers collector cardinality and parser discipline.
- Specs: no behavior changed. A PLUGINSD slot-limit spec should be added in SOW-0033 if remediation introduces a hard public cap.
- End-user/operator docs: no update in validation-only work. A security advisory or release note belongs with remediation/disclosure, not this validation record.
- End-user/operator skills: no update; no public/operator skill workflow changed.
- SOW lifecycle: validation SOW completed; remediation deferred to pending SOW-0033.

Specs update:

- No spec update was needed because this SOW did not change product behavior. SOW-0033 will update specs if it creates a slot-limit contract.

Project skills update:

- No project skill update was needed; the existing collector skill already records cardinality and parser quality expectations.

End-user/operator docs update:

- No end-user/operator docs update was needed for validation-only work. The issue is not safe to document as operational guidance before remediation/disclosure.

End-user/operator skills update:

- No end-user/operator skill update was needed; no public skill behavior or commands changed.

Lessons:

- RCE proof-of-concept code must be checked against real control flow. A standalone simulated primitive can prove memory corruption potential, but not end-to-end RCE when it bypasses ordering that exists in production code.

Follow-up mapping:

- Implemented: branch fetch, root-cause validation, non-weaponized exploitability validation, same-failure search.
- Rejected: running the network PoC or RCE chain locally; not needed for validation and would be unsafe/noisy.
- Tracked: source remediation and slot-cap decision in `.agents/sow/pending/SOW-0033-20260529-dimension-slot-overflow-remediation.md`.

## Outcome

Validation complete:

- The vulnerability is valid as authenticated remote heap memory corruption and allocation-failure DoS in the streaming `DIMENSION SLOT` path.
- Current evidence does not prove reliable end-to-end RCE. The branch's RCE PoCs demonstrate simulated primitives, while the real grow path hits the initialization loop before publishing the huge logical array needed by the second-stage write.
- Recommended remediation is to add both a slot validation cap and checked PRD allocation arithmetic, with the cap decision tracked in SOW-0033.

## Lessons Extracted

- Treat PoCs that skip production ordering as primitive demonstrations, not end-to-end exploit proof.

## Followup

None yet.

## Regression Log

None yet.
