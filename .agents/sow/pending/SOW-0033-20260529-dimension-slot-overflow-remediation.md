# SOW-0033 - Dimension Slot Overflow Remediation

## Status

Status: open

Sub-state: follow-up remediation tracked from SOW-0032 validation.

## Requirements

### Purpose

Patch the Netdata Agent PLUGINSD slot receive paths so authenticated streaming peers and local plugins cannot turn `SLOT:` values into integer-overflow allocations, out-of-bounds PRD array writes, or fatal resource-exhaustion allocations.

### User Request

Follow-up from validation of the public `security/dimension-slot-overflow-v2` branch.

### Assistant Understanding

Facts:

- SOW-0032 validated a real heap-buffer overflow in the `DIMENSION SLOT` path.
- `prd_array_create()` performs flexible-array allocation arithmetic without an overflow check.
- The chart-slot receive path already rejects negative and `INT32_MAX`-or-larger slots, but still allows very large slots below that threshold.
- Sender-side chart and dimension slots are `uint32_t`.

Inferences:

- A complete remediation should include both arithmetic overflow prevention and a resource cap.
- The resource cap should apply consistently to chart and dimension slots, or the dimension fix will leave a closely related chart-slot DoS path.

Unknowns:

- The maximum PLUGINSD slot count maintainers will accept as a hard compatibility contract.
- Whether the cap should be fixed, configurable, or tied to existing chart/dimension cardinality controls.

### Acceptance Criteria

- Reject dangerous chart and dimension slot values before allocation or indexing.
- Add checked allocation arithmetic for `PRD_ARRAY` flexible-array allocation and memory accounting.
- Preserve normal streaming slot behavior for realistic chart and dimension counts.
- Add focused regression coverage for overflow-class values, very large non-overflowing values, zero/negative/clamped values, and normal small slots.
- Validate with the narrowest relevant build/test command.

## Analysis

Sources checked:

- SOW-0032 validation evidence.
- `src/plugins.d/pluginsd_internals.h`.
- `src/database/rrdset-pluginsd-array.h`.
- `src/database/rrdset-slots.c`.
- `src/streaming/protocol/command-chart-definition.c`.
- `src/database/rrddim.h`.
- `src/database/rrdset.h`.

Current state:

- Pending remediation; no implementation in this SOW yet.

Risks:

- A hard cap that is too low can reject unusual but legitimate high-cardinality charts.
- A cap that is too high can still allow allocation-failure DoS.
- Fixing only dimension slots leaves the chart-slot resource-exhaustion shape unresolved.

## Pre-Implementation Gate

Status: needs-user-decision

Problem / root-cause model:

- Remote `SLOT:` input is parsed as a large integer and later used as allocation size or array index.
- `DIMENSION SLOT` lacks the chart-slot upper-bound guard and reaches unchecked flexible-array allocation.
- Existing chart-slot guarding prevents integer overflow at extreme values but not excessive allocation below `INT32_MAX`.

Evidence reviewed:

- SOW-0032 validation record and local non-network harness results.

Affected contracts and surfaces:

- PLUGINSD parser receive behavior for `CHART`, `DIMENSION`, `BEGIN`, `SET`, `BEGIN2`, `SET2`, and replication commands.
- Streaming parent compatibility with child senders using `STREAM_CAP_SLOTS`.
- Slot memory accounting and PRD cleanup paths.

Existing patterns to reuse:

- `pluginsd_rrdset_cache_put_to_slot()` early rejection style.
- Local checked arithmetic patterns using `__builtin_mul_overflow()` and `SIZE_MAX` comparisons.
- Log-limited error reporting for malformed or unsafe PLUGINSD input.

Risk and blast radius:

- Security improvement is high; compatibility risk is limited to extreme slot cardinalities.
- A single shared cap affects both chart and dimension slots and should be documented as a protocol/resource limit if accepted.

Sensitive data handling plan:

- No secrets, UUIDs, customer identifiers, private endpoints, or local absolute paths will be written.
- Tests will use synthetic slot classes, not real streaming keys or host data.

Implementation plan:

1. Decide the maximum accepted slot count and whether it is shared across chart and dimension slots.
2. Add a common slot validation helper or local guards in PLUGINSD internals.
3. Add checked size computation for `PRD_ARRAY`.
4. Add regression tests or a focused harness.
5. Run focused validation.

Validation plan:

- Compile the affected C path or targeted unit/harness.
- Re-run overflow-class and resource-exhaustion slot tests.
- Search all slot parser consumers and PRD allocation callers after patch.

Artifact impact plan:

- AGENTS.md: likely no change.
- Runtime project skills: update only if the chosen cap becomes workflow-relevant guidance.
- Specs: update or add a PLUGINSD slot-limit spec if a new public protocol/resource contract is introduced.
- End-user/operator docs: update only if operators need to know/configure the cap.
- End-user/operator skills: likely no change.
- SOW lifecycle: this pending SOW tracks the remediation deferred by SOW-0032.

Open-source reference evidence:

- No external OSS reference is needed before the slot-limit decision; this is Netdata-specific protocol behavior.

Open decisions:

1. Choose the accepted maximum slot count and whether it is fixed or configurable.
2. Choose whether chart-slot resource exhaustion is fixed in the same patch as dimension-slot overflow. Recommended: yes, same patch.

## Implications And Decisions

Pending.

## Plan

Pending user/maintainer decision on the slot cap.

## Execution Log

None yet.

## Validation

Pending.

## Outcome

Pending.

## Lessons Extracted

Pending.

## Followup

None yet.

## Regression Log

None yet.
