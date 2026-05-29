# Technical Analysis Notes

## Bug Location

- **Root cause:** `src/plugins.d/pluginsd_internals.h`, line 163–165
- **Missing guard:** No `INT32_MAX` check in `pluginsd_rrddim_put_to_slot()` (contrast: `pluginsd_rrdset_cache_put_to_slot()` at line 388 has it)
- **Overflow site:** `src/database/rrdset-pluginsd-array.h`, line 52 (`prd_array_create`)
- **Parser entry:** `src/plugins.d/pluginsd_parser.c`, line 476 (`pluginsd_dimension`)
- **Network dispatch:** `src/streaming/stream-receiver.c`, line 471 (PARSER_INIT_STREAMING)

## Arithmetic

```
sizeof(struct pluginsd_rrddim) = 24 bytes (3 pointers on x86-64)
sizeof(PRD_ARRAY header) = 16 bytes (int32_t refcount + size_t size)

Overflow condition: size * 24 > 2^64
Threshold: size > 2^64 / 24 = 0xAAAAAAAAAAAAAAAA (768,614,336,404,564,650)

Example overflow values:
  slot = 0x0AAAAAAAAAAAAAAA → slot*24 mod 2^64 = 18446744073709551600 (+16 = 0 alloc!)
  slot = 0x0AAAAAAAAAAAAAAB → slot*24 mod 2^64 = 8   (+16 = 24 bytes allocated)
  slot = 0x0AAAAAAAAAAAAAAC → slot*24 mod 2^64 = 32  (+16 = 48 bytes allocated)
  slot = 0x0AAAAAAAAAAAAAAD → slot*24 mod 2^64 = 56  (+16 = 72 bytes allocated)
  slot = 0x0AAAAAAAAAAAAAAE → slot*24 mod 2^64 = 80  (+16 = 96 bytes allocated)

In all cases: arr->size = slot (huge), actual allocation = tiny.
```

## DoS Arithmetic (non-overflow path)

```
slot = 0x40000000 (1,073,741,824)
alloc = 16 + 1,073,741,824 * 24 = 25,769,803,792 bytes (~25 GB)
Result: callocz() → libc calloc() → kernel fails → OOM kill
        OR callocz() returns NULL → fatal() → process exit
```

## Authentication Required

The streaming handshake (src/streaming/stream-receiver-connection.c:540-595) checks:
1. `stream_conf_is_key_type(rpt->key, "api")` — key must be typed as API
2. `stream_conf_api_key_is_enabled(rpt->key, false)` — key must be `enabled = yes`
3. `stream_conf_api_key_allows_client(rpt->key, w->user_auth.client_ip)` — IP in allow list

Default `allow from = *` permits any IP. The API key is a shared secret (same UUID on all children).

## Why This Wasn't Caught

The chart-slot path was hardened with `slot >= INT32_MAX` check (likely after a prior issue).
The dimension-slot path was added/refactored separately and the same guard was not applied.
The PRD_ARRAY refactor (reference-counted flexible array) is relatively recent — the old code
used `reallocz(wanted_size * sizeof(...))` which had the same unbounded multiplication.

## What the Init Loop Does

```c
for(size_t i = current_size; i < wanted_size; i++) {
    new_arr->entries[i].rda = NULL;  // writes 8 bytes
    new_arr->entries[i].rd  = NULL;  // writes 8 bytes
    new_arr->entries[i].id  = NULL;  // writes 8 bytes
}
// Each iteration writes 24 bytes at increasing offsets from the base.
// With overflow: wanted_size = ~7.7*10^17, actual buffer = 24 bytes.
// The loop immediately writes past the buffer into adjacent heap memory.
// Within microseconds, it hits an unmapped page → SIGSEGV.
```

## Confirmed Test Environment

- **Parent:** Netdata v2.10.0-289-nightly on Debian/Ubuntu (GCP e2-medium, 4GB RAM)
- **Attacker:** Python 3 on separate VPS
- **Network:** Internal GCP network, port 19999 open
- **Results:**
  - `0x40000000` → OOM kill (peak 3.4GB, signal=KILL)
  - `0x0AAAAAAAAAAAAAAB` → SIGSEGV (core dump, segfault at 0x68)

## ASan Output (from standalone PoC)

```
==365==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000058
WRITE of size 8 at 0x603000000058 thread T0
    #0 in put_to_slot poc_prd_overflow.c:85
    #1 in main poc_prd_overflow.c:100
0x603000000058 is located 0 bytes to the right of 24-byte region [0x603000000040,0x603000000058)
allocated by thread T0 here:
    #0 in calloc
    #1 in prd_array_create poc_prd_overflow.c:46
```

## RCE Assessment (Honest)

The standalone PoCs demonstrate a write primitive and function pointer hijack within their own
process. This proves the MECHANISM but NOT remote exploitation of a running Netdata binary.

Gaps for full remote RCE:
1. The init loop crashes BEFORE `prd_array_replace()` publishes the corrupted array
2. Therefore the "second DIMENSION reuses huge arr->size" scenario cannot occur in real flow
3. The uncontrolled zeroing in the init loop IS heap corruption, but it's not attacker-directed
4. Heap grooming over the streaming protocol was not demonstrated against real glibc
5. ASLR was not bypassed

Honest classification: **Authenticated remote heap corruption + guaranteed DoS**.
RCE potential exists (all ingredients are present) but is not proven end-to-end.

## Fix Verification

After applying `if(slot >= INT32_MAX) return;`:
- All overflow slot values (> 2^31) are rejected before reaching prd_array_create()
- All DoS slot values (> 2^31) are rejected
- Legitimate slot values (1 to ~millions) still work
- Matches the existing chart-slot guard for consistency
