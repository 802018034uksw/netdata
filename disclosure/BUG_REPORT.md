# Bug Report: Integer Overflow in Streaming DIMENSION SLOT → Remote Crash (DoS / Heap Buffer Overflow)

## Pre-submission checklist

- [x] Verified this issue is not already reported on GitHub
- [x] Netdata Agent is up to date (tested on latest nightly v2.10.0-289)

---

## Bug description

An authenticated streaming peer (child agent) can remotely crash the Netdata parent process by sending a single crafted `DIMENSION SLOT:<value>` command over the streaming protocol (TCP port 19999).

The function `pluginsd_parse_rrd_slot()` in `src/plugins.d/pluginsd_internals.h` parses the SLOT value as a full 64-bit integer with **no upper-bound check** (only negatives are clamped). This value is used directly as the allocation size in `prd_array_create()`.

This is **1 bug with 2 different crash outcomes** depending on the slot value:

| Slot Value | What Happens | Crash Type |
|-----------|--------------|------------|
| `0x40000000` (1 billion) | Requests ~25GB allocation → kernel OOM killer fires | `signal=KILL` (oom-kill) |
| `0x0AAAAAAAAAAAAAAB` | `slot * 24` overflows `size_t` → 24-byte alloc, but code thinks it has ~7.7×10^17 entries → init loop writes OOB | `signal=SEGV` (core-dump) |

Both are triggered by the **same missing bounds check** and require only a valid streaming API key.

**Note:** The chart-slot path (`pluginsd_rrdset_cache_put_to_slot()` at line 388) correctly guards `slot >= INT32_MAX`. The dimension-slot path has no equivalent guard.

**Vulnerable code (`src/plugins.d/pluginsd_internals.h:163`):**
```c
if(slot >= 1) {
    st->pluginsd.dims_with_slots = true;
    wanted_size = (size_t)slot;  // No upper bound, attacker-controlled
}
```

**The allocation that overflows (`src/database/rrdset-pluginsd-array.h:52`):**
```c
PRD_ARRAY *arr = callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
//                                              size * 24 overflows size_t for large values
arr->size = size;  // Stores huge logical size
```

---

## Expected behavior

The parent should reject DIMENSION SLOT values that exceed a reasonable upper bound (e.g., `INT32_MAX`, matching the existing chart-slot guard) and continue operating normally. The streaming session should be terminated or the invalid dimension ignored without any crash, memory corruption, or resource exhaustion.

---

## Steps to reproduce

### Prerequisites

- Netdata parent with streaming enabled
- A valid streaming API key in `/etc/netdata/stream.conf`:

```ini
[11111111-2222-3333-4444-555555555555]
    enabled = yes
    default history = 3600
    default memory mode = ram
    health enabled by default = auto
    allow from = *
```

- Python 3 on a separate machine (attacker)

### Steps

1. Ensure Netdata parent is running: `systemctl start netdata`

2. Verify it is listening: `ss -tlnp | grep 19999`

3. From the attacker machine, save the exploit script (see `exploit.py` attached)

4. Run the exploit (DoS variant, guaranteed kill):

```bash
python3 exploit.py <PARENT_IP> 19999 11111111-2222-3333-4444-555555555555 0x40000000
```

5. Check parent status:

```bash
systemctl status netdata
# Result: Active: failed (Result: oom-kill), signal=KILL
```

6. Restart and test heap overflow variant:

```bash
systemctl start netdata
# From attacker:
python3 exploit.py <PARENT_IP> 19999 11111111-2222-3333-4444-555555555555 0x0AAAAAAAAAAAAAAB
```

7. Check parent again:

```bash
systemctl status netdata
# Result: Active: failed (Result: core-dump), signal=SEGV

dmesg | tail -5
# Shows: netdata[PID]: segfault at 68 ... error 6 in netdata[...]
```

---

## Installation method

Standard kickstart installer (latest nightly):

```bash
curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh
bash /tmp/netdata-kickstart.sh --dont-wait
```

---

## System info

```
Linux netdata-parent 6.8.0-60-generic #62-Ubuntu SMP x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.2 LTS"
VERSION_ID="24.04"
Platform: GCP e2-medium (2 vCPU, 4GB RAM)
```

---

## Netdata build info

```
netdata v2.10.0-289-nightly

Configure options: standard kickstart defaults
Compiled with: GCC

Features:
 streaming:          YES
 pluginsd:           YES

sizeof(size_t):     8 (64-bit)
sizeof(ssize_t):    8
sizeof(void*):      8
```

---

## Additional info

### Confirmed test results (2026-05-29)

**Test 1 — OOM Kill (slot `0x40000000`):**
```
netdata.service
     Active: deactivating (final-sigterm) (Result: oom-kill)
    Process: 8101 ExecStart=/usr/sbin/netdata -P /run/netdata/netdata.pid -D (code=killed, signal=KILL)
     Memory: 138.7M (peak: 3.4G)
```

**Test 2 — Heap Overflow (slot `0x0AAAAAAAAAAAAAAB`):**
```
netdata.service
     Active: deactivating (stop-sigterm) (Result: core-dump)
    Process: 8904 ExecStart=/usr/sbin/netdata -P /run/netdata/netdata.pid -D (code=dumped, signal=SEGV)

dmesg: WEB[3][9289]: segfault at 68 ip 00006357f4f0fcc1 sp 0000798602b47a40 error 6 in netdata[...]
```

### Why this is 1 bug, 2 outcomes

```
                     pluginsd_parse_rrd_slot()
                              |
                    slot (no upper bound)  <-- THE BUG
                              |
              +---------------+---------------+
              |                               |
     slot = 0x40000000               slot = 0x0AAAAAAAAAAAAAAB
     (large, no overflow)             (causes size_t overflow)
              |                               |
     callocz(25,769,803,776)         callocz(24) <-- tiny!
              |                               |
     kernel OOM -> SIGKILL           init loop writes OOB -> SIGSEGV
              |                               |
         DEAD (oom-kill)                 DEAD (core-dump)
```

### Impact

- **Type:** Authenticated Remote Denial of Service + Heap Buffer Overflow (CWE-190, CWE-122)
- **Who is impacted:** Any Netdata deployment using parent-child streaming (the recommended production architecture). The streaming API key is a shared secret distributed to all children. Compromise of any single child node exposes the key.
- **Severity:** High. Single-packet remote kill of the central monitoring parent. Repeatable on every restart. Takes down all dashboards, alerts, and notifications across the entire monitored fleet.
- **Precondition:** Valid streaming API key + network access to port 19999
- **Blast radius:** When the parent dies, all monitoring goes blind. Attacker can loop the exploit to maintain permanent blackout, covering further intrusion.

### Suggested fix

Mirror the existing chart-slot guard in the dimension-slot path:

```c
// In pluginsd_rrddim_put_to_slot(), add before wanted_size = (size_t)slot:
if(unlikely(slot >= INT32_MAX)) {
    netdata_log_error("PLUGINSD: dimension slot %zd exceeds maximum, ignoring", slot);
    return;
}
```

### Source code references

| File | Line | Function | Issue |
|------|------|----------|-------|
| `src/plugins.d/pluginsd_internals.h` | 372 | `pluginsd_parse_rrd_slot()` | Full 64-bit parse, no upper bound |
| `src/plugins.d/pluginsd_internals.h` | 163 | `pluginsd_rrddim_put_to_slot()` | `wanted_size = (size_t)slot` unchecked |
| `src/database/rrdset-pluginsd-array.h` | 52 | `prd_array_create()` | `size * 24` overflows size_t |
| `src/plugins.d/pluginsd_internals.h` | 388 | `pluginsd_rrdset_cache_put_to_slot()` | Has `slot >= INT32_MAX` guard (the fix that is MISSING from the dimension path) |
