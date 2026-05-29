# Netdata Agent Security Audit - Working Notes

Version: v2.10.0-289-nightly (commit 4b4599484)

## Goal
Find NEW (novel) MEDIUM-CRITICAL vulns. Manually validated, reproducible, evidence-based.

## Trust model (confirmed)
- Web server port 19999: dashboard ACL open by default. ACLs from socket, not headers.
- Cloud privilege headers (X-Netdata-Permissions/Role/Account-Id/Auth) gated by
  WEB_CLIENT_FLAG_CONN_CLOUD && acl&HTTP_ACL_ACLK. These are ONLY set by aclk_query.c
  for connections arriving via the authenticated MQTT cloud link. NOT spoofable over TCP. OK.
- client_ip comes from accept_socket(), not headers. OK.
- Bearer tokens: signed with XXH3 over host_uuid; loaded from varlib. OK.
- MCP /mcp /sse require http_can_access_dashboard only, but function execution uses
  w->user_auth.access (anonymous by default) -> rrd_function_run enforces per-function access. OK.
- ndsudo setuid helper: validates argv chars (no shell metachar), execve clean env. OK
  (argument-injection possible but constrained; likely known design).

## Areas reviewed (no confirmed novel bug yet)
- HTTP request parsing (web_client.c) - bounded
- url_decode_r / multibyte utf8 - bounded
- http_header.c header parsing - bounded strncpyz
- WebSocket frame parser + decompression - frame 20MB cap; in_buffer max 20MB. bounded
- stream compression/decompression (lz4/gzip) - bounded, LZ4_decompress_safe
- pluginsd slot indexing - bounds checked
- str2ull/ndd encoded decoders - stop at terminator
- bearer get token / bearer protection auth flow - careful UUID checks
- circular_buffer.c - reviewed

## Leads / partial
- api_v1_config: `path` param placed in `CONFIG tree '%s' '%s'` without quote-escaping;
  quoted_strings_splitter treats ' specially -> argument injection into config function.
  Impact bounded (config tree navigation, not shell). Requires authorized access. LOW/MED.
  Need to confirm what config function does with injected args.

## CONFIRMED FINDING #1 (CRITICAL): Integer overflow -> heap overflow via DIMENSION SLOT
- File: src/database/rrdset-pluginsd-array.h:51 prd_array_create()
  `callocz(1, sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim))`
  size (=slot) attacker-controlled 64-bit; *24 overflows size_t.
- Slot parsed unbounded: src/plugins.d/pluginsd_internals.h:372 pluginsd_parse_rrd_slot()
  str2ull_encoded full 64-bit, only negatives clamped.
- put_to_slot: src/plugins.d/pluginsd_internals.h:159; wanted_size=(size_t)slot;
  init loop writes 24B per index up to wanted_size -> OOB heap write.
- Reachable: DIMENSION keyword has PARSER_INIT_STREAMING (gperf-config.txt:82),
  receiver parser repertoire=PARSER_INIT_STREAMING (stream-receiver.c:471).
  parser_execute dispatches DIMENSION->pluginsd_dimension unconditionally.
  No capability gate on SLOT: token parsing.
- struct pluginsd_rrddim = 3 ptrs = 24 bytes. sizeof(PRD_ARRAY)=16.
- PoC slot 0xaaaaaaaaaaaaaab -> calloc 24 bytes, arr->size=7.6e17 -> ASan heap-buffer-overflow CONFIRMED.
- Also DoS variant: slot 0x40000000 -> ~25GB alloc -> callocz fatal() -> agent exit.
- Compare: chart-slot path pluginsd_rrdset_cache_put_to_slot() DOES guard slot<INT32_MAX. dim path does NOT.
- Precondition: parent with streaming [API_KEY] enabled (standard parent deployment),
  attacker = malicious/compromised child with valid api key from allowed IP.
- Pre-existing (PR #21628 mar 2026 refactor kept the unbounded slot; old code reallocz same).
- PoC: .local/audits/security/poc_prd_overflow.c (ASan confirmed).
