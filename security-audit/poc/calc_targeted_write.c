// calc_targeted_write.c
//
// Shows the relationship between the overflow slot value, the resulting
// calloc size, and the offset at which &entries[slot-1] lands relative
// to the undersized chunk.
//
// For each slot near floor(2^64/24):
//   alloc_bytes = sizeof(PRD_ARRAY) + slot*24   (mod 2^64, wraps to small)
//   entry_off   = sizeof(PRD_ARRAY) + (slot-1)*24  (mod 2^64)
//
// The entry_off column shows where the entries[slot-1] write lands relative
// to the start of the chunk. Small values mean the write hits nearby memory.
//
// Build: gcc -O0 -o calc_targeted_write calc_targeted_write.c
// Run  : ./calc_targeted_write
//
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

int main(void) {
    const uint64_t E = 24;   // sizeof(struct pluginsd_rrddim) on 64-bit
    const uint64_t H = 16;   // sizeof(PRD_ARRAY) on 64-bit

    unsigned __int128 two64 = (unsigned __int128)1 << 64;
    uint64_t base = (uint64_t)(two64 / E);  // floor(2^64 / 24)

    printf("%-20s  %12s  %22s  %22s\n",
           "slot (hex)", "alloc_bytes", "entry_off_from_arr", "entry_off_from_entries");
    printf("%-20s  %12s  %22s  %22s\n",
           "--------------------", "------------", "----------------------", "----------------------");

    for (int64_t d = -2; d <= 6; d++) {
        uint64_t slot = (uint64_t)((int64_t)base + d);
        if ((int64_t)slot < 1) continue;

        // alloc_bytes: what callocz(1, H + slot*E) actually requests (wraps mod 2^64)
        uint64_t alloc = H + slot * E;

        // where &entries[slot-1] lands relative to arr (mod 2^64)
        uint64_t entry_off_arr     = H + (slot - 1) * E;
        uint64_t entry_off_entries = (slot - 1) * E;

        printf("0x%016llx  %12llu  %+22lld  %+22lld\n",
               (unsigned long long)slot,
               (unsigned long long)alloc,
               (long long)(int64_t)entry_off_arr,
               (long long)(int64_t)entry_off_entries);
    }

    printf("\n");
    printf("Notes:\n");
    printf("  alloc_bytes   : real bytes requested from calloc (wraps for overflow slots)\n");
    printf("  entry_off_arr : &entries[slot-1] - arr  (mod 2^64)\n");
    printf("                  small positive = write lands just past the chunk\n");
    printf("                  small negative = write lands just before the chunk\n");
    printf("  The write at entries[slot-1] stores prd->rda, prd->rd, prd->id\n");
    printf("  (real heap pointers + attacker-controlled id string pointer).\n");
    return 0;
}
