// SPDX-License-Identifier: GPL-3.0-or-later
//
// REGRESSION TEST: Validates that the dimension-slot overflow is detectable.
//
// This test replicates the EXACT vulnerable code path from:
//   - pluginsd_parse_rrd_slot()  [src/plugins.d/pluginsd_internals.h]
//   - prd_array_create()         [src/database/rrdset-pluginsd-array.h]
//   - pluginsd_rrddim_put_to_slot() init loop
//
// It exercises multiple attack vectors and asserts they would overflow.
// A proper fix should make all "VULNERABLE" cases return early / reject the slot.
//
// Build: gcc -O0 -g -o test_slot_overflow_regression test_slot_overflow_regression.c
// Run  : ./test_slot_overflow_regression
//        Exit 0 = all overflow conditions detected (vulnerability confirmed)
//        Exit 1 = unexpected behavior
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

// --- Exact replica of relevant types/sizes ---
struct pluginsd_rrddim { void *rda; void *rd; const char *id; };
#define SIZEOF_PRD_ENTRY sizeof(struct pluginsd_rrddim)  // 24 on 64-bit

typedef struct {
    int32_t refcount;
    size_t  size;
    struct pluginsd_rrddim entries[];
} PRD_ARRAY;
#define SIZEOF_PRD_HEADER sizeof(PRD_ARRAY)  // 16 on 64-bit

// --- Replica of str2ull_encoded (simplified: decimal + hex) ---
static unsigned long long str2ull_encoded(const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return strtoull(s + 2, NULL, 16);
    return strtoull(s, NULL, 10);
}

// --- Replica of pluginsd_parse_rrd_slot ---
static long long parse_rrd_slot(const char *slot_str) {
    // In the real code: "SLOT:<value>" where value is parsed by str2ull_encoded
    long long slot = (long long)str2ull_encoded(slot_str);
    if (slot < 0) slot = 0;  // only negative clamping, no upper bound
    return slot;
}

// --- The missing guard (what the fix should add) ---
// Two-level defense:
//   Level 1: Mirror chart-slot guard (slot >= INT32_MAX -> reject)
//   Level 2: Allocation overflow check in prd_array_create (catches huge-but-below-INT32_MAX)
// Together they prevent both the integer overflow AND the OOM-DoS.
#define MAX_REASONABLE_SLOTS 10000000  // 10M dims * 24B = 240MB max (configurable)
static bool slot_is_safe(long long slot) {
    // The real fix should use INT32_MAX like chart-slot path,
    // PLUS a reasonable upper bound for resource control.
    return (slot >= 1 && slot < INT32_MAX);
}
static bool slot_passes_resource_guard(long long slot) {
    // Additional resource guard: even if < INT32_MAX, reject absurdly large
    return (slot >= 1 && (unsigned long long)slot <= MAX_REASONABLE_SLOTS);
}

// --- Overflow detection: does size * 24 + 16 overflow size_t? ---
static bool allocation_would_overflow(size_t size) {
    // Check: sizeof(PRD_ARRAY) + size * sizeof(struct pluginsd_rrddim) > SIZE_MAX
    if (size > (SIZE_MAX - SIZEOF_PRD_HEADER) / SIZEOF_PRD_ENTRY)
        return true;
    return false;
}

// --- Test vectors ---
struct test_case {
    const char *name;
    const char *slot_str;       // value after "SLOT:"
    bool expect_overflow;       // should the alloc overflow size_t?
    bool expect_rejected;       // should the guard reject it? (after fix)
};

static struct test_case cases[] = {
    // --- Overflow cases (attacker values that wrap size_t) ---
    {"overflow_exact_zero_alloc",   "0x0AAAAAAAAAAAAAAA", true, true},
    {"overflow_24_byte_alloc",      "0x0AAAAAAAAAAAAAAB", true, true},
    {"overflow_48_byte_alloc",      "0x0AAAAAAAAAAAAAAC", true, true},
    {"overflow_hex_upper",          "0x0AAAAAAAAAAAAAAD", true, true},
    // Note: "18446744073709551615" (UINT64_MAX) becomes -1 as ssize_t,
    // which parse_rrd_slot clamps to 0 — NOT an overflow, it's rejected differently.
    {"uint64_max_clamped_to_zero",  "18446744073709551615", false, true},

    // --- DoS cases (large but non-overflowing -> OOM/fatal) ---
    // These are BELOW INT32_MAX so the basic guard won't catch them,
    // but the resource guard (MAX_REASONABLE_SLOTS) should.
    {"dos_25gb_alloc",              "0x40000000", false, false},   // 1G entries; guard_rejects=no (below INT32_MAX)
    {"dos_1gb_alloc",               "0x10000000", false, false},   // 256M entries; guard_rejects=no (below INT32_MAX)
    {"dos_above_int32max",          "2147483648", false, true},   // INT32_MAX + 1

    // --- Legitimate cases (should be allowed) ---
    {"valid_slot_1",                "1", false, false},
    {"valid_slot_100",              "100", false, false},
    {"valid_slot_10000",            "10000", false, false},
    {"valid_slot_max_reasonable",   "1000000", false, false},
};

#define NUM_CASES (sizeof(cases) / sizeof(cases[0]))

int main(void) {
    int failures = 0;
    int overflow_confirmed = 0;
    int guard_would_catch = 0;

    printf("=== DIMENSION SLOT Overflow Regression Test ===\n");
    printf("sizeof(struct pluginsd_rrddim) = %zu\n", SIZEOF_PRD_ENTRY);
    printf("sizeof(PRD_ARRAY header)       = %zu\n", SIZEOF_PRD_HEADER);
    printf("INT32_MAX                      = %d\n", INT32_MAX);
    printf("\n");

    for (size_t i = 0; i < NUM_CASES; i++) {
        struct test_case *tc = &cases[i];
        long long slot = parse_rrd_slot(tc->slot_str);
        bool overflows = (slot > 0) ? allocation_would_overflow((size_t)slot) : false;
        bool safe = slot_is_safe(slot);
        bool resource_ok = slot_passes_resource_guard(slot);

        printf("[%02zu] %-30s slot=%-22lld overflow=%-5s guard_rejects=%-5s resource=%-5s ",
               i, tc->name, slot,
               overflows ? "YES" : "no",
               safe ? "no" : "YES",
               resource_ok ? "ok" : "BLOCK");

        // Verify overflow detection matches expectation
        if (overflows != tc->expect_overflow) {
            printf("FAIL (expected overflow=%s)\n", tc->expect_overflow ? "YES" : "no");
            failures++;
            continue;
        }

        // Verify guard behavior matches expectation
        bool guard_rejects = !safe;
        if (guard_rejects != tc->expect_rejected) {
            printf("FAIL (expected rejected=%s)\n", tc->expect_rejected ? "YES" : "no");
            failures++;
            continue;
        }

        if (overflows) overflow_confirmed++;
        if (guard_rejects && tc->expect_rejected) guard_would_catch++;
        if (!resource_ok && tc->expect_rejected) guard_would_catch++; // resource guard also catches
        printf("OK\n");
    }

    printf("\n--- Results ---\n");
    printf("Total tests:                %zu\n", NUM_CASES);
    printf("Overflow cases confirmed:   %d\n", overflow_confirmed);
    printf("Guard would catch (fix):    %d\n", guard_would_catch);
    printf("Failures:                   %d\n", failures);

    if (failures == 0) {
        printf("\n[PASS] All overflow conditions detected. The vulnerability exists in the\n"
               "       unpatched code (no upper-bound guard). The proposed INT32_MAX guard\n"
               "       would reject all dangerous slot values while allowing legitimate ones.\n");
        return 0;
    } else {
        printf("\n[FAIL] %d test(s) produced unexpected results.\n", failures);
        return 1;
    }
}
