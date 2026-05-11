/*
 * storfuzz_rt.c — StorFuzz data-coverage runtime for Angora fast builds.
 *
 * Defines __angora_data_area_ptr (the map pointer the LLVM pass writes to)
 * and attaches the shared memory region passed via ANGORA_DATA_SHM_ID.
 *
 * Build note: compiled into libcontext.a alongside context.c.
 * Gated at call sites by ANGORA_USE_STORFUZZ=1 / USE_FAST=1.
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/shm.h>

#ifndef STORFUZZ_MAP_SIZE
# define STORFUZZ_MAP_SIZE (1 << 17)   /* 131072 — matches DATA_COV_SIZE */
#endif

/* Static fallback map used when shmem is not configured (e.g. dry-run
 * without ANGORA_DATA_SHM_ID).  Never causes a NULL deref. */
static uint8_t __angora_storfuzz_default_map[STORFUZZ_MAP_SIZE];

/* The LLVM pass emits:
 *   @__angora_data_area_ptr = external global i8*
 * and dereferences it at every instrumented store.
 * We define it here with ExternalLinkage (must match the pass). */
uint8_t *__angora_data_area_ptr = __angora_storfuzz_default_map;

/* Constructor priority 200 — runs after Angora's ctor (default priority)
 * so the fork-server environment is already set up. */
__attribute__((constructor(200)))
static void __angora_storfuzz_init(void) {
    const char *id_str = getenv("ANGORA_DATA_SHM_ID");
    if (!id_str) return;

    int shm_id = atoi(id_str);
    void *p = shmat(shm_id, NULL, 0);
    if (p == (void *)-1) return;

    __angora_data_area_ptr = (uint8_t *)p;
}
