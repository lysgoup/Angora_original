/*
<<<<<<< Updated upstream
 * storfuzz_rt.c — StorFuzz data-coverage shmem runtime for Angora fast mode.
 *
 * Responsibilities
 * ----------------
 *  1. Provide the global pointer __angora_data_area_ptr that the LLVM pass
 *     writes to.  Falls back to a static buffer so the target can run
 *     standalone (without the fuzzer attached).
 *  2. At process startup, attach to the fuzzer-allocated shared-memory
 *     segment identified by ANGORA_DATA_SHM_ID and redirect the pointer.
 *
 * Per-execution reset
 * -------------------
 *  The data map is cleared by the Rust fuzzer (parent process) via
 *  DataCov::clear_run_map() immediately before each fork-server trigger —
 *  the same pattern used for the branch map (Branches::clear_trace()).
 *  No C-side memset is needed here.
 *
 * Constructor ordering
 * --------------------
 *  The branch-map init runs via the `ctor` crate's #[ctor] which compiles
 *  to __attribute__((constructor)) with no explicit priority (compiler
 *  assigns a default).  We use priority 200 here to run after the branch-map
 *  init.  If the branch map ever gains an explicit priority, bump this
 *  accordingly.
=======
 * storfuzz_rt.c — StorFuzz data-coverage runtime for Angora fast builds.
 *
 * Defines __angora_data_area_ptr (the map pointer the LLVM pass writes to)
 * and attaches the shared memory region passed via ANGORA_DATA_SHM_ID.
 *
 * Build note: compiled into libcontext.a alongside context.c.
 * Gated at call sites by ANGORA_USE_STORFUZZ=1 / USE_FAST=1.
>>>>>>> Stashed changes
 */

#include <stdint.h>
#include <stdlib.h>
<<<<<<< Updated upstream
#include <string.h>
#include <sys/shm.h>

#define STORFUZZ_MAP_SIZE (1 << 17)

/* Static fallback buffer — used when no fuzzer is attached */
static uint8_t __angora_storfuzz_default_map[STORFUZZ_MAP_SIZE];

/*
 * __angora_data_area_ptr — the global written by instrumented stores.
 * ExternalWeakLinkage in the LLVM pass means this definition wins at link
 * time and the pass's weak declaration resolves to it.
 */
uint8_t *__angora_data_area_ptr = __angora_storfuzz_default_map;

/*
 * Constructor: runs once at process start.
 * Reads ANGORA_DATA_SHM_ID, attaches the shared-memory segment, and
 * redirects __angora_data_area_ptr so instrumented stores go into the
 * fuzzer-visible region.
 */
=======
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
>>>>>>> Stashed changes
__attribute__((constructor(200)))
static void __angora_storfuzz_init(void) {
    const char *id_str = getenv("ANGORA_DATA_SHM_ID");
    if (!id_str) return;

    int shm_id = atoi(id_str);
    void *p = shmat(shm_id, NULL, 0);
<<<<<<< Updated upstream
    if (p != (void *)-1) {
        __angora_data_area_ptr = (uint8_t *)p;
    }
=======
    if (p == (void *)-1) return;

    __angora_data_area_ptr = (uint8_t *)p;
>>>>>>> Stashed changes
}
