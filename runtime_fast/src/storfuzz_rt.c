/*
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
 */

#include <stdint.h>
#include <stdlib.h>
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
__attribute__((constructor(200)))
static void __angora_storfuzz_init(void) {
    const char *id_str = getenv("ANGORA_DATA_SHM_ID");
    if (!id_str) return;

    int shm_id = atoi(id_str);
    void *p = shmat(shm_id, NULL, 0);
    if (p != (void *)-1) {
        __angora_data_area_ptr = (uint8_t *)p;
    }
}
