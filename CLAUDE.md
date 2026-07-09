# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Angora is a mutation-based, coverage-guided fuzzer that increases branch coverage by solving
path constraints via gradient-descent-style search instead of symbolic execution (see
[paper](https://arxiv.org/abs/1803.01307), S&P 2018). The fuzzer core is Rust; target
instrumentation is done via an LLVM pass + DFSan-based taint tracking (or, alternatively,
Intel Pin). This repo is a fork (`Angora_original`) with active local modifications on top of
upstream Angora — recent work has focused on dry-run behavior, map size, signal/sync
directories, and per-input logging (see `git log`).

## Build

Requires Linux-amd64, Rust stable (>= 1.31, via rustup), and LLVM 4.0.0–12.0.1.

```shell
export PATH=/path-to-clang/bin:$PATH
export LD_LIBRARY_PATH=/path-to-clang/lib:$LD_LIBRARY_PATH

./build/build.sh          # installs LLVM if missing, cargo builds debug+release, builds llvm_mode via cmake, installs into ./bin
```

`build/build.sh` populates `./bin/` with the `fuzzer` binary, static runtime libs, and the
instrumenting compiler/passes (`angora-clang`, `angora-clang++`, LLVM pass `.so` files). The
top-level `angora_fuzzer` shell script is the entry point users invoke — it sets
`RUST_LOG`/`ANGORA_BIN_DIR` and execs `target/{debug,release}/fuzzer` (`BUILD_TYPE` env var
selects debug vs release, default `release`).

Also required once per machine: disable core dumps (`echo core | sudo tee
/proc/sys/kernel/core_pattern`), needed by both the fuzzer and `check_dep::check_dep`.

Pin-mode taint tracking (libdft64, alternative to DFSan) is a git submodule at
`pin_mode/libdft64`; see `build/install_pin_mode.sh` and `docs/pin_mode.md`.

## Test

There is no target-agnostic `cargo test` suite of real coverage — CI (`.cirrus.yml`) just runs
`cargo build` via `build/build.sh` then `cargo test` (workspace unit tests, currently sparse).

The real test suite is `tests/`: small C programs, each fuzzed end-to-end to confirm Angora's
pass/runtime/search pipeline actually works on real binaries.

```shell
cd tests
./test.sh mini        # compiles tests/mini/mini.c, fuzzes it, requires tests/mini/args
```

Each subdirectory under `tests/` (e.g. `mini`, `strcmp`, `switch`, `gep`, `context`, `asan`,
`fstream`, ...) holds one target `<name>/<name>.c` plus an `args` file (program args, `@@` is
replaced with the generated input path). `test.sh` compiles the target twice with
`../bin/angora-clang` — once `USE_FAST=1` (branch/constraint instrumentation, `.fast` binary)
and once `USE_TRACK=1` (DFSan taint tracking, `.taint` binary) — then runs
`../angora_fuzzer -m llvm -t <target>.taint -- <target>.fast <args>` against a single seed in
`./input`. `testcpp.sh` and `test_bc.sh` are variants for C++ targets and pre-bitcode
(`wllvm`/`gllvm`) builds respectively. Set `RELEASE=1` to fuzz against a release build.

To add a new fuzz-target test case, mirror an existing `tests/<name>/` directory (source +
`args` file).

## Architecture

Angora requires **two instrumented copies** of the target: a `.fast` binary (branch/constraint
coverage, lightweight) and a `.taint`/`.pin` binary (full taint tracking, only invoked when a
new interesting branch is found — taint tracking is too slow to run on every execution). This
split is the central design constraint; most of the crate boundaries below exist to serve it.

Cargo workspace members (`Cargo.toml`):

- **`common`** (`angora_common`) — shared types used by both the fuzzer and the target-side
  runtime: `defs.rs` (env var names, magic constants, directory names shared across the whole
  pipeline), `config.rs` (tunables: map size `MAP_SIZE_POW2`, mutation/search limits, time/mem
  limits — read this before touching search or executor behavior), `cond_stmt_base.rs` (the
  wire format for a branch condition, shared between runtime and fuzzer), `tag.rs`, `shm.rs`
  (shared-memory layout), `log_data.rs`.
- **`runtime`** — the taint-tracking runtime linked into `.taint`/`.pin` binaries: DFSan
  tag-set management (`tag_set.rs`, `tag_set_wrap.rs`), heap tracking (`heapmap.rs`),
  length-label propagation (`len_label.rs`), and `track.rs` which records
  `__dfsw___angora_trace_cmp_tt` calls (comparisons) to the track file the fuzzer later parses.
- **`runtime_fast`** — the lightweight runtime linked into `.fast` binaries: branch-hit shared
  memory (`shm_branches.rs`), condition shared memory (`shm_conds.rs`), and the AFL-style
  fork-server protocol (`forkcli.rs`, `context.c`/`context.rs`) that the fuzzer's executor talks
  to for fast repeated execution without re-exec/re-fork overhead per input.
- **`fuzzer`** (`angora` crate) — the orchestrator, driven by `fuzz_main.rs` →
  `fuzz_loop.rs` per worker thread:
  - `depot/` — on-disk queue of interesting inputs plus their conditions (`Depot`,
    `qpriority.rs` priority ordering, `sync.rs` for AFL-directory syncing via `--sync_afl`,
    `dump.rs`, `file.rs`).
  - `executor/` — runs the target binary through the fork server (`forksrv.rs`), enforces
    memory/time limits (`limit.rs`), classifies exit status (`status_type.rs`).
  - `track/` — parses the taint/comparison track file produced by `runtime` after a taint run
    (`fparser.rs`, `filter.rs`) or the Pin-mode equivalent (`load_pin_data.rs`).
  - `cond_stmt/` — in-memory representation of a branch constraint being solved
    (`cond_stmt.rs`, `cond_state.rs` state machine: det → search → one-byte → exploit/done),
    plus shared-memory hookup (`shm_conds.rs`).
  - `search/` — pluggable constraint-solving strategies selected by `-r`
    (`gd.rs` gradient descent — default, `random.rs`, `mb.rs`, `cbh.rs`), plus supporting
    strategies always applied regardless of `-r`: `det.rs` (deterministic byte mutations),
    `one_byte.rs`, `afl.rs` (classic AFL havoc/splice, disable with `-A`), `interesting_val.rs`,
    `len.rs`, `cmpfn.rs`. `handler.rs`'s `SearchHandler` is what every strategy runs against.
  - `branches.rs` — global coverage bitmap (`GlobalBranches`, sized by
    `config::MAP_SIZE_POW2`/`BRANCHES_SIZE`) used to decide if a new execution is "interesting".
  - `stats/` — live UI / stats file rendering (`show.rs`, `chart.rs`, `fuzz.rs`); see
    `docs/ui.md` for field meanings.
  - `command.rs` — `CommandOpt`, built once from CLI args, then `.specify(thread_id)`'d per
    fuzzing thread; owns the LLVM-vs-Pin mode branching (`InstrumentationMode`) and per-thread
    tmpfs working dirs.
  - `check_dep.rs` — preflight checks: core-dump config, target has expected instrumentation
    symbols (`__angora_cond_cmpid` for `.fast`, `__dfsw___angora_trace_cmp_tt` for `.taint`),
    ASAN detection (forces unlimited memory).
  - `bin/fuzzer.rs` is the CLI (clap) entry point; `bin/parse_track_file.rs` and
    `bin/speed_test.rs` are standalone debug utilities over the same track/executor code.
- **`llvm_mode`** — C++ LLVM passes (built via CMake, not Cargo) that instrument target source:
  `AngoraPass.cc` (branch/constraint instrumentation for `.fast`), `DFSanPass.cc` (taint
  instrumentation for `.taint`), `UnfoldBranchPass.cc` (splits compound conditionals so each
  atomic comparison gets its own id). `compiler/angora_clang.c` is the `angora-clang` wrapper
  invoked as `CC`/`CXX` by target build systems, switched between fast/track/pin modes via
  `USE_FAST`/`USE_TRACK`/`USE_PIN` env vars. `rules/angora_abilist.txt` /
  `exploitation_list.txt` control which library calls are treated as taint sources/sinks or
  exploitable sinks.
- **`pin_mode`** — Intel Pin-based alternative to DFSan for taint tracking (`pin_track.cpp`),
  using libdft64 (submodule).

Fuzzing flow: `fuzz_main` picks/creates the output dir → `check_dep` validates the target
binaries → `Depot::new` + `sync_depot` do the dry run over seeds (populates initial branches;
fuzzing aborts if this finds nothing) → one `fuzz_loop` thread per `-j` job pulls a
`(CondStmt, priority)` from the depot, runs it through the state machine in `cond_state.rs`
(dispatching to `search/*` based on state and `-r`), executes candidate inputs via `executor`
against the `.fast` binary, and any input that hits new branches gets queued and — when a new
*branch* (not just new input) is found — re-run against the `.taint`/`.pin` binary to extract
fresh conditions for the depot. The main thread periodically calls `show_stats`, and (if
`--sync_afl`) syncs with AFL's queue directory.

## Documentation map

`docs/` has topic-specific guides worth reading before non-trivial changes in that area:
`build_target.md` (compiling arbitrary target programs, wllvm/gllvm fallback), `running.md`,
`usage.md`, `configuration.md`, `environment_variables.md`, `ui.md` (stats field meanings),
`pin_mode.md`, `exploitation.md`, `lava.md` / `lava-who-fix.md` (LAVA-M benchmark notes),
`troubleshoot.md`, `coverage.md`.

## Style

`rustfmt.toml`: tabs of 4 spaces, block indent, `brace_style = "SameLineWhere"`,
`control_brace_style = "AlwaysSameLine"`, imports merged. Run `cargo fmt` before committing
Rust changes.
