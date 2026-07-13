use crate::{
    branches::GlobalBranches, command::CommandOpt, depot::Depot, executor::Executor, search::*,
    stats,
};
use angora_common::config;
use stats::OpKind;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

// Runs one operator and attributes the exec/inputs/hangs/crashes/time it spent to `kind` in
// the executor's per-operator stats (stats::OpStats) -- this is what backs the `-- FUZZ --`
// breakdown in the periodic stats block, same granularity the original Angora's per-FuzzType
// table gave.
fn run_op<'a>(
    handler: &mut SearchHandler<'a>,
    kind: OpKind,
    f: impl FnOnce(&mut SearchHandler<'a>),
) {
    let snapshot = handler.executor.local_stats.snapshot();
    f(handler);
    handler.executor.local_stats.record_op(kind, snapshot);
}

// One worker thread's main loop. Unlike the old CondStmt-era version, this doesn't dispatch on
// a per-branch FuzzType/CondState -- every seed popped off the queue runs through the same
// fixed mutation menu (AFL havoc/splice, deterministic sweep, reuse-pool splat, and the
// hint-driven exploit/len/magic-bytes operators), all working off whatever taint hints that
// seed carries. A seed is never "done" -- it just keeps getting requeued, same as classic AFL.
pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
) {
    let enable_afl = cmd_opt.enable_afl;
    let enable_reusing = cmd_opt.enable_reusing;
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
    );

    while running.load(Ordering::Relaxed) {
        let id = match depot.get_entry() {
            Some(id) => id,
            None => break,
        };

        let buf = depot.get_input_buf(id);
        let hints = depot.get_hints(id);
        let mut cursors = depot.get_cursors(id);
        let (_speed, edge_num, fuzzed_count) = depot.get_entry_info(id);
        let first_time = fuzzed_count == 0;
        // Which window of hints Det/Reusing/Len/MagicBytes cover this visit (see
        // search::rotated_hint_indices) -- advances by a full window each time this seed is
        // fuzzed again, so a hint-rich input eventually gets all its hints covered across
        // several visits instead of the same prefix forever.
        let rotation_offset = fuzzed_count * config::MAX_HINTS_FOR_BUDGET_SCALING;

        {
            let mut handler = SearchHandler::new(running.clone(), &mut executor, buf);

            // TEMPORARY: Det/Exploit/MagicBytes/Len disabled to isolate Reusing vs. AFL's
            // exec/time share for a comparison run against Reusing_mut -- re-enable once
            // that's done.
            if enable_reusing {
                run_op(&mut handler, OpKind::Reusing, |h| {
                    ReusingFuzz::new(h).run(&hints, &mut cursors)
                });
            }
            // run_op(&mut handler, OpKind::Det, |h| {
            //     DetFuzz::new(h).run(&hints, rotation_offset)
            // });
            // run_op(&mut handler, OpKind::Exploit, |h| {
            //     ExploitOp::new(h).run(&hints)
            // });
            // run_op(&mut handler, OpKind::MagicBytes, |h| {
            //     MagicBytesOp::new(h).run(&hints, rotation_offset)
            // });

            if enable_afl {
                run_op(&mut handler, OpKind::Afl, |h| {
                    AFLFuzz::new(h, &hints, edge_num as usize, enable_reusing).run(first_time)
                });
            }

            // run_op(&mut handler, OpKind::Len, |h| {
            //     LenOp::new(h).run(&hints, rotation_offset)
            // });
        }

        depot.set_cursors(id, cursors);
        depot.update_entry(id);
    }
}
