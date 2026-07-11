use crate::{
    branches::GlobalBranches, command::CommandOpt, depot::Depot, executor::Executor, search::*,
    stats,
};
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

        {
            let mut handler = SearchHandler::new(running.clone(), &mut executor, buf);

            // Cheap and targeted first, generic/expensive havoc last: give the reuse pool
            // (the main solving mechanism) and the other targeted operators first crack at
            // the round's budget, and spend AFL's much larger splice+havoc budget on
            // whatever's left. Each operator carves out its own budget via set_budget, so
            // this ordering is about priority, not starvation -- but there's no reason to
            // burn budget on generic havoc before the targeted attempts get a turn.
            run_op(&mut handler, OpKind::Reusing, |h| {
                ReusingFuzz::new(h).run(&hints, &mut cursors, 50)
            });
            run_op(&mut handler, OpKind::Det, |h| DetFuzz::new(h).run(&hints));
            run_op(&mut handler, OpKind::Exploit, |h| {
                ExploitOp::new(h).run(&hints)
            });
            run_op(&mut handler, OpKind::Len, |h| LenOp::new(h).run(&hints));
            run_op(&mut handler, OpKind::MagicBytes, |h| {
                MagicBytesOp::new(h).run(&hints)
            });

            if enable_afl {
                run_op(&mut handler, OpKind::Afl, |h| {
                    AFLFuzz::new(h, &hints, edge_num as usize).run(first_time)
                });
            }
        }

        depot.set_cursors(id, cursors);
        depot.update_entry(id);
    }
}
