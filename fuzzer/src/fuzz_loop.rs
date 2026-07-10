use crate::{
    branches::GlobalBranches, command::CommandOpt, depot::Depot, executor::Executor, search::*,
    stats,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

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
        let (_speed, edge_num, fuzzed_count) = depot.get_entry_info(id);
        let first_time = fuzzed_count == 0;

        {
            let mut handler = SearchHandler::new(running.clone(), &mut executor, buf);

            if enable_afl {
                AFLFuzz::new(&mut handler, &hints, edge_num as usize).run(first_time);
            }

            DetFuzz::new(&mut handler).run(&hints);
            ReusingFuzz::new(&mut handler).run(&hints, 50);
            ExploitOp::new(&mut handler).run(&hints);
            LenOp::new(&mut handler).run(&hints);
            MagicBytesOp::new(&mut handler).run(&hints);
        }

        depot.update_entry(id);
    }
}
