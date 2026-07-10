use super::*;
use crate::stats::Counter;

// Shared execution/budget plumbing every mutation operator in the per-seed menu
// (fuzz_loop.rs) is built on. Unlike the old CondStmt-era SearchHandler, this holds no
// per-branch state to solve -- operators read hints (fuzzer/src/hint) as read-only guidance
// and just mutate `buf`; success is judged by the executor's own new-coverage detection
// (has_new_path/has_new_edge), not by any distance-to-zero signal this handler tracks.
pub struct SearchHandler<'a> {
    running: Arc<AtomicBool>,
    pub executor: &'a mut Executor,
    pub buf: Vec<u8>,
    pub max_times: Counter,
    pub skip: bool,
}

impl<'a> SearchHandler<'a> {
    pub fn new(running: Arc<AtomicBool>, executor: &'a mut Executor, buf: Vec<u8>) -> Self {
        executor.local_stats.register();
        Self {
            running,
            executor,
            buf,
            max_times: config::MAX_SEARCH_EXEC_NUM.into(),
            skip: false,
        }
    }

    pub fn is_stopped_or_skip(&self) -> bool {
        !self.running.load(Ordering::Relaxed) || self.skip
    }

    // Grants this operator its own execution allowance on top of whatever earlier operators in
    // this round have already spent, and clears any skip they left behind. Since one handler
    // now runs the whole mutation menu (AFL, Det, Reusing, ...) per seed instead of one
    // operator per handler, budgets must stack relative to num_exec rather than each operator
    // overwriting max_times with its own absolute constant (which would immediately trip skip
    // for whichever operator runs later).
    pub fn set_budget(&mut self, budget: usize) {
        self.skip = false;
        self.max_times = (self.executor.local_stats.num_exec.0 + budget).into();
    }

    fn process_status(&mut self, status: StatusType) {
        match status {
            StatusType::Skip => {
                self.skip = true;
            },
            _ => {},
        }

        // bonus
        if self.executor.has_new_path {
            self.max_times += config::BONUS_EXEC_NUM.into();
        }

        // Skip if it reach max epoch,
        // Like a Round-Robin algorithm,
        // To avoid stuck on one seed too much time.
        if self.executor.local_stats.num_exec > self.max_times {
            self.skip = true;
        }
    }

    // `buf` is a candidate the caller built (typically a clone of self.buf with some bytes
    // changed) -- self.buf itself is never mutated by execute, it stays the stable base every
    // operator tries variants against, and doubles as the "parent" the executor diffs against
    // to figure out which bytes this candidate actually changed.
    pub fn execute(&mut self, buf: &Vec<u8>) {
        let status = self.executor.run(buf, &self.buf);
        self.process_status(status);
    }
}

impl<'a> Drop for SearchHandler<'a> {
    fn drop(&mut self) {
        self.executor.update_log();
    }
}
