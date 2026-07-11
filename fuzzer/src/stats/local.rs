use super::*;
use crate::executor::StatusType;

// Exec/inputs/hangs/crashes counters at the moment an operator started, so the delta after it
// finishes can be attributed to that specific operator (see LocalStats::record_op). Also its
// own start time, to compute how long that operator ran.
pub struct OpSnapshot {
    num_exec: Counter,
    num_inputs: Counter,
    num_hangs: Counter,
    num_crashes: Counter,
    start: TimeIns,
}

#[derive(Default)]
pub struct LocalStats {
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,

    pub track_time: TimeDuration,
    pub start_time: TimeIns,

    pub avg_exec_time: SyncAverage,
    pub avg_edge_num: SyncAverage,

    pub op_stats: OpStats,
}

impl LocalStats {
    // Called once per seed picked up by fuzz_loop, before running it through the mutation
    // menu -- resets the per-round counters synced into ChartStats on the next update_log().
    pub fn register(&mut self) {
        self.clear();
    }

    pub fn clear(&mut self) {
        self.num_exec = Default::default();
        self.num_inputs = Default::default();
        self.num_hangs = Default::default();
        self.num_crashes = Default::default();

        self.start_time = Default::default();
        self.track_time = Default::default();

        self.op_stats = Default::default();
    }

    pub fn find_new(&mut self, status: &StatusType) {
        match status {
            StatusType::Normal => {
                self.num_inputs.count();
            },
            StatusType::Timeout => {
                self.num_hangs.count();
            },
            StatusType::Crash => {
                self.num_crashes.count();
            },
            _ => {},
        }
    }

    pub fn snapshot(&self) -> OpSnapshot {
        OpSnapshot {
            num_exec: self.num_exec,
            num_inputs: self.num_inputs,
            num_hangs: self.num_hangs,
            num_crashes: self.num_crashes,
            start: Default::default(),
        }
    }

    // Attributes the exec/inputs/hangs/crashes/time delta since `snapshot` to `kind`'s bucket
    // in op_stats. Called once right after each operator's run() returns (fuzz_loop.rs).
    pub fn record_op(&mut self, kind: OpKind, snapshot: OpSnapshot) {
        let st = self.op_stats.get_mut(kind.index());
        st.time += snapshot.start.into();
        st.num_exec += Counter(self.num_exec.0 - snapshot.num_exec.0);
        st.num_inputs += Counter(self.num_inputs.0 - snapshot.num_inputs.0);
        st.num_hangs += Counter(self.num_hangs.0 - snapshot.num_hangs.0);
        st.num_crashes += Counter(self.num_crashes.0 - snapshot.num_crashes.0);
    }
}
