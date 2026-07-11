use super::*;
use crate::{branches::GlobalBranches, depot::Depot};
use colored::*;
use serde_derive::Serialize;
use std::sync::Arc;

#[derive(Default, Serialize)]
pub struct ChartStats {
    init_time: TimeIns,
    track_time: TimeDuration,
    density: Average,

    num_rounds: Counter,
    max_rounds: Counter,
    num_exec: Counter,
    speed: Average,

    avg_exec_time: Average,
    avg_edge_num: Average,

    num_inputs: Counter,
    num_hangs: Counter,
    num_crashes: Counter,

    // Size of the reuse pool (label_pattern_tracker) -- the main thing worth watching for this
    // fuzzer, since reuse is the primary solving mechanism rather than a bolt-on.
    reuse_patterns: Counter,
    reuse_records: Counter,

    // Per-operator breakdown (AFL/Det/Reusing/Exploit/Len/MagicBytes), restoring the
    // visibility the original per-FuzzType `-- FUZZ --` table gave.
    op: OpStats,
}

impl ChartStats {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn sync_from_local(&mut self, local: &mut LocalStats) {
        self.track_time += local.track_time;
        self.num_rounds.count();

        local.avg_edge_num.sync(&mut self.avg_edge_num);
        local.avg_exec_time.sync(&mut self.avg_exec_time);

        self.num_exec += local.num_exec;
        self.num_inputs += local.num_inputs;
        self.num_hangs += local.num_hangs;
        self.num_crashes += local.num_crashes;

        for i in 0..OP_KIND_NUM {
            let src = *local.op_stats.get(i);
            let dst = self.op.get_mut(i);
            dst.time += src.time;
            dst.num_exec += src.num_exec;
            dst.num_inputs += src.num_inputs;
            dst.num_hangs += src.num_hangs;
            dst.num_crashes += src.num_crashes;
        }
    }

    pub fn sync_from_global(&mut self, depot: &Arc<Depot>, gb: &Arc<GlobalBranches>) {
        self.get_speed();
        self.max_rounds = depot.max_fuzzed_count().into();
        self.sync_reuse_stats();
        self.sync_from_branches(gb);
    }

    fn sync_reuse_stats(&mut self) {
        let (num_patterns, num_records) = crate::depot::get_pattern_stats();
        self.reuse_patterns = num_patterns.into();
        self.reuse_records = num_records.into();
    }

    fn sync_from_branches(&mut self, gb: &Arc<GlobalBranches>) {
        self.density = Average::new(gb.get_density(), 0);
    }

    fn get_speed(&mut self) {
        let t: TimeDuration = self.init_time.into();
        let d: time::Duration = t.into();
        let ts = d.as_secs() as f64;
        let speed = if ts > 0.0 {
            let v: usize = self.num_exec.into();
            v as f64 / ts
        } else {
            0.0
        };
        self.speed = Average::new(speed as f32, 0);
    }

    pub fn mini_log(&self) -> String {
        format!(
            "{}, {}, {}, {}, {}",
            self.init_time.0.elapsed().as_secs(),
            self.density.0,
            self.num_inputs.0,
            self.num_hangs.0,
            self.num_crashes.0
        )
    }

    // Stall-detection signal for fuzz_main's main loop: how many interesting inputs have been
    // found so far. Replaces the old CondStmt-era "how many Explore conds solved" count -- for
    // an input-centric fuzzer, "found nothing new in a while" is the natural analogue.
    pub fn get_progress_num(&self) -> usize {
        self.num_inputs.into()
    }
}

impl fmt::Display for ChartStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.density.0 > 10.0 {
            warn!("Density is too large (> 10%). Please increase `MAP_SIZE_POW2` in and `common/src/config.rs`. Or disable function-call context(density > 50%) by compiling with `ANGORA_CUSTOM_FN_CONTEXT=k` (k is an integer and 0 <= k <= 32) environment variable. Angora disables context if k is 0.");
        }

        write!(
            f,
            r#"
{}
{}
    TIMING |     RUN: {},   TRACK: {}
  COVERAGE |    EDGE: {},   DENSITY: {}%
    EXECS  |   TOTAL: {},     ROUND: {},     MAX_R: {}
    SPEED  |  PERIOD: {:6}r/s    TIME: {}us,
    FOUND  |    PATH: {},     HANGS: {},   CRASHES: {}
{}
{}
{}
    REUSE  | PATTERNS: {},   RECORDS: {}

"#,
            get_bunny_logo().bold(),
            " -- OVERVIEW -- ".blue().bold(),
            self.init_time,
            self.track_time,
            self.avg_edge_num,
            self.density,
            self.num_exec,
            self.num_rounds,
            self.max_rounds,
            self.speed,
            self.avg_exec_time,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
            " -- FUZZ -- ".blue().bold(),
            self.op,
            " -- REUSE -- ".blue().bold(),
            self.reuse_patterns,
            self.reuse_records,
        )
    }
}
