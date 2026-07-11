use super::*;
use serde_derive::Serialize;

// Which mutation operator in the per-seed menu (fuzz_loop.rs) ran -- replaces the old
// per-branch FuzzType now that the queue holds seeds, not conds being solved. Restores the
// original Angora's per-strategy stats breakdown at this same granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Afl,
    Det,
    Reusing,
    Exploit,
    Len,
    MagicBytes,
}

pub const OP_KIND_NUM: usize = OpKind::MagicBytes as usize + 1;
static OP_KIND_NAME: [&str; OP_KIND_NUM] =
    ["AFL", "Det", "Reusing", "Exploit", "Len", "MagicBytes"];

impl OpKind {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

pub fn get_op_kind_name(i: usize) -> String {
    OP_KIND_NAME[i].to_string()
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct StrategyStats {
    pub time: TimeDuration,
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
}

impl fmt::Display for StrategyStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EXEC: {}, TIME: {}, FOUND: {} - {} - {}",
            self.num_exec, self.time, self.num_inputs, self.num_hangs, self.num_crashes,
        )
    }
}

#[derive(Clone, Default, Serialize)]
pub struct OpStats([StrategyStats; OP_KIND_NUM]);

impl OpStats {
    #[inline]
    pub fn get_mut(&mut self, i: usize) -> &mut StrategyStats {
        &mut self.0[i]
    }

    pub fn get(&self, i: usize) -> &StrategyStats {
        &self.0[i]
    }
}

impl fmt::Display for OpStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let contents = self
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| format!("  {:>10} | {}", get_op_kind_name(i).to_uppercase(), s))
            .collect::<Vec<_>>()
            .join("\n");
        write!(f, "{}", contents)
    }
}
