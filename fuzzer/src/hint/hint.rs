use angora_common::{cond_stmt_base::CondStmtBase, defs, tag::TagSeg};

// What kind of taint-tracking record this hint came from -- decides which operator(s) in the
// per-seed mutation menu (fuzz_loop.rs) act on it. Replaces the old FuzzType dispatch; there is
// no AFL/Other variant here since plain AFL havoc runs on every seed unconditionally rather than
// being represented as a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    Explore,
    Exploit,
    Len,
    CmpFn,
}

impl HintKind {
    pub fn from_op(op: u32) -> Option<Self> {
        match op {
            defs::COND_LEN_OP => Some(HintKind::Len),
            defs::COND_FN_OP => Some(HintKind::CmpFn),
            _ => {
                if op <= defs::COND_MAX_EXPLORE_OP {
                    Some(HintKind::Explore)
                } else if op <= defs::COND_MAX_EXPLOIT_OP {
                    Some(HintKind::Exploit)
                } else {
                    None
                }
            },
        }
    }
}

// One tainted comparison site extracted from a taint-tracking run, attached to the seed input
// that produced it (see depot::QueueEntry). Replaces CondStmt: carries only the data that
// mutation operators need to act on this site, not the GD/state-machine bookkeeping
// (no `state`/`fuzz_times`/`num_minimal_optima`/`belong` -- the last is implicit since a hint
// lives inside the QueueEntry of the input that produced it).
#[derive(Debug, Clone)]
pub struct TaintHint {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
    pub op: u32,
    pub condition: u32,
    pub size: u32,
    pub lb1: u32,
    pub lb2: u32,
    pub arg1: u64,
    pub arg2: u64,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    pub variables: Vec<u8>,
    pub kind: HintKind,
}

impl TaintHint {
    pub fn from_base(base: &CondStmtBase) -> Option<Self> {
        let kind = HintKind::from_op(base.op)?;
        Some(Self {
            cmpid: base.cmpid,
            context: base.context,
            order: base.order,
            op: base.op,
            condition: base.condition,
            size: base.size,
            lb1: base.lb1,
            lb2: base.lb2,
            arg1: base.arg1,
            arg2: base.arg2,
            offsets: vec![],
            offsets_opt: vec![],
            variables: vec![],
            kind,
        })
    }

    pub fn is_tainted(&self) -> bool {
        !self.offsets.is_empty()
    }

    // Equality-style comparisons (==, !=, switch-case) are asking "does this match a specific
    // constant", which is exactly the kind of value cross-hint reuse is good at transferring.
    // Ordering comparisons (<, <=, >, >=) are asking "is this past some threshold" -- a value
    // that satisfied an unrelated equality check elsewhere has no particular reason to be a
    // meaningful threshold here, so reuse across hints is restricted to this being true on
    // both ends (see depot::label_pattern_tracker).
    pub fn is_eq_like(&self) -> bool {
        let basic = self.op & defs::COND_BASIC_MASK;
        basic == defs::COND_ICMP_EQ_OP
            || basic == defs::COND_ICMP_NE_OP
            || basic == defs::COND_SW_OP
    }
}
