// ************ Switches **************
// length
pub const ENABLE_INPUT_LEN_EXPLORATION: bool = true;
pub const ENABLE_RANDOM_LEN: bool = false;
pub const ENABLE_MICRO_RANDOM_LEN: bool = true;

// other
pub const DISABLE_INFER_SHAPE_IF_HAS_AND_OP: bool = true;

// ************ Resources ****************
pub const MAX_INPUT_LEN: usize = 1000000;

// branch.rs
pub const MAP_SIZE_POW2: usize = 23;
pub const BRANCHES_SIZE: usize = 1 << MAP_SIZE_POW2;

// executor.rs:
pub const TMOUT_SKIP: usize = 3;
pub const TIME_LIMIT: u64 = 1;
pub const MEM_LIMIT: u64 = 200; // MB
pub const TIME_LIMIT_TRACK: u64 = 12;
pub const MEM_LIMIT_TRACK: u64 = 0;
pub const LONG_FUZZ_TIME: usize = 8;
// based the bit bucket: [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
pub const MAX_COND_ORDER: u32 = 16;

// ************ Mutation ****************
// SEARCH
pub const MAX_SEARCH_EXEC_NUM: usize = 376;
pub const MAX_EXPLOIT_EXEC_NUM: usize = 66;
pub const BONUS_EXEC_NUM: usize = 66;
// Det/Reusing/Len/MagicBytes each size their per-round budget as some constant times
// hints.len() -- fine for small synthetic targets (a handful of hints per input), but on a
// real-world target a single traced input can carry hundreds or thousands of taint hints,
// which blows the whole round's budget up to millions of executions. Since these operators
// run before AFL in the mutation menu (fuzz_loop.rs) and all share one SearchHandler, that
// starves AFL down to a sliver of the total exec budget and can pin a worker thread on its
// very first seed for the entire campaign (observed: 12h run, AFL got 12 minutes of it).
// Capping the hints.len() multiplier at this ceiling keeps a single round bounded regardless
// of target complexity, so the queue keeps cycling and every operator (including AFL) gets a
// turn on every seed instead of just the first one.
pub const MAX_HINTS_FOR_BUDGET_SCALING: usize = 64;

// AFL
pub const MUTATE_ARITH_MAX: u32 = 30;
pub const RANDOM_LEN_NUM: usize = 30;
pub const MAX_HAVOC_FLIP_TIMES: usize = 45; // for all bytes
pub const MAX_SPLICE_TIMES: usize = 45;
