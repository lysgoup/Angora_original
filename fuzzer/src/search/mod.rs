use crate::{
    executor::{Executor, StatusType},
    hint::{HintKind, TaintHint},
    mut_input::{self, MutInput},
};
use angora_common::config;
use rand::prelude::*;
use std::{
    self,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub mod interesting_val;
pub use self::interesting_val::*;
mod handler;
pub use self::handler::SearchHandler;

pub mod afl;
pub use self::afl::AFLFuzz;
pub mod det;
pub use self::det::DetFuzz;
pub mod reusing;
pub use self::reusing::ReusingFuzz;
pub mod exploit_op;
pub use self::exploit_op::ExploitOp;
pub mod len_op;
pub use self::len_op::LenOp;
pub mod magic_bytes_op;
pub use self::magic_bytes_op::MagicBytesOp;

// Which of `hints_len` indices this round's hints.len()-scaled operators (Det/Reusing/Len/
// MagicBytes) should visit, given their shared MAX_HINTS_FOR_BUDGET_SCALING cap. Always
// starting the window at index 0 would mean every hint past the cap is permanently unvisited
// once hints.len() exceeds it -- instead the window slides forward by `rotation_offset`
// (fuzz_loop.rs derives this from the seed's fuzzed_count) each visit and wraps around, so
// repeated visits to the same seed eventually cycle through every hint.
pub fn rotated_hint_indices(
    hints_len: usize,
    rotation_offset: usize,
) -> impl Iterator<Item = usize> {
    let cap = if hints_len == 0 {
        0
    } else {
        config::MAX_HINTS_FOR_BUDGET_SCALING.min(hints_len)
    };
    let start = if hints_len == 0 {
        0
    } else {
        rotation_offset % hints_len
    };
    (0..cap).map(move |k| (start + k) % hints_len.max(1))
}

#[cfg(test)]
mod rotated_hint_indices_tests {
    use super::*;

    #[test]
    fn empty_hints_yields_nothing() {
        let v: Vec<usize> = rotated_hint_indices(0, 0).collect();
        assert!(v.is_empty());
        let v: Vec<usize> = rotated_hint_indices(0, 100).collect();
        assert!(v.is_empty());
    }

    #[test]
    fn under_cap_covers_everything_from_zero_regardless_of_offset() {
        let n = config::MAX_HINTS_FOR_BUDGET_SCALING - 1;
        let v: Vec<usize> = rotated_hint_indices(n, 0).collect();
        assert_eq!(v, (0..n).collect::<Vec<_>>());
        // Even with a nonzero offset, at-or-under-cap still visits every index (just
        // starting elsewhere and wrapping), never fewer than n distinct indices.
        let v: Vec<usize> = rotated_hint_indices(n, 5).collect();
        assert_eq!(v.len(), n);
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), n);
    }

    #[test]
    fn over_cap_window_size_is_exactly_the_cap() {
        let n = config::MAX_HINTS_FOR_BUDGET_SCALING * 5;
        let v: Vec<usize> = rotated_hint_indices(n, 0).collect();
        assert_eq!(v.len(), config::MAX_HINTS_FOR_BUDGET_SCALING);
        assert_eq!(
            v,
            (0..config::MAX_HINTS_FOR_BUDGET_SCALING).collect::<Vec<_>>()
        );
    }

    #[test]
    fn successive_windows_eventually_cover_every_hint() {
        let cap = config::MAX_HINTS_FOR_BUDGET_SCALING;
        let n = cap * 3 + 7; // not an exact multiple of cap, to also exercise wraparound
        let mut covered = std::collections::HashSet::new();
        for visit in 0..10 {
            let offset = visit * cap;
            for i in rotated_hint_indices(n, offset) {
                assert!(i < n);
                covered.insert(i);
            }
        }
        assert_eq!(
            covered.len(),
            n,
            "every hint should be visited within a few rotations"
        );
    }
}
