use super::*;
use angora_common::tag::TagSeg;

// Cheap, non-iterative fallback for hints the reuse pool has nothing to offer yet: exhaustive
// bit-flip sweep plus a deterministic pass over AFL's "interesting values" table for each
// tainted region. No gradient/numeric optimization -- this is a bounded, one-shot sweep per
// hint, not a search that runs to convergence.
pub struct DetFuzz<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> DetFuzz<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    // `rotation_offset` (see search::rotated_hint_indices) picks which window of hints this
    // visit covers, so a target with more hints than MAX_HINTS_FOR_BUDGET_SCALING still gets
    // all of them covered across repeated visits instead of only ever the first window.
    pub fn run(&mut self, hints: &[TaintHint], rotation_offset: usize) {
        // Must call set_budget (not just inherit whatever budget/skip state an earlier
        // operator in this round left behind) -- otherwise this silently does nothing
        // whenever it runs after an operator that already exhausted its own budget.
        // hints.len() is capped (see MAX_HINTS_FOR_BUDGET_SCALING) so a target with hundreds
        // or thousands of hints per input can't blow this round's budget up to the point
        // where AFL never gets a turn.
        let scale = hints.len().max(1).min(config::MAX_HINTS_FOR_BUDGET_SCALING);
        self.handler.set_budget(config::MAX_SEARCH_EXEC_NUM * scale);
        for i in rotated_hint_indices(hints.len(), rotation_offset) {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let hint = &hints[i];
            if hint.offsets.is_empty() {
                continue;
            }
            self.bitflip(&hint.offsets);
            if self.handler.is_stopped_or_skip() {
                break;
            }
            self.interesting_sweep(&hint.offsets);
        }
    }

    // Exhaustively flips every bit in the tainted region once, restoring it right after --
    // one_byte's exhaustive 0..256 search for a single tainted byte is the n==8 case of this.
    fn bitflip(&mut self, offsets: &Vec<TagSeg>) {
        let base = self.handler.buf.clone();
        let mut input = MutInput::from(offsets, &base);
        let n = std::cmp::min(input.val_len() << 3, config::MAX_SEARCH_EXEC_NUM);
        for i in 0..n {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            input.bitflip(i);
            let mut buf = base.clone();
            input.write_to_input(offsets, &mut buf);
            self.handler.execute(&buf);
            input.bitflip(i);
        }
    }

    // For each dimension in the tainted region, try every AFL "interesting value" of the
    // matching width (0, 1, -1, INT_MAX-ish boundary values, ...) -- cheap, and the closest
    // thing to a numeric solver this fuzzer has for a hint no other input has ever matched.
    fn interesting_sweep(&mut self, offsets: &Vec<TagSeg>) {
        let base = self.handler.buf.clone();
        let mut input = MutInput::from(offsets, &base);
        for i in 0..input.len() {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let width = input.get_entry_len(i);
            let orig_v = input.get_entry(i);
            for &v in get_interesting_bytes(width).iter() {
                if self.handler.is_stopped_or_skip() {
                    break;
                }
                input.set(i, v);
                let mut buf = base.clone();
                input.write_to_input(offsets, &mut buf);
                self.handler.execute(&buf);
            }
            input.set(i, orig_v);
        }
    }
}
