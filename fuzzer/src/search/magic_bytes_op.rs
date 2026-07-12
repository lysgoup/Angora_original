// Folds the old cmpfn.rs: for a CmpFn-kind hint (strcmp/memcmp-style comparison function),
// resizes the tainted region to the recorded magic-byte length and writes those bytes in
// directly. Simpler than the original's diff-correction arithmetic between two encoded magic
// values -- just try the literal recorded value.
use super::*;

pub struct MagicBytesOp<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> MagicBytesOp<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    // `rotation_offset` (see search::rotated_hint_indices) picks which window of hints this
    // visit covers, so a target with more hints than MAX_HINTS_FOR_BUDGET_SCALING still gets
    // all of them covered across repeated visits instead of only ever the first window.
    pub fn run(&mut self, hints: &[TaintHint], rotation_offset: usize) {
        // hints.len() is capped (see MAX_HINTS_FOR_BUDGET_SCALING) -- same reasoning as
        // det.rs/reusing.rs.
        let scale = hints.len().max(1).min(config::MAX_HINTS_FOR_BUDGET_SCALING);
        self.handler.set_budget(scale);
        for i in rotated_hint_indices(hints.len(), rotation_offset) {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let hint = &hints[i];
            if hint.kind != HintKind::CmpFn || hint.offsets.is_empty() || hint.variables.is_empty()
            {
                continue;
            }
            self.run_one(hint);
        }
    }

    fn run_one(&mut self, hint: &TaintHint) {
        let offsets = &hint.offsets;
        let begin = offsets[0].begin as usize;
        let cur_end = offsets.last().unwrap().end as usize;
        let want_len = hint.variables.len();

        let mut buf = self.handler.buf.clone();
        if cur_end > buf.len() {
            buf.resize(cur_end, 0);
        }
        let cur_len = cur_end.saturating_sub(begin);

        if want_len > cur_len {
            let filler = if cur_end > begin { buf[begin] } else { 0 };
            for _ in 0..(want_len - cur_len) {
                buf.insert(begin, filler);
            }
        } else if want_len < cur_len {
            for _ in 0..(cur_len - want_len) {
                if begin < buf.len() {
                    buf.remove(begin);
                }
            }
        }

        let end = begin + want_len;
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[begin..end].copy_from_slice(&hint.variables);

        self.handler.execute(&buf);
    }
}
