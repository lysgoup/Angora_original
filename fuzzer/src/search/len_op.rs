// Folds the old len.rs: for a Len-kind hint (length-derived comparison, lb1/lb2 repurposed as
// read-offset/read-size per runtime/len_label.rs), grow or shrink the buffer by the delta
// needed to flip the comparison, plus a few common special-char terminators. Assumes the
// relationship is direct and linear, same as the original.
use super::*;

pub struct LenOp<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> LenOp<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    // `rotation_offset` (see search::rotated_hint_indices) picks which window of hints this
    // visit covers, so a target with more hints than MAX_HINTS_FOR_BUDGET_SCALING still gets
    // all of them covered across repeated visits instead of only ever the first window.
    pub fn run(&mut self, hints: &[TaintHint], rotation_offset: usize) {
        if !config::ENABLE_INPUT_LEN_EXPLORATION {
            return;
        }
        // hints.len() is capped (see MAX_HINTS_FOR_BUDGET_SCALING) -- same reasoning as
        // det.rs/reusing.rs.
        let scale = hints.len().max(1).min(config::MAX_HINTS_FOR_BUDGET_SCALING);
        self.handler.set_budget(16 * scale);
        for i in rotated_hint_indices(hints.len(), rotation_offset) {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let hint = &hints[i];
            if hint.kind != HintKind::Len {
                continue;
            }
            self.run_one(hint);
        }
    }

    fn run_one(&mut self, hint: &TaintHint) {
        let size = hint.lb2 as usize;
        let delta =
            crate::hint::get_output(hint.op, hint.condition, hint.size, hint.arg1, hint.arg2)
                as usize;
        if delta == 0 || size == 0 {
            return;
        }

        let extended_len = delta * size;
        if extended_len >= config::MAX_INPUT_LEN {
            return;
        }

        let base = self.handler.buf.clone();
        let buf_len = base.len();

        if buf_len + extended_len < config::MAX_INPUT_LEN {
            let mut buf = base.clone();
            let mut v = vec![0u8; extended_len + 1];
            rand::thread_rng().fill_bytes(&mut v);
            buf.append(&mut v);
            self.handler.execute(&buf); // len > X

            let special_chars = [0u8, 10, 13, 32]; // NUL, LF, CR, SPACE
            for &c in &special_chars {
                if self.handler.is_stopped_or_skip() {
                    break;
                }
                buf.push(c);
                self.handler.execute(&buf);
                buf.pop();
            }

            buf.pop();
            self.handler.execute(&buf); // len == X
        }

        if buf_len > extended_len {
            let mut buf = base.clone();
            buf.truncate(buf_len - extended_len);
            self.handler.execute(&buf); // len == X
            if buf_len > extended_len + 1 {
                buf.pop();
                self.handler.execute(&buf); // len < X
            }
        }
    }
}
