// The primary solving mechanism of this fuzzer. Ported from docs/reusing.md's design, but
// promoted from a GD preamble to the main strategy: for each of this seed's taint hints, look
// up the reuse pool (depot::label_pattern_tracker) by tainted-segment-length pattern and splat
// matching critical values -- no gradient descent, no per-branch distance tracking. Whether a
// candidate "worked" is entirely the executor's business (has_new_path/has_new_edge); this
// just fires off candidates.
use super::*;
use crate::depot::{
    extract_pattern, get_single_segment_pool, next_records, report_success, ReusingCursor,
};
use crate::mut_input::offsets::{merge_continuous_segments, merge_offsets};
use angora_common::tag::TagSeg;

pub struct ReusingFuzz<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> ReusingFuzz<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    // `cursors` is parallel to `hints` (same index, same length -- see depot::QueueEntry) and
    // persists across visits to this seed, so the same value is never re-applied to the same
    // hint offsets twice: this is a deterministic sweep through the pool, not a repeated random
    // sample of it.
    pub fn run(
        &mut self,
        hints: &[TaintHint],
        cursors: &mut Vec<ReusingCursor>,
        iterations: usize,
    ) {
        // Roughly: offsets + offsets_opt + combined-offsets + combined-offsets_opt, each up to
        // `iterations` executions per hint -- must call set_budget (not just rely on whatever
        // budget/skip state an earlier operator in this round left behind), otherwise this
        // "main" solver silently does nothing whenever it runs after an operator that already
        // exhausted its own budget (skip stays true from there). hints.len() is capped (see
        // MAX_HINTS_FOR_BUDGET_SCALING) so a target with hundreds/thousands of hints per input
        // can't blow this round's budget up to the point where AFL never gets a turn.
        let scale = hints.len().max(1).min(config::MAX_HINTS_FOR_BUDGET_SCALING);
        self.handler.set_budget(iterations * scale * 4);
        for (i, hint) in hints.iter().enumerate() {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !hint.is_tainted() {
                continue;
            }
            let is_eq_like = hint.is_eq_like();
            let cursor = cursors
                .get_mut(i)
                .expect("cursors must be parallel to hints");
            self.try_offsets(
                &hint.offsets,
                hint.kind,
                is_eq_like,
                &mut cursor.offsets,
                iterations,
            );
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !hint.offsets_opt.is_empty() {
                self.try_offsets(
                    &hint.offsets_opt,
                    hint.kind,
                    is_eq_like,
                    &mut cursor.offsets_opt,
                    iterations,
                );
                if self.handler.is_stopped_or_skip() {
                    break;
                }
                // Both operands together as one region (e.g. x's and y's taint combined for
                // `x == y`) -- a distinct pattern from either side alone, with its own
                // independent cursor, since it's a separate pool lookup.
                let merged = merge_offsets(&hint.offsets, &hint.offsets_opt);
                self.try_offsets(
                    &merged,
                    hint.kind,
                    is_eq_like,
                    &mut cursor.merged,
                    iterations,
                );
            }
        }

        if !self.handler.is_stopped_or_skip() {
            self.try_combined(hints, iterations);
        }
    }

    fn try_offsets(
        &mut self,
        offsets: &Vec<TagSeg>,
        kind: HintKind,
        is_eq_like: bool,
        cursor: &mut usize,
        iterations: usize,
    ) {
        let merged = merge_continuous_segments(offsets);
        let pattern = extract_pattern(&merged);
        if pattern.is_empty() {
            return;
        }
        let records = match next_records(&pattern, kind, is_eq_like, cursor, iterations) {
            Some(r) => r,
            None => return, // nothing past the cursor yet -- already tried everything the pool has for this hint
        };

        let base = self.handler.buf.clone();
        for record in records {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if let Some(buf) = splat(&merged, &record.critical_values, &base) {
                self.handler.execute(&buf);
                // This execution changed exactly one region (this record's value at this
                // hint's offsets), so a resulting new-coverage finding can be attributed to it
                // cleanly -- boost its confidence for AFL's reuse-splat to pick more often.
                if self.handler.executor.has_new_path {
                    report_success(&pattern, record.id);
                }
            }
        }
    }

    // Mixes critical values observed at *different* comparisons for multi-segment patterns --
    // e.g. segment 1's value came from one cmp, segment 2's from an unrelated one -- since the
    // exact combination may never have appeared together in any single input. Still randomized
    // (no cursor): a "combination" doesn't have a stable identity to dedupe against the way a
    // single pool record does. Restricted to same kind + same eq-like-ness as the consuming
    // hint, same as try_offsets.
    fn try_combined(&mut self, hints: &[TaintHint], iterations: usize) {
        for hint in hints {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let is_eq_like = hint.is_eq_like();
            self.try_combined_offsets(&hint.offsets, hint.kind, is_eq_like, iterations);
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !hint.offsets_opt.is_empty() {
                self.try_combined_offsets(&hint.offsets_opt, hint.kind, is_eq_like, iterations);
            }
        }
    }

    fn try_combined_offsets(
        &mut self,
        offsets: &Vec<TagSeg>,
        kind: HintKind,
        is_eq_like: bool,
        iterations: usize,
    ) {
        let merged = merge_continuous_segments(offsets);
        if merged.len() < 2 {
            return;
        }
        let pattern = extract_pattern(&merged);

        let pools: Vec<Vec<(u64, Vec<u8>)>> = pattern
            .iter()
            .map(|&size| get_single_segment_pool(size, kind, is_eq_like))
            .collect();
        if pools.iter().any(|p| p.is_empty()) {
            return;
        }

        let mut rng = rand::thread_rng();
        let base = self.handler.buf.clone();
        for _ in 0..iterations {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let chosen: Vec<&(u64, Vec<u8>)> = pools
                .iter()
                .filter_map(|pool| pool.choose(&mut rng))
                .collect();
            if chosen.len() != merged.len() {
                continue;
            }
            let values: Vec<Vec<u8>> = chosen.iter().map(|(_, v)| v.clone()).collect();
            if let Some(buf) = splat(&merged, &values, &base) {
                self.handler.execute(&buf);
                // Each segment's value came from its own single-segment pool record -- if the
                // combination as a whole found new coverage, credit all of them (we can't tell
                // which one mattered, but unlike AFL's stacked havoc, every byte that changed
                // here came from a pool value we're tracking, not an untracked random tweak).
                if self.handler.executor.has_new_path {
                    for (i, (id, _)) in chosen.iter().enumerate() {
                        report_success(&vec![pattern[i]], *id);
                    }
                }
            }
        }
    }
}

// Writes `values` (one slice per segment) into a clone of `base` at `merged`'s positions.
// Returns None if the candidate would be identical to base (not worth an execution) or the
// value count doesn't match the segment count.
fn splat(merged: &[TagSeg], values: &[Vec<u8>], base: &[u8]) -> Option<Vec<u8>> {
    if values.len() != merged.len() {
        return None;
    }
    if matches_original(merged, values, base) {
        return None;
    }

    let max_end = merged.iter().map(|s| s.end as usize).max().unwrap_or(0);
    let mut buf = base.to_vec();
    if max_end > buf.len() {
        buf.resize(max_end, 0);
    }
    for (seg, value) in merged.iter().zip(values.iter()) {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let copy_len = value.len().min(end - begin);
        buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
    }
    Some(buf)
}

// pub(crate): also used by search/afl.rs's reuse_splat, for the same reason -- no point
// executing a candidate that's byte-for-byte identical to what's already there.
pub(crate) fn matches_original(merged: &[TagSeg], values: &[Vec<u8>], base: &[u8]) -> bool {
    merged.iter().zip(values.iter()).all(|(seg, value)| {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        end <= base.len() && &base[begin..end] == value.as_slice()
    })
}
