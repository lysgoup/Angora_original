// The primary solving mechanism of this fuzzer. Ported from docs/reusing.md's design, but
// promoted from a GD preamble to the main strategy: for each of this seed's taint hints, look
// up the reuse pool (depot::label_pattern_tracker) by tainted-segment-length pattern and splat
// matching critical values -- no gradient descent, no per-branch distance tracking. Whether a
// candidate "worked" is entirely the executor's business (has_new_path/has_new_edge); this
// just fires off candidates.
use super::*;
use crate::depot::{extract_pattern, get_single_segment_pool, sample_records};
use crate::mut_input::offsets::merge_continuous_segments;
use angora_common::tag::TagSeg;

pub struct ReusingFuzz<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> ReusingFuzz<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run(&mut self, hints: &[TaintHint], iterations: usize) {
        for hint in hints {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !hint.is_tainted() {
                continue;
            }
            let is_eq_like = hint.is_eq_like();
            self.try_offsets(&hint.offsets, hint.kind, is_eq_like, iterations);
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !hint.offsets_opt.is_empty() {
                self.try_offsets(&hint.offsets_opt, hint.kind, is_eq_like, iterations);
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
        iterations: usize,
    ) {
        let merged = merge_continuous_segments(offsets);
        let pattern = extract_pattern(&merged);
        if pattern.is_empty() {
            return;
        }
        let records = match sample_records(&pattern, kind, is_eq_like, iterations) {
            Some(r) => r,
            None => return,
        };

        let base = self.handler.buf.clone();
        for record in records {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if let Some(buf) = splat(&merged, &record.critical_values, &base) {
                self.handler.execute(&buf);
            }
        }
    }

    // Mixes critical values observed at *different* comparisons for multi-segment patterns --
    // e.g. segment 1's value came from one cmp, segment 2's from an unrelated one -- since the
    // exact combination may never have appeared together in any single input. Restricted to
    // same kind + same eq-like-ness as the consuming hint, same as try_offsets.
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

        let pools: Vec<Vec<Vec<u8>>> = pattern
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
            let values: Vec<Vec<u8>> = pools
                .iter()
                .filter_map(|pool| pool.choose(&mut rng).cloned())
                .collect();
            if values.len() != merged.len() {
                continue;
            }
            if let Some(buf) = splat(&merged, &values, &base) {
                self.handler.execute(&buf);
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

fn matches_original(merged: &[TagSeg], values: &[Vec<u8>], base: &[u8]) -> bool {
    merged.iter().zip(values.iter()).all(|(seg, value)| {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        end <= base.len() && &base[begin..end] == value.as_slice()
    })
}
