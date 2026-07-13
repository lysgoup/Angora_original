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
    // hint offsets twice.
    //
    // One "pick" = choose a hint at random, then try exactly one not-yet-tried value for it,
    // cascading through offsets -> offsets_opt -> merged -> combined (the first tier that still
    // has something untried wins); repeat picks until the budget (set_budget below, so the
    // usual success bonus in SearchHandler::process_status still extends it) runs out. This
    // replaces the old fixed `iterations`-per-hint sweep so total real executions are bounded
    // by max_times alone, not by hints.len().
    //
    // A pick that finds nothing to try anywhere (empty/exhausted pool for that hint) never
    // calls execute(), so it doesn't count against max_times at all -- without a separate
    // guard, a seed whose hints all have empty/exhausted pools would spin here forever (num_exec
    // never advances, so is_stopped_or_skip() never trips). miss_limit is that guard: give up
    // once this many consecutive picks in a row found nothing, since that's a strong signal
    // there's nothing left in the pool for any of this seed's hints right now.
    //
    // The opposite failure mode also needs a guard: SearchHandler's success bonus adds
    // BONUS_EXEC_NUM to max_times on *every* new-coverage find, from any operator. If this
    // loop's own hit rate is high enough (easily true when many hints share one pool bucket --
    // e.g. a target with hundreds of same-width comparisons -- so cross-hint value swaps keep
    // finding "new" coverage), max_times can be pushed outward faster than num_exec catches up,
    // so the loop would never naturally terminate. own_exec_limit is a hard ceiling on this
    // call's own execute() count, independent of how far bonuses have pushed max_times out --
    // generous enough to let a genuinely productive visit run well past the base budget, but
    // never unbounded.
    pub fn run(&mut self, hints: &[TaintHint], cursors: &mut Vec<ReusingCursor>) {
        if hints.is_empty() {
            return;
        }
        self.handler.set_budget(config::MAX_SEARCH_EXEC_NUM);

        let mut rng = rand::thread_rng();
        let miss_limit = hints.len() * 4;
        let mut misses = 0usize;
        let own_exec_limit = config::MAX_SEARCH_EXEC_NUM * 20;
        let mut own_execs = 0usize;
        while !self.handler.is_stopped_or_skip() {
            if misses >= miss_limit || own_execs >= own_exec_limit {
                break;
            }
            let i = rng.gen_range(0, hints.len());
            let hint = &hints[i];
            if !hint.is_tainted() {
                misses += 1;
                continue;
            }
            let is_eq_like = hint.is_eq_like();
            let cursor = cursors
                .get_mut(i)
                .expect("cursors must be parallel to hints");

            let hit = self.try_one(&hint.offsets, hint.kind, is_eq_like, &mut cursor.offsets)
                || (!hint.offsets_opt.is_empty()
                    && (self.try_one(
                        &hint.offsets_opt,
                        hint.kind,
                        is_eq_like,
                        &mut cursor.offsets_opt,
                    ) || self.try_one(
                        &merge_offsets(&hint.offsets, &hint.offsets_opt),
                        hint.kind,
                        is_eq_like,
                        &mut cursor.merged,
                    )))
                || self.try_combined_once(hint);

            if hit {
                misses = 0;
                own_execs += 1;
            } else {
                misses += 1;
            }
        }
    }

    // Tries exactly the next not-yet-tried pool record for `offsets` (via `cursor`). Returns
    // whether an execution actually happened -- false means either the pool has nothing past
    // the cursor, or the next value happens to match what's already in the buffer (splat then
    // skips it as not worth an execution); either way the caller should fall through to the
    // next tier.
    fn try_one(
        &mut self,
        offsets: &Vec<TagSeg>,
        kind: HintKind,
        is_eq_like: bool,
        cursor: &mut usize,
    ) -> bool {
        let merged = merge_continuous_segments(offsets);
        let pattern = extract_pattern(&merged);
        if pattern.is_empty() {
            return false;
        }
        let record = match next_records(&pattern, kind, is_eq_like, cursor, 1) {
            Some(mut r) => match r.pop() {
                Some(record) => record,
                None => return false,
            },
            None => return false, // nothing past the cursor yet
        };

        let base = self.handler.buf.clone();
        if let Some(buf) = splat(&merged, &record.critical_values, &base) {
            self.handler.execute(&buf);
            // This execution changed exactly one region (this record's value at this hint's
            // offsets), so a resulting new-coverage finding can be attributed to it cleanly --
            // boost its confidence for AFL's reuse-splat to pick more often.
            if self.handler.executor.has_new_path {
                report_success(&pattern, record.id);
            }
            true
        } else {
            false
        }
    }

    // Mixes critical values observed at *different* comparisons for multi-segment patterns --
    // e.g. segment 1's value came from one cmp, segment 2's from an unrelated one -- since the
    // exact combination may never have appeared together in any single input. No cursor: a
    // combination doesn't have a stable identity to dedupe against the way a single pool record
    // does, so this is always a fresh random draw, tried for `offsets` first and then
    // `offsets_opt` if the first didn't produce anything.
    fn try_combined_once(&mut self, hint: &TaintHint) -> bool {
        let is_eq_like = hint.is_eq_like();
        if self.try_combined_one(&hint.offsets, hint.kind, is_eq_like) {
            return true;
        }
        !hint.offsets_opt.is_empty()
            && self.try_combined_one(&hint.offsets_opt, hint.kind, is_eq_like)
    }

    fn try_combined_one(
        &mut self,
        offsets: &Vec<TagSeg>,
        kind: HintKind,
        is_eq_like: bool,
    ) -> bool {
        let merged = merge_continuous_segments(offsets);
        if merged.len() < 2 {
            return false;
        }
        let pattern = extract_pattern(&merged);

        let pools: Vec<Vec<(u64, Vec<u8>)>> = pattern
            .iter()
            .map(|&size| get_single_segment_pool(size, kind, is_eq_like))
            .collect();
        if pools.iter().any(|p| p.is_empty()) {
            return false;
        }

        let mut rng = rand::thread_rng();
        let base = self.handler.buf.clone();
        let chosen: Vec<&(u64, Vec<u8>)> = pools
            .iter()
            .filter_map(|pool| pool.choose(&mut rng))
            .collect();
        if chosen.len() != merged.len() {
            return false;
        }
        let values: Vec<Vec<u8>> = chosen.iter().map(|(_, v)| v.clone()).collect();
        if let Some(buf) = splat(&merged, &values, &base) {
            self.handler.execute(&buf);
            // Each segment's value came from its own single-segment pool record -- if the
            // combination as a whole found new coverage, credit all of them (we can't tell
            // which one mattered, but unlike AFL's stacked havoc, every byte that changed here
            // came from a pool value we're tracking, not an untracked random tweak).
            if self.handler.executor.has_new_path {
                for (i, (id, _)) in chosen.iter().enumerate() {
                    report_success(&vec![pattern[i]], *id);
                }
            }
            true
        } else {
            false
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
