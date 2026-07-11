// The reuse pool: caches critical byte values seen at tainted sites, keyed by the
// tainted-segment-length pattern, so a later hint with a matching pattern can try them before
// (or instead of) any cheaper deterministic/random guessing. This is the primary solving
// mechanism of this fuzzer -- always on, no opt-in flag (see docs/reusing.md for the design
// this was ported from).
use super::depot::Depot;
use crate::hint::{HintKind, TaintHint};
use crate::mut_input::offsets::{merge_continuous_segments, merge_offsets};
use angora_common::tag::TagSeg;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub type LabelPattern = Vec<u32>;

#[derive(Debug, Clone)]
pub struct HintRecord {
    pub id: u64,
    // Not read by the reuse/combining logic itself (kind/is_eq_like are used to filter at
    // lookup time instead) -- kept so a value's origin can be traced for debugging/analysis.
    #[allow(dead_code)]
    pub cmpid: u32,
    #[allow(dead_code)]
    pub offsets: Vec<TagSeg>,
    pub kind: HintKind,
    pub is_eq_like: bool,
    pub critical_values: Vec<Vec<u8>>,
    // How many bytes differed from the parent input when this value was captured -- a cheap
    // proxy for how many independent things changed at once (AFL's stacked havoc can flip up
    // to 256 bytes in one candidate, while Det/Reusing/MagicBytes/LenOp change exactly one
    // region), so a lower diff_size is a better bet that *this* region specifically caused the
    // new coverage rather than some other byte AFL happened to also flip. 0 for seeds with no
    // parent to diff against (dry-run/AFL-synced), deliberately the best possible score.
    pub diff_size: usize,
    // Bumped each time this exact record is reused by ReusingFuzz (which changes only one
    // region per execution, so success can be attributed cleanly) and the resulting candidate
    // finds new coverage. Never touched by AFL's havoc reuse-splat -- see search/afl.rs.
    pub success_count: u64,
}

fn next_record_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

// Used only to bias AFL's reuse-splat pick (search/afl.rs via sample_records) towards records
// more likely to have actually caused the coverage that got them stored -- never to exclude
// anything. ReusingFuzz's own sweep (next_records) ignores this entirely and stays a plain
// sequential walk through the pool, so it isn't affected by success_count changing over time.
fn confidence(r: &HintRecord) -> f64 {
    1.0 / (1.0 + r.diff_size as f64) + r.success_count as f64
}

pub fn label_pattern_map() -> &'static Mutex<HashMap<LabelPattern, Vec<HintRecord>>> {
    static MAP: OnceLock<Mutex<HashMap<LabelPattern, Vec<HintRecord>>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn extract_pattern(offsets: &Vec<TagSeg>) -> LabelPattern {
    offsets.iter().map(|seg| seg.end - seg.begin).collect()
}

// Extracts one critical-value slice per (already merged) segment from input_buf.
fn extract_value_from_merged(merged_offsets: &Vec<TagSeg>, input_buf: &Vec<u8>) -> Vec<Vec<u8>> {
    let mut critical_values = Vec::new();

    for seg in merged_offsets {
        let begin = seg.begin as usize;
        let end = seg.end as usize;

        if end <= input_buf.len() {
            critical_values.push(input_buf[begin..end].to_vec());
        } else if begin < input_buf.len() {
            let mut bytes = input_buf[begin..].to_vec();
            bytes.resize(end - begin, 0);
            critical_values.push(bytes);
        } else {
            critical_values.push(vec![0u8; end - begin]);
        }
    }

    critical_values
}

fn create_record(
    pattern: &LabelPattern,
    offsets: &Vec<TagSeg>,
    critical_values: &Vec<Vec<u8>>,
    cmpid: u32,
    kind: HintKind,
    is_eq_like: bool,
    diff_size: usize,
) {
    let mut map = label_pattern_map().lock().unwrap();

    if let Some(existing) = map.get(pattern) {
        // A duplicate only counts as such within the same kind/is_eq_like -- otherwise an
        // Exploit-kind (or `<`/`>`) hint that happens to share bytes with an already-stored
        // Explore/`==` record would silently never get its own record, and lookups filtering
        // for that other kind/is_eq_like would never see this value at all.
        if existing.iter().any(|r| {
            r.critical_values == *critical_values && r.kind == kind && r.is_eq_like == is_eq_like
        }) {
            return;
        }
    }

    let record = HintRecord {
        id: next_record_id(),
        cmpid,
        offsets: offsets.clone(),
        kind,
        is_eq_like,
        critical_values: critical_values.clone(),
        diff_size,
        success_count: 0,
    };
    map.entry(pattern.clone())
        .or_insert_with(Vec::new)
        .push(record);
}

fn add_for_offsets(offsets: &Vec<TagSeg>, hint: &TaintHint, input_buf: &Vec<u8>, diff_size: usize) {
    if offsets.is_empty() {
        return;
    }

    let merged_offsets = merge_continuous_segments(offsets);
    let pattern = extract_pattern(&merged_offsets);
    let critical_values = extract_value_from_merged(&merged_offsets, input_buf);
    let is_eq_like = hint.is_eq_like();

    // 1) whole-pattern record
    create_record(
        &pattern,
        offsets,
        &critical_values,
        hint.cmpid,
        hint.kind,
        is_eq_like,
        diff_size,
    );

    // 2) if the pattern has 2+ segments, also record each segment under its own single-segment
    //    pattern -- this is what lets try_combined_segments mix values that were never actually
    //    observed together in the same input.
    if merged_offsets.len() > 1 {
        for i in 0..merged_offsets.len() {
            let single_segment = vec![merged_offsets[i]];
            let single_pattern = vec![merged_offsets[i].end - merged_offsets[i].begin];
            let single_values = vec![critical_values[i].clone()];
            create_record(
                &single_pattern,
                &single_segment,
                &single_values,
                hint.cmpid,
                hint.kind,
                is_eq_like,
                diff_size,
            );
        }
    }
}

// Byte indices where `new_buf` differs from `parent`, plus (if lengths differ) the whole
// tail past the shorter one -- an insert/delete changed that region too, even though there's
// no matching byte in `parent` to compare against.
fn diff_offsets(parent: &[u8], new_buf: &[u8]) -> HashSet<u32> {
    let common = parent.len().min(new_buf.len());
    let mut mutated: HashSet<u32> = (0..common as u32)
        .filter(|&i| parent[i as usize] != new_buf[i as usize])
        .collect();
    mutated.extend(common as u32..new_buf.len() as u32);
    mutated
}

fn overlaps_mutated(offsets: &Vec<TagSeg>, mutated: &HashSet<u32>) -> bool {
    offsets
        .iter()
        .any(|seg| (seg.begin..seg.end).any(|o| mutated.contains(&o)))
}

// Called once, right when a freshly-tracked input's hints are attached to its queue entry.
// Rather than caching every hint this input happens to carry, only hints whose tainted bytes
// actually changed relative to the parent seed get their values recorded -- a hint whose
// region is untouched by this mutation isn't telling us anything new about what caused this
// input to be interesting. With no parent (raw/dry-run/AFL-synced seed), there's nothing to
// diff against, so every hint is cached.
pub fn add_hints_to_pattern_map(
    hints: &[TaintHint],
    depot: &Depot,
    input_id: usize,
    parent_buf: Option<&[u8]>,
) {
    let input_buf = depot.get_input_buf(input_id);
    let mutated = parent_buf.map(|parent| diff_offsets(parent, &input_buf));
    // Used as this batch's records' initial confidence (see HintRecord::diff_size) -- how many
    // bytes changed in total to produce this input, regardless of which hint's region we're
    // storing right now. A seed with no parent gets 0 (best possible score).
    let diff_size = mutated.as_ref().map(|m| m.len()).unwrap_or(0);

    for hint in hints {
        if !hint.is_tainted() {
            continue;
        }
        let keep = |offsets: &Vec<TagSeg>| match &mutated {
            Some(m) => overlaps_mutated(offsets, m),
            None => true,
        };
        let offsets_kept = keep(&hint.offsets);
        if offsets_kept {
            add_for_offsets(&hint.offsets, hint, &input_buf, diff_size);
        }
        let offsets_opt_kept = !hint.offsets_opt.is_empty() && keep(&hint.offsets_opt);
        if offsets_opt_kept {
            add_for_offsets(&hint.offsets_opt, hint, &input_buf, diff_size);
        }
        // Both operands together as one region -- matches search/reusing.rs's merged-cursor
        // lookup, which would otherwise never find anything (nothing else stores under the
        // merged pattern's key). Kept if either side individually would have been.
        if !hint.offsets_opt.is_empty() && (offsets_kept || offsets_opt_kept) {
            let merged = merge_offsets(&hint.offsets, &hint.offsets_opt);
            add_for_offsets(&merged, hint, &input_buf, diff_size);
        }
    }
}

// Called by ReusingFuzz right after a splat it applied leads to new coverage (has_new_path) --
// boosts that exact record's confidence so AFL's confidence-weighted reuse-splat picks it more
// often (see search/afl.rs::sample_records / confidence above). Not called for AFL's own
// reuse-splat: havoc stacks many simultaneous changes per execution, so there's no way to
// attribute a success to any one of them without repeating the false-attribution problem this
// whole confidence signal exists to avoid.
pub fn report_success(pattern: &LabelPattern, record_id: u64) {
    let mut map = label_pattern_map().lock().unwrap();
    if let Some(records) = map.get_mut(pattern) {
        if let Some(r) = records.iter_mut().find(|r| r.id == record_id) {
            r.success_count += 1;
        }
    }
}

pub fn get_stats() -> (usize, usize) {
    let map = label_pattern_map().lock().unwrap();
    let num_patterns = map.len();
    let num_records: usize = map.values().map(|v| v.len()).sum();
    (num_patterns, num_records)
}

// Confidence-weighted counterpart to next_records, for the one-shot havoc-splat choice in
// search/afl.rs (search/reusing.rs's main sweep uses the cursor-based next_records instead,
// which stays a plain sequential walk -- see next_records' doc comment for why). A single
// random havoc pick doesn't have a stable "this exact hint, this exact visit" identity worth
// persisting a cursor for, so every call is a fresh weighted draw: records with a lower
// diff_size (fewer simultaneous byte changes when captured) or a higher success_count (this
// exact value has previously led ReusingFuzz to new coverage) are picked more often, but
// nothing is ever excluded outright.
//
// Only records whose `kind`/`is_eq_like` match the *consuming* hint are eligible: reusing a
// value across two comparisons only makes sense if they're asking a similar kind of question
// (e.g. don't let an Exploit hint's deliberately-extreme sacrificial value leak into an
// Explore hint's search, and don't let a `<`/`>` threshold masquerade as a `==` magic
// constant). See the design discussion this restricts -- cmpid itself carries no such
// signal (it's just a per-callsite id), so it isn't part of the filter.
pub fn sample_records(
    pattern: &LabelPattern,
    kind: HintKind,
    is_eq_like: bool,
    iterations: usize,
) -> Option<Vec<HintRecord>> {
    use rand::Rng;
    let map = label_pattern_map().lock().unwrap();
    let all_records = map.get(pattern)?;
    let mut candidates: Vec<HintRecord> = all_records
        .iter()
        .filter(|r| r.kind == kind && r.is_eq_like == is_eq_like)
        .cloned()
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() <= iterations {
        return Some(candidates);
    }

    let mut rng = rand::thread_rng();
    let mut selected = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let total_weight: f64 = candidates.iter().map(confidence).sum();
        let mut r = rng.gen_range(0.0, total_weight);
        let mut pick_idx = candidates.len() - 1;
        for (i, c) in candidates.iter().enumerate() {
            r -= confidence(c);
            if r <= 0.0 {
                pick_idx = i;
                break;
            }
        }
        selected.push(candidates.remove(pick_idx));
    }
    Some(selected)
}

// Deterministic counterpart to sample_records, for ReusingFuzz's main sweep (try_offsets):
// applying the exact same value to the exact same hint offsets twice is never useful, so this
// takes a persistent per-(input, hint) cursor (see depot::ReusingCursor) and only ever returns
// records past it, then advances it. The pool's Vec<HintRecord> for a given key is append-only
// (create_record only pushes), and filtering-then-indexing preserves relative order regardless
// of what unrelated (non-matching) records get appended in between, so an index into the
// *filtered* list stays valid as the pool grows -- new matching records only ever appear past
// wherever the cursor already reached.
pub fn next_records(
    pattern: &LabelPattern,
    kind: HintKind,
    is_eq_like: bool,
    cursor: &mut usize,
    iterations: usize,
) -> Option<Vec<HintRecord>> {
    let map = label_pattern_map().lock().unwrap();
    let all_records = map.get(pattern)?;
    let matching: Vec<&HintRecord> = all_records
        .iter()
        .filter(|r| r.kind == kind && r.is_eq_like == is_eq_like)
        .collect();

    let total = matching.len();
    let start = *cursor;
    if start >= total {
        return None;
    }

    let end = (start + iterations).min(total);
    *cursor = end;
    Some(matching[start..end].iter().map(|r| (*r).clone()).collect())
}

// Returns (record id, value) pairs rather than bare values so a caller combining values across
// segments (search/reusing.rs::try_combined_offsets) can report success back against the exact
// records it drew from.
pub fn get_single_segment_pool(
    segment_size: u32,
    kind: HintKind,
    is_eq_like: bool,
) -> Vec<(u64, Vec<u8>)> {
    let map = label_pattern_map().lock().unwrap();
    let single_pattern = vec![segment_size];
    map.get(&single_pattern)
        .map(|records| {
            records
                .iter()
                .filter(|r| r.kind == kind && r.is_eq_like == is_eq_like)
                .filter_map(|r| r.critical_values.first().cloned().map(|v| (r.id, v)))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // label_pattern_map() is one process-wide singleton, shared by every test in this binary
    // (which may run concurrently) -- each test below uses a segment size unique to itself so
    // its pattern key can never collide with another test's.

    fn seg(begin: u32, end: u32) -> TagSeg {
        TagSeg {
            sign: false,
            begin,
            end,
        }
    }

    #[test]
    fn next_records_ignores_confidence_stays_insertion_order() {
        let pattern = vec![91001u32];
        create_record(
            &pattern,
            &vec![seg(0, 91001)],
            &vec![vec![1u8]],
            1,
            HintKind::Explore,
            true,
            50, // high diff_size -> low initial confidence
        );
        create_record(
            &pattern,
            &vec![seg(0, 91001)],
            &vec![vec![2u8]],
            2,
            HintKind::Explore,
            true,
            0, // low diff_size -> high initial confidence
        );

        // Give the second (high-confidence) record a success boost too -- next_records must
        // still return them in plain insertion order, since ReusingFuzz's sweep is a fixed
        // sequential walk that never reorders on confidence.
        report_success(&pattern, 2);

        let mut cursor = 0usize;
        let first =
            next_records(&pattern, HintKind::Explore, true, &mut cursor, 1).expect("first record");
        assert_eq!(first[0].critical_values, vec![vec![1u8]]);
        let second =
            next_records(&pattern, HintKind::Explore, true, &mut cursor, 1).expect("second record");
        assert_eq!(second[0].critical_values, vec![vec![2u8]]);
        assert!(next_records(&pattern, HintKind::Explore, true, &mut cursor, 1).is_none());
    }

    #[test]
    fn report_success_only_bumps_the_matching_record() {
        let pattern = vec![91002u32];
        create_record(
            &pattern,
            &vec![seg(0, 91002)],
            &vec![vec![10u8]],
            1,
            HintKind::Explore,
            true,
            0,
        );
        create_record(
            &pattern,
            &vec![seg(0, 91002)],
            &vec![vec![20u8]],
            2,
            HintKind::Explore,
            true,
            0,
        );

        let mut cursor = 0usize;
        let records = next_records(&pattern, HintKind::Explore, true, &mut cursor, 2).unwrap();
        let target_id = records[0].id;
        let other_id = records[1].id;

        report_success(&pattern, target_id);
        report_success(&pattern, target_id);

        let map = label_pattern_map().lock().unwrap();
        let stored = map.get(&pattern).unwrap();
        let target = stored.iter().find(|r| r.id == target_id).unwrap();
        let other = stored.iter().find(|r| r.id == other_id).unwrap();
        assert_eq!(target.success_count, 2);
        assert_eq!(other.success_count, 0);
    }

    #[test]
    fn sample_records_favors_higher_confidence() {
        let pattern = vec![91003u32];
        create_record(
            &pattern,
            &vec![seg(0, 91003)],
            &vec![vec![1u8]],
            1,
            HintKind::Explore,
            true,
            0,
        );
        create_record(
            &pattern,
            &vec![seg(0, 91003)],
            &vec![vec![2u8]],
            2,
            HintKind::Explore,
            true,
            0,
        );

        let (low_id, high_id) = {
            let map = label_pattern_map().lock().unwrap();
            let stored = map.get(&pattern).unwrap();
            let low = stored
                .iter()
                .find(|r| r.critical_values == vec![vec![1u8]])
                .unwrap()
                .id;
            let high = stored
                .iter()
                .find(|r| r.critical_values == vec![vec![2u8]])
                .unwrap()
                .id;
            (low, high)
        };
        // Give the second record a large success-count lead so its confidence overwhelmingly
        // dominates the first (which starts with a merely-average diff_size-only confidence).
        for _ in 0..50 {
            report_success(&pattern, high_id);
        }

        let mut high_picks = 0;
        for _ in 0..200 {
            let picked = sample_records(&pattern, HintKind::Explore, true, 1).unwrap();
            if picked[0].id == high_id {
                high_picks += 1;
            }
        }
        assert!(
            high_picks > 180,
            "expected the high-confidence record to dominate the weighted draw, got {}/200",
            high_picks
        );
        let _ = low_id;
    }
}
