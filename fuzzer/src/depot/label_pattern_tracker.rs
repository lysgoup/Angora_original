// The reuse pool: caches critical byte values seen at tainted sites, keyed by the
// tainted-segment-length pattern, so a later hint with a matching pattern can try them before
// (or instead of) any cheaper deterministic/random guessing. This is the primary solving
// mechanism of this fuzzer -- always on, no opt-in flag (see docs/reusing.md for the design
// this was ported from).
use super::depot::Depot;
use crate::hint::{HintKind, TaintHint};
use crate::mut_input::offsets::merge_continuous_segments;
use angora_common::tag::TagSeg;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

pub type LabelPattern = Vec<u32>;

#[derive(Debug, Clone)]
pub struct HintRecord {
    // Not read by the reuse/combining logic itself (kind/is_eq_like are used to filter at
    // lookup time instead) -- kept so a value's origin can be traced for debugging/analysis.
    #[allow(dead_code)]
    pub cmpid: u32,
    #[allow(dead_code)]
    pub offsets: Vec<TagSeg>,
    pub kind: HintKind,
    pub is_eq_like: bool,
    pub critical_values: Vec<Vec<u8>>,
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
) {
    let mut map = label_pattern_map().lock().unwrap();

    if let Some(existing) = map.get(pattern) {
        // A duplicate only counts as such within the same kind/is_eq_like -- otherwise an
        // Exploit-kind (or `<`/`>`) hint that happens to share bytes with an already-stored
        // Explore/`==` record would silently never get its own record, and lookups filtering
        // for that other kind/is_eq_like would never see this value at all.
        if existing
            .iter()
            .any(|r| r.critical_values == *critical_values && r.kind == kind && r.is_eq_like == is_eq_like)
        {
            return;
        }
    }

    let record = HintRecord {
        cmpid,
        offsets: offsets.clone(),
        kind,
        is_eq_like,
        critical_values: critical_values.clone(),
    };
    map.entry(pattern.clone())
        .or_insert_with(Vec::new)
        .push(record);
}

fn add_for_offsets(offsets: &Vec<TagSeg>, hint: &TaintHint, input_buf: &Vec<u8>) {
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

    for hint in hints {
        if !hint.is_tainted() {
            continue;
        }
        let keep = |offsets: &Vec<TagSeg>| match &mutated {
            Some(m) => overlaps_mutated(offsets, m),
            None => true,
        };
        if keep(&hint.offsets) {
            add_for_offsets(&hint.offsets, hint, &input_buf);
        }
        if !hint.offsets_opt.is_empty() && keep(&hint.offsets_opt) {
            add_for_offsets(&hint.offsets_opt, hint, &input_buf);
        }
    }
}

pub fn get_stats() -> (usize, usize) {
    let map = label_pattern_map().lock().unwrap();
    let num_patterns = map.len();
    let num_records: usize = map.values().map(|v| v.len()).sum();
    (num_patterns, num_records)
}

// Hints don't persist a "how far through the pool have I gotten" cursor across dispatch
// rounds (they're rebuilt fresh each time an input is tracked, not long-lived like the old
// CondStmt), so instead of a monotonic cursor this samples a random contiguous window each
// call -- cheap way to avoid always retrying the same first `iterations` records on repeat
// visits to the same seed.
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
    let records: Vec<HintRecord> = all_records
        .iter()
        .filter(|r| r.kind == kind && r.is_eq_like == is_eq_like)
        .cloned()
        .collect();
    if records.is_empty() {
        return None;
    }

    let total = records.len();
    if total <= iterations {
        return Some(records);
    }

    let start = rand::thread_rng().gen_range(0, total - iterations + 1);
    Some(records[start..start + iterations].to_vec())
}

pub fn get_single_segment_pool(
    segment_size: u32,
    kind: HintKind,
    is_eq_like: bool,
) -> Vec<Vec<u8>> {
    let map = label_pattern_map().lock().unwrap();
    let single_pattern = vec![segment_size];
    map.get(&single_pattern)
        .map(|records| {
            records
                .iter()
                .filter(|r| r.kind == kind && r.is_eq_like == is_eq_like)
                .filter_map(|r| r.critical_values.first().cloned())
                .collect()
        })
        .unwrap_or_default()
}
