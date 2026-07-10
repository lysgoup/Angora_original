// Builds Vec<TaintHint> from a taint-tracking run's LogData -- the input-based-queue
// replacement for track::fparser's read_and_parse + get_offsets_and_variables, and
// track::filter's filter_cond_list. Undesirable hints (no taint, duplicate, malformed) are
// dropped outright here instead of being kept-but-flagged (there is no priority queue entry
// for a hint to linger in anymore -- it either becomes mutation guidance for this seed or it
// doesn't exist).
use super::hint::TaintHint;
use crate::mut_input;
use angora_common::{config, defs, log_data::LogData, tag::TagSeg};
use std::collections::{HashMap, HashSet};

pub fn build_hints(log_data: &LogData, enable_exploitation: bool) -> Vec<TaintHint> {
    let mut hints = Vec::new();

    for (i, cond_base) in log_data.cond_list.iter().enumerate() {
        if !enable_exploitation && cond_base.is_exploitable() {
            continue;
        }
        let mut hint = match TaintHint::from_base(cond_base) {
            Some(h) => h,
            None => continue, // AFL / unrecognized op -- not represented as a hint
        };
        if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
            set_offsets_and_variables(&log_data.tags, &mut hint, log_data.magic_bytes.get(&i));
        }
        hints.push(hint);
    }

    filter_hints(hints)
}

fn set_offsets_and_variables(
    tags: &HashMap<u32, Vec<TagSeg>>,
    hint: &mut TaintHint,
    magic_bytes: Option<&(Vec<u8>, Vec<u8>)>,
) {
    let empty_offsets: Vec<TagSeg> = vec![];
    let offsets1 = tags.get(&hint.lb1).unwrap_or(&empty_offsets);
    let offsets2 = tags.get(&hint.lb2).unwrap_or(&empty_offsets);
    if offsets2.is_empty() || (!offsets1.is_empty() && offsets1.len() <= offsets2.len()) {
        hint.offsets = offsets1.clone();
        if hint.lb2 > 0 && hint.lb1 != hint.lb2 {
            hint.offsets_opt = offsets2.clone();
        }
        hint.variables = if let Some(args) = magic_bytes {
            [&args.1[..], &args.0[..]].concat()
        } else {
            // integer comparison: use the constant operand's bytes as the magic value
            mut_input::write_as_ule(hint.arg2, hint.size as usize)
        };
    } else {
        hint.offsets = offsets2.clone();
        if hint.lb1 > 0 && hint.lb1 != hint.lb2 {
            hint.offsets_opt = offsets1.clone();
        }
        hint.variables = if let Some(args) = magic_bytes {
            [&args.0[..], &args.1[..]].concat()
        } else {
            mut_input::write_as_ule(hint.arg1, hint.size as usize)
        };
    }
}

#[derive(PartialEq, Eq, Hash)]
struct HintArgs {
    cmpid: u32,
    lb1: u32,
    lb2: u32,
    arg1: u64,
    arg2: u64,
}

impl HintArgs {
    fn from(hint: &TaintHint) -> Self {
        Self {
            cmpid: hint.cmpid,
            lb1: hint.lb1,
            lb2: hint.lb2,
            arg1: hint.arg1,
            arg2: hint.arg2,
        }
    }
}

fn has_no_taint(hint: &TaintHint) -> bool {
    hint.op != defs::COND_LEN_OP && hint.offsets.is_empty()
}

fn exceed_max_order(hint: &TaintHint) -> bool {
    (hint.order & 0xFFFF) > config::MAX_COND_ORDER
}

fn size_not_match(hint: &TaintHint) -> bool {
    use super::hint::HintKind;
    matches!(hint.kind, HintKind::Explore | HintKind::Exploit)
        && hint.size != 1
        && hint.size != 2
        && hint.size != 4
        && hint.size != 8
}

fn is_eof_sentinel(hint: &TaintHint) -> bool {
    hint.op & 0xFF == defs::COND_ICMP_EQ_OP
        && hint.arg2 == 18446744073709551615
        && hint.offsets.len() == 1
        && hint.arg1 < 256
        && hint.size == 4
}

fn filter_hints(hints: Vec<TaintHint>) -> Vec<TaintHint> {
    use super::hint::HintKind;

    let mut exploitable_labels = HashSet::new();
    let mut unique_hints = HashSet::new();
    let mut kept = Vec::with_capacity(hints.len());

    for hint in hints {
        if has_no_taint(&hint)
            || exceed_max_order(&hint)
            || size_not_match(&hint)
            || is_eof_sentinel(&hint)
        {
            continue;
        }

        match hint.kind {
            HintKind::Exploit => {
                // De-dup by taint label: we just want to try extreme/interesting values at
                // each distinct tainted site once, not once per dynamic occurrence.
                if exploitable_labels.contains(&hint.lb1) {
                    continue;
                }
                exploitable_labels.insert(hint.lb1);
            },
            HintKind::Explore | HintKind::Len => {
                // Different context/order but same cmpid+args+labels -> same underlying value
                // comparison, keep only one.
                let args = HintArgs::from(&hint);
                if unique_hints.contains(&args) {
                    continue;
                }
                unique_hints.insert(args);
            },
            HintKind::CmpFn => {},
        }

        kept.push(hint);
    }

    kept
}
