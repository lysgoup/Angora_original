// Modify input randomly like AFL.
// All the byte offsets in the input is the input.
// Random pick offsets, then flip, add/sub ..
// And GE algorithm.
// Plus one extra havoc choice: splat a reuse-pool value at one of this seed's own tainted
// regions, so the classic AFL mutation engine benefits from the reuse pool too, not just
// ReusingFuzz.

use super::*;
use crate::depot::{extract_pattern, sample_records};
use crate::mut_input::offsets::merge_continuous_segments;
use angora_common::tag::TagSeg;
use rand::{self, distributions::Uniform, rngs::ThreadRng, Rng};

static IDX_TO_SIZE: [usize; 4] = [1, 2, 4, 8];

// One tainted region this seed carries, plus the kind/eq-ness of the hint it came from --
// needed so the reuse-splat havoc choice only pulls values recorded under a matching
// kind/eq-ness (see depot::label_pattern_tracker::sample_records).
struct OffsetGroup {
    kind: HintKind,
    is_eq_like: bool,
    offsets: Vec<TagSeg>,
}

pub struct AFLFuzz<'a, 'b> {
    handler: &'b mut SearchHandler<'a>,
    run_ratio: usize,
    // One entry per hint's offsets, and (separately) per hint's offsets_opt when present --
    // real tainted regions in this seed that the reuse-splat havoc choice can target. Left
    // empty when reusing is disabled, since nothing will ever consult it then.
    offset_groups: Vec<OffsetGroup>,
    enable_reusing: bool,
}

impl<'a, 'b> AFLFuzz<'a, 'b> {
    pub fn new(
        handler: &'b mut SearchHandler<'a>,
        hints: &[TaintHint],
        edge_num: usize,
        enable_reusing: bool,
    ) -> Self {
        let avg_edge_num = handler.executor.local_stats.avg_edge_num.get() as usize;
        let run_ratio = if edge_num * 3 < avg_edge_num {
            2
        } else if edge_num < avg_edge_num {
            3
        } else {
            5
        };

        let mut offset_groups = Vec::new();
        if enable_reusing {
            for hint in hints {
                let is_eq_like = hint.is_eq_like();
                if !hint.offsets.is_empty() {
                    offset_groups.push(OffsetGroup {
                        kind: hint.kind,
                        is_eq_like,
                        offsets: hint.offsets.clone(),
                    });
                }
                if !hint.offsets_opt.is_empty() {
                    offset_groups.push(OffsetGroup {
                        kind: hint.kind,
                        is_eq_like,
                        offsets: hint.offsets_opt.clone(),
                    });
                }
            }
        }

        Self {
            handler,
            run_ratio,
            offset_groups,
            enable_reusing,
        }
    }

    pub fn run(&mut self, first_time: bool) {
        if first_time {
            self.afl_len();
        }

        self.handler
            .set_budget(config::MAX_SPLICE_TIMES * self.run_ratio);
        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !self.splice() {
                break;
            }
        }

        let max_stacking = if self.handler.buf.len() <= 16 {
            64
        } else {
            256
        };
        let base_choice = if config::ENABLE_MICRO_RANDOM_LEN {
            8
        } else {
            6
        };
        // +1: reuse-pool splat slot -- present only when reusing is enabled. When enabled but
        // the pool is still empty (e.g. early in a run) this slot is just a no-op; when
        // disabled entirely, dropping it from the range means `choice` can never land on it, so
        // reuse_splat is never called at all.
        let max_choice = if self.enable_reusing {
            base_choice + 1
        } else {
            base_choice
        };
        let choice_range = Uniform::new(0, max_choice);

        self.handler.max_times += (config::MAX_HAVOC_FLIP_TIMES * self.run_ratio).into();
        self.handler.skip = false;

        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let mut buf = self.handler.buf.clone();
            self.havoc_flip(&mut buf, max_stacking, choice_range, base_choice);
            self.handler.execute(&buf);
        }
    }

    fn locate_diffs(buf1: &Vec<u8>, buf2: &Vec<u8>, len: usize) -> (Option<usize>, Option<usize>) {
        let mut first_loc = None;
        let mut last_loc = None;

        for i in 0..len {
            if buf1[i] != buf2[i] {
                if first_loc.is_none() {
                    first_loc = Some(i);
                }
                last_loc = Some(i);
            }
        }

        (first_loc, last_loc)
    }

    fn splice_two_vec(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Option<Vec<u8>> {
        let len = std::cmp::min(buf1.len(), buf2.len());
        if len < 2 {
            return None;
        }
        let (f_loc, l_loc) = Self::locate_diffs(buf1, buf2, len);
        if f_loc.is_none() || l_loc.is_none() {
            return None;
        }
        let f_loc = f_loc.unwrap();
        let l_loc = l_loc.unwrap();
        if f_loc == l_loc {
            return None;
        }

        let split_at = f_loc + rand::random::<usize>() % (l_loc - f_loc);
        Some([&buf1[..split_at], &buf2[split_at..]].concat())
    }

    // GE algorithm
    fn splice(&mut self) -> bool {
        let buf1 = self.handler.buf.clone();
        let buf2 = self.handler.executor.random_input_buf();
        if let Some(new_buf) = Self::splice_two_vec(&buf1, &buf2) {
            self.handler.execute(&new_buf);
            true
        } else {
            false
        }
    }

    // Picks one of this seed's own tainted regions and, if the reuse pool holds a value for
    // that region's segment-length pattern, splats it in directly instead of a random tweak.
    fn reuse_splat(&self, buf: &mut Vec<u8>, rng: &mut ThreadRng) {
        let group = match self.offset_groups.choose(rng) {
            Some(g) => g,
            None => return,
        };
        let merged = merge_continuous_segments(&group.offsets);
        let pattern = extract_pattern(&merged);
        if pattern.is_empty() {
            return;
        }
        let max_end = merged.iter().map(|s| s.end as usize).max().unwrap_or(0);
        if max_end > buf.len() {
            return;
        }
        let records = match sample_records(&pattern, group.kind, group.is_eq_like, 1) {
            Some(r) => r,
            None => return,
        };
        let record = match records.first() {
            Some(r) => r,
            None => return,
        };
        if record.critical_values.len() != merged.len() {
            return;
        }
        // Same bytes already sitting there -- not worth a copy (or the execution this havoc
        // iteration eventually runs would just be repeating a known-uninteresting candidate).
        if reusing::matches_original(&merged, &record.critical_values, buf) {
            return;
        }
        for (seg, value) in merged.iter().zip(record.critical_values.iter()) {
            let begin = seg.begin as usize;
            let end = seg.end as usize;
            let copy_len = value.len().min(end - begin);
            buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
        }
    }

    // TODO both endian?
    fn havoc_flip(
        &self,
        buf: &mut Vec<u8>,
        max_stacking: usize,
        choice_range: Uniform<u32>,
        reusing_choice: u32,
    ) {
        let mut rng = rand::thread_rng();
        let mut byte_len = buf.len() as u32;
        let use_stacking = 1 + rng.gen_range(0, max_stacking);

        for _ in 0..use_stacking {
            let choice = rng.sample(choice_range);

            if choice == reusing_choice {
                self.reuse_splat(buf, &mut rng);
                continue;
            }

            match choice {
                0 | 1 => {
                    // flip bit
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let bit_idx: u32 = rng.gen_range(0, 8);
                    buf[byte_idx as usize] ^= 128 >> bit_idx;
                },
                2 | 3 => {
                    //add or sub
                    let n: u32 = rng.gen_range(0, 3);
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32);
                        let v: u32 = rng.gen_range(0, config::MUTATE_ARITH_MAX);
                        let direction: bool = rng.gen();
                        mut_input::update_val_in_buf(
                            buf,
                            false,
                            byte_idx as usize,
                            size,
                            direction,
                            v as u64,
                        );
                    }
                },
                4 => {
                    // set interesting value
                    let n: u32 = rng.gen_range(0, 3);
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32);
                        let vals = get_interesting_bytes(size);
                        let wh = rng.gen_range(0, vals.len() as u32);
                        mut_input::set_val_in_buf(buf, byte_idx as usize, size, vals[wh as usize]);
                    }
                },
                5 => {
                    // random byte
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let val: u8 = rng.gen();
                    buf[byte_idx as usize] = val;
                },
                6 => {
                    // delete bytes
                    let remove_len: u32 = rng.gen_range(1, 5);
                    if byte_len > remove_len {
                        byte_len -= remove_len;
                        let byte_idx: u32 = rng.gen_range(0, byte_len);
                        for _ in 0..remove_len {
                            buf.remove(byte_idx as usize);
                        }
                    }
                },
                7 => {
                    // insert bytes
                    let add_len = rng.gen_range(1, 5);
                    let new_len = byte_len + add_len;
                    if new_len < config::MAX_INPUT_LEN as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len);
                        byte_len = new_len;
                        for i in 0..add_len {
                            buf.insert((byte_idx + i) as usize, rng.gen());
                        }
                    }
                },
                _ => {},
            }
        }
    }

    fn random_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        let orig_len = self.handler.buf.len();
        let mut rng = rand::thread_rng();

        let mut buf = self.handler.buf.clone();
        for _ in 0..config::RANDOM_LEN_NUM {
            let step = rng.gen::<usize>() % orig_len + 1;
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf);
            } else {
                break;
            }
        }
    }

    fn add_small_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        let mut rng = rand::thread_rng();
        let mut buf = self.handler.buf.clone();
        let mut step = 1;
        for _ in 0..4 {
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            step = step * 2;
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf);
            } else {
                break;
            }
        }
    }

    fn afl_len(&mut self) {
        if config::ENABLE_RANDOM_LEN {
            self.random_len();
        } else {
            self.add_small_len();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_locate_diffs() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 3, 4, 5];
        let len = std::cmp::min(buf1.len(), buf2.len());
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert!(f_loc.is_none());
        assert!(l_loc.is_none());
        let buf2: Vec<u8> = vec![0, 2, 3, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(0));
        let buf2: Vec<u8> = vec![1, 2, 0, 0, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(2));
        assert_eq!(l_loc, Some(3));
        let buf2: Vec<u8> = vec![0, 2, 0, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(2));
    }

    #[test]
    fn test_splice() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 2, 2, 5, 6];

        let new_vec = AFLFuzz::splice_two_vec(&buf1, &buf2).unwrap();
        println!("{:?}", new_vec);
        // split at index 2 or 3
        assert!(new_vec == vec![1, 2, 2, 4, 5, 6] || new_vec == vec![1, 2, 2, 2, 5, 6]);
    }
}
