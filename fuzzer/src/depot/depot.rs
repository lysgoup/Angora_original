use super::*;
use crate::{executor::StatusType, hint::TaintHint};
use rand;
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

// How far ReusingFuzz's main sweep (search/reusing.rs::try_offsets) has already gotten into
// the reuse pool for one hint's offsets / offsets_opt / merged-both-operands view, so a
// repeat visit to this input only tries values it hasn't tried yet on that exact hint instead
// of re-applying ones already known not to help. All three are independent: they're separate
// patterns (different segment-length lists in general) with their own position in the pool.
// Parallel array to QueueEntry.hints (same index, same length).
#[derive(Default, Clone, Copy)]
pub struct ReusingCursor {
    pub offsets: usize,
    pub offsets_opt: usize,
    pub merged: usize,
}

// One seed input's scheduling metadata: the taint hints gathered the one time it was tracked,
// plus how many times it's been picked for mutation. Replaces CondStmt as the thing the
// fuzz loop schedules -- this fuzzer's queue holds inputs, not individual branch constraints.
pub struct QueueEntry {
    pub id: usize,
    pub hints: Vec<TaintHint>,
    pub speed: u32,
    pub edge_num: u32,
    pub fuzzed_count: usize,
    pub reusing_cursors: Vec<ReusingCursor>,
}

pub struct Depot {
    // Round-robin schedule of input ids. A plain FIFO ring is enough now that every entry is
    // "just an input" -- pop the front, mutate it, push it back -- there's no more
    // AFL-cond-vs-regular-cond priority distinction to justify a priority queue.
    queue: Mutex<VecDeque<usize>>,
    pub entries: Mutex<HashMap<usize, QueueEntry>>,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub dirs: DepotDir,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            entries: Mutex::new(HashMap::new()),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
        }
    }

    fn save_input(status: &StatusType, buf: &Vec<u8>, num: &AtomicUsize, dir: &Path) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!("Find {} th new {:?} input.", id, status);
        let new_path = get_file_name(dir, id);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>) -> usize {
        match status {
            StatusType::Normal => {
                Self::save_input(&status, buf, &self.num_inputs, &self.dirs.inputs_dir)
            },
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, &self.dirs.hangs_dir)
            },
            StatusType::Crash => {
                Self::save_input(&status, buf, &self.num_crashes, &self.dirs.crashes_dir)
            },
            _ => 0,
        }
    }

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random(&self) -> usize {
        rand::random::<usize>() % self.num_inputs.load(Ordering::Relaxed)
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    // Called once, right after a freshly-saved Normal input has been tracked: attaches its
    // hints and enters it into the schedule. Also feeds the reuse pool (label_pattern_tracker)
    // from these hints, since that's the only place critical values get harvested from.
    // `parent_buf` is the seed this input was mutated from (None for raw/dry-run/AFL-synced
    // seeds); only hints tied to bytes that actually differ from the parent get cached.
    pub fn set_hints(
        &self,
        id: usize,
        hints: Vec<TaintHint>,
        speed: u32,
        edge_num: u32,
        parent_buf: Option<&[u8]>,
    ) {
        label_pattern_tracker::add_hints_to_pattern_map(&hints, self, id, parent_buf);

        let reusing_cursors = vec![ReusingCursor::default(); hints.len()];
        let entry = QueueEntry {
            id,
            hints,
            speed,
            edge_num,
            fuzzed_count: 0,
            reusing_cursors,
        };
        self.entries.lock().unwrap().insert(id, entry);
        self.queue.lock().unwrap().push_back(id);
    }

    // Pops the least-recently-fuzzed input id and requeues it at the back (round-robin).
    pub fn get_entry(&self) -> Option<usize> {
        let mut q = self.queue.lock().unwrap();
        let id = q.pop_front()?;
        q.push_back(id);
        Some(id)
    }

    pub fn get_hints(&self, id: usize) -> Vec<TaintHint> {
        self.entries
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| e.hints.clone())
            .unwrap_or_default()
    }

    pub fn get_cursors(&self, id: usize) -> Vec<ReusingCursor> {
        self.entries
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| e.reusing_cursors.clone())
            .unwrap_or_default()
    }

    pub fn set_cursors(&self, id: usize, cursors: Vec<ReusingCursor>) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            entry.reusing_cursors = cursors;
        }
    }

    // (speed, edge_num, fuzzed_count) in one lock acquisition.
    pub fn get_entry_info(&self, id: usize) -> (u32, u32, usize) {
        self.entries
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| (e.speed, e.edge_num, e.fuzzed_count))
            .unwrap_or((0, 0, 0))
    }

    pub fn update_entry(&self, id: usize) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            entry.fuzzed_count += 1;
        }
    }

    pub fn max_fuzzed_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|e| e.fuzzed_count)
            .max()
            .unwrap_or(0)
    }
}
