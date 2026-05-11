/* data_cov.rs — StorFuzz data-flow coverage map, Rust side.
 *
 * Mirrors branches.rs in structure and import set.
 * Gated behind #[cfg(feature = "storfuzz")] at all call sites.
<<<<<<< Updated upstream
 * This file is compiled unconditionally but only instantiated when the
 * feature is active; the struct is zero-cost when unused.
=======
>>>>>>> Stashed changes
 */

use angora_common::{config::DATA_COV_SIZE, shm::SHM};

pub type DataBuf = [u8; DATA_COV_SIZE];

pub struct DataCov {
<<<<<<< Updated upstream
    /// Accumulates all bits ever seen — a bit that flips from 0→1 here
    /// means the run was interesting for data coverage.
=======
    /// Accumulates all bits ever seen.
>>>>>>> Stashed changes
    virgin: Box<DataBuf>,
    /// Shared-memory region written by instrumented stores in child processes.
    shm: SHM<DataBuf>,
}

impl DataCov {
    pub fn new() -> Self {
        let shm = SHM::<DataBuf>::new();
        // NOTE: the shmem ID is inserted into the executor's envs HashMap by
        // Executor::new() (same pattern as branches / cond_stmt).
        // Do NOT call env::set_var here — child processes are spawned with
        // env_clear().envs(&envs), so process-level env vars are never seen.
        DataCov {
            virgin: Box::new([0u8; DATA_COV_SIZE]),
            shm,
        }
    }

    /// Return the shmem ID so Executor::new() can insert it into envs.
    pub fn get_id(&self) -> i32 {
        self.shm.get_id()
    }

    /// Zero the run map before each execution.
<<<<<<< Updated upstream
    /// Called immediately after Branches::clear_trace() in run_inner().
=======
>>>>>>> Stashed changes
    pub fn clear_run_map(&mut self) {
        self.shm.clear();
    }

    /// Returns true if this run produced bits not present in the virgin map.
<<<<<<< Updated upstream
    /// Updates the virgin map in place.  Does NOT touch the branch map.
=======
    /// Updates the virgin map in place.
>>>>>>> Stashed changes
    pub fn has_new(&mut self) -> bool {
        let cur: &DataBuf = &*self.shm;
        let mut novel = false;
        let mut new_bit_count = 0usize;
        for i in 0..DATA_COV_SIZE {
            let new_bits = cur[i] & !self.virgin[i];
            if new_bits != 0 {
                self.virgin[i] |= new_bits;
                novel = true;
                new_bit_count += new_bits.count_ones() as usize;
            }
        }
        if novel {
            debug!(
                "[DATACOV] +{} new bits this run (cumulative total={})",
                new_bit_count,
                self.bits_set()
            );
        }
        novel
    }

    /// Count bits set in the virgin map (for stats reporting).
    pub fn bits_set(&self) -> usize {
        self.virgin.iter().map(|b| b.count_ones() as usize).sum()
    }
}

impl std::fmt::Debug for DataCov {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DataCov(bits={})", self.bits_set())
    }
}
