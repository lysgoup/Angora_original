use super::{limit::SetLimit, *};

use crate::{branches, command, depot, hint, stats, track};
use angora_common::{config, defs};

use std::{
    collections::HashMap,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, RwLock,
    },
    time,
};
use wait_timeout::ChildExt;

pub struct Executor {
    pub cmd: command::CommandOpt,
    pub branches: branches::Branches,
    envs: HashMap<String, String>,
    forksrv: Option<Forksrv>,
    depot: Arc<depot::Depot>,
    fd: PipeFd,
    tmout_cnt: usize,
    pub has_new_path: bool,
    pub global_stats: Arc<RwLock<stats::ChartStats>>,
    pub local_stats: stats::LocalStats,
    // Set for the duration of run_sync (dry run) only. While true, do_if_has_new saves/tracks
    // every seed unconditionally instead of only ones that add new coverage -- a dry-run seed
    // that happens to be a coverage subset of an earlier one is still a legitimate part of the
    // corpus, not noise to discard.
    pub is_dry_run: bool,
    pub dryrun_discarded_count: usize,
    pub dryrun_forkserver_error_count: usize,
    pub dryrun_track_skipped_speed: usize,
    pub dryrun_track_skipped_memory: usize,
}

impl Executor {
    pub fn new(
        cmd: command::CommandOpt,
        global_branches: Arc<branches::GlobalBranches>,
        depot: Arc<depot::Depot>,
        global_stats: Arc<RwLock<stats::ChartStats>>,
    ) -> Self {
        // ** Share Memory **
        let branches = branches::Branches::new(global_branches);

        // ** Envs **
        let mut envs = HashMap::new();
        envs.insert(
            defs::ASAN_OPTIONS_VAR.to_string(),
            defs::ASAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            defs::MSAN_OPTIONS_VAR.to_string(),
            defs::MSAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            defs::BRANCHES_SHM_ENV_VAR.to_string(),
            branches.get_id().to_string(),
        );
        envs.insert(
            defs::LD_LIBRARY_PATH_VAR.to_string(),
            cmd.ld_library.clone(),
        );

        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = Some(forksrv::Forksrv::new(
            &cmd.forksrv_socket_path,
            &cmd.main,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
        ));

        Self {
            cmd,
            branches,
            envs,
            forksrv,
            depot,
            fd,
            tmout_cnt: 0,
            has_new_path: false,
            global_stats,
            local_stats: Default::default(),
            is_dry_run: false,
            dryrun_discarded_count: 0,
            dryrun_forkserver_error_count: 0,
            dryrun_track_skipped_speed: 0,
            dryrun_track_skipped_memory: 0,
        }
    }

    pub fn rebind_forksrv(&mut self) {
        {
            // delete the old forksrv
            self.forksrv = None;
        }
        let fs = forksrv::Forksrv::new(
            &self.cmd.forksrv_socket_path,
            &self.cmd.main,
            &self.envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit,
            self.cmd.mem_limit,
        );
        self.forksrv = Some(fs);
    }

    fn try_unlimited_memory(&mut self, buf: &Vec<u8>) -> bool {
        let mut skip = false;
        self.branches.clear_trace();
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        compiler_fence(Ordering::SeqCst);
        let unmem_status =
            self.run_target(&self.cmd.main, config::MEM_LIMIT_TRACK, self.cmd.time_limit);
        compiler_fence(Ordering::SeqCst);

        // find difference
        if unmem_status != StatusType::Normal {
            skip = true;
            warn!(
                "Behavior changes if we unlimit memory!! status={:?}",
                unmem_status
            );
            // crash or hang
            if self.branches.has_new(unmem_status).0 {
                self.depot.save(unmem_status, &buf);
            }
        }
        skip
    }

    // `parent` is the seed this buf was mutated from (None for raw/dry-run/AFL-synced seeds,
    // which aren't a mutation of anything Angora already knows about) -- used to figure out
    // which bytes actually changed, so the reuse pool only caches values from hints tied to
    // that changed region instead of every hint this input happens to carry.
    fn do_if_has_new(&mut self, buf: &Vec<u8>, status: StatusType, parent: Option<&[u8]>) {
        // new edge: one byte in bitmap
        let (has_new_path, has_new_edge, edge_num) = self.branches.has_new(status);

        // During dry run every seed from the seed directory is saved/tracked regardless of
        // whether it adds new coverage over an earlier seed -- it's still part of the corpus
        // the user handed us, not noise to discard just because some other seed already hit
        // the same edges.
        if has_new_path || self.is_dry_run {
            self.has_new_path = true;
            self.local_stats.find_new(&status);
            let id = self.depot.save(status, &buf);

            if status == StatusType::Normal {
                self.local_stats.avg_edge_num.update(edge_num as f32);
                let speed = self.count_time();
                let speed_ratio = self.local_stats.avg_exec_time.get_ratio(speed as f32);
                self.local_stats.avg_exec_time.update(speed as f32);

                // Avoid track slow ones
                if (!has_new_edge && speed_ratio > 10 && id > 10) || (speed_ratio > 25 && id > 10) {
                    warn!(
                        "Skip tracking id {}, speed: {}, speed_ratio: {}, has_new_edge: {}",
                        id, speed, speed_ratio, has_new_edge
                    );
                    if self.is_dry_run {
                        self.dryrun_track_skipped_speed += 1;
                    }
                    return;
                }
                let crash_or_tmout = self.try_unlimited_memory(buf);
                if crash_or_tmout && self.is_dry_run {
                    self.dryrun_track_skipped_memory += 1;
                }
                if !crash_or_tmout {
                    let hints = self.track(id, buf);
                    self.depot.set_hints(
                        id,
                        hints,
                        speed,
                        edge_num as u32,
                        parent,
                        self.cmd.enable_reusing,
                    );
                }
            }
        }
    }

    pub fn run(&mut self, buf: &Vec<u8>, parent: &[u8]) -> StatusType {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, status, Some(parent));
        self.check_timeout(status)
    }

    // Returns false (without saving/tracking anything) if the forkserver couldn't be revived
    // after a socket error, even after one rebind-and-retry -- the caller (depot::sync_depot)
    // counts this so a transient dry-run hiccup is visible instead of silently swallowed.
    pub fn run_sync(&mut self, buf: &Vec<u8>) -> bool {
        self.is_dry_run = true;
        self.run_init();
        let mut status = self.run_inner(buf);

        if status == StatusType::Error {
            warn!("Dry run socket error, retrying after rebind");
            self.rebind_forksrv();
            self.has_new_path = false;
            status = self.run_inner(buf);
            if status == StatusType::Error {
                warn!("Dry run retry also failed, skipping seed");
                self.is_dry_run = false;
                return false;
            }
        }

        self.do_if_has_new(buf, status, None);
        self.is_dry_run = false;
        true
    }

    fn run_init(&mut self) {
        self.has_new_path = false;
        self.local_stats.num_exec.count();
    }

    fn check_timeout(&mut self, status: StatusType) -> StatusType {
        let mut ret_status = status;
        if ret_status == StatusType::Error {
            self.rebind_forksrv();
            ret_status = StatusType::Timeout;
        }

        if ret_status == StatusType::Timeout {
            self.tmout_cnt = self.tmout_cnt + 1;
            if self.tmout_cnt >= config::TMOUT_SKIP {
                ret_status = StatusType::Skip;
                self.tmout_cnt = 0;
            }
        } else {
            self.tmout_cnt = 0;
        };

        ret_status
    }

    fn run_inner(&mut self, buf: &Vec<u8>) -> StatusType {
        self.write_test(buf);

        self.branches.clear_trace();

        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.forksrv {
            fs.run()
        } else {
            self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit)
        };
        compiler_fence(Ordering::SeqCst);

        ret_status
    }

    fn count_time(&mut self) -> u32 {
        let t_start = time::Instant::now();
        for _ in 0..3 {
            if self.cmd.is_stdin {
                self.fd.rewind();
            }
            if let Some(ref mut fs) = self.forksrv {
                let status = fs.run();
                if status == StatusType::Error {
                    self.rebind_forksrv();
                    return defs::SLOW_SPEED;
                }
            } else {
                self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit);
            }
        }
        let used_t = t_start.elapsed();
        let used_us = (used_t.as_secs() as u32 * 1000_000) + used_t.subsec_nanos() / 1_000;
        used_us / 3
    }

    fn track(&mut self, id: usize, buf: &Vec<u8>) -> Vec<hint::TaintHint> {
        self.envs.insert(
            defs::TRACK_OUTPUT_VAR.to_string(),
            self.cmd.track_path.clone(),
        );

        let t_now: stats::TimeIns = Default::default();

        self.write_test(buf);

        compiler_fence(Ordering::SeqCst);
        let ret_status = self.run_target(
            &self.cmd.track,
            config::MEM_LIMIT_TRACK,
            config::TIME_LIMIT_TRACK,
        );
        compiler_fence(Ordering::SeqCst);

        if ret_status != StatusType::Normal {
            error!(
                "Crash or hang while tracking! -- {:?},  id: {}",
                ret_status, id
            );
            return vec![];
        }

        let hints = match track::read_log_data(
            Path::new(&self.cmd.track_path),
            self.cmd.mode.is_pin_mode(),
        ) {
            Ok(log_data) => hint::build_hints(&log_data, self.cmd.enable_exploitation),
            Err(err) => {
                error!("parse track file error!! {:?}", err);
                vec![]
            },
        };

        self.local_stats.track_time += t_now.into();
        hints
    }

    pub fn random_input_buf(&self) -> Vec<u8> {
        let id = self.depot.next_random();
        self.depot.get_input_buf(id)
    }

    fn write_test(&mut self, buf: &Vec<u8>) {
        self.fd.write_buf(buf);
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
    }

    fn run_target(
        &self,
        target: &(String, Vec<String>),
        mem_limit: u64,
        time_limit: u64,
    ) -> StatusType {
        let mut cmd = Command::new(&target.0);
        let mut child = cmd
            .args(&target.1)
            .stdin(Stdio::null())
            .env_clear()
            .envs(&self.envs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .mem_limit(mem_limit.clone())
            .setsid()
            .pipe_stdin(self.fd.as_raw_fd(), self.cmd.is_stdin)
            .spawn()
            .expect("Could not run target");

        let timeout = time::Duration::from_secs(time_limit);
        let ret = match child.wait_timeout(timeout).unwrap() {
            Some(status) => {
                if let Some(status_code) = status.code() {
                    if (self.cmd.uses_asan && status_code == defs::MSAN_ERROR_CODE)
                        || (self.cmd.mode.is_pin_mode() && status_code > 128)
                    {
                        StatusType::Crash
                    } else {
                        StatusType::Normal
                    }
                } else {
                    StatusType::Crash
                }
            },
            None => {
                // Timeout
                // child hasn't exited yet
                child.kill().expect("Could not send kill signal to child.");
                child.wait().expect("Error during waiting for child.");
                StatusType::Timeout
            },
        };
        ret
    }

    pub fn update_log(&mut self) {
        self.global_stats
            .write()
            .unwrap()
            .sync_from_local(&mut self.local_stats);

        self.tmout_cnt = 0;
    }
}
