use super::*;
use std::{fs, io::prelude::*};

impl Drop for Depot {
    fn drop(&mut self) {
        info!("dump per-input hint summary..");
        let dir = self.dirs.inputs_dir.parent().unwrap();

        let mut log_q = fs::File::create(dir.join("input_hints.csv")).unwrap();
        writeln!(log_q, "id, fuzzed_count, num_hints, hints").unwrap();
        let entries = self.entries.lock().unwrap();

        let mut ids: Vec<&usize> = entries.keys().collect();
        ids.sort();
        for id in ids {
            let entry = &entries[id];
            let hints: Vec<String> = entry
                .hints
                .iter()
                .map(|h| {
                    let offsets: Vec<String> = h
                        .offsets
                        .iter()
                        .map(|off| format!("{}-{}", off.begin, off.end))
                        .collect();
                    format!("{}:{:?}:{}", h.cmpid, h.kind, offsets.join("&"))
                })
                .collect();

            writeln!(
                log_q,
                "{}, {}, {}, {}",
                entry.id,
                entry.fuzzed_count,
                entry.hints.len(),
                hints.join(";")
            )
            .unwrap();
        }
    }
}
