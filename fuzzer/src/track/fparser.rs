use super::load_pin_data::get_log_data_pin;
use angora_common::log_data::LogData;
use runtime::get_log_data;
use std::{io, path::Path};

// Loads the raw taint-tracking output written by the .taint/.pin binary. Building the
// resulting Vec<TaintHint> from this LogData is hint::build_hints' job now (see
// executor::Executor::track), not this module's -- this is purely the file-format half.
pub fn read_log_data(out_f: &Path, is_pin_mode: bool) -> io::Result<LogData> {
    if is_pin_mode {
        get_log_data_pin(out_f)
    } else {
        get_log_data(out_f)
    }
}
