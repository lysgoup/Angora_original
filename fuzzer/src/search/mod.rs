use crate::{
    executor::{Executor, StatusType},
    hint::{HintKind, TaintHint},
    mut_input::{self, MutInput},
};
use angora_common::config;
use rand::prelude::*;
use std::{
    self,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub mod interesting_val;
pub use self::interesting_val::*;
mod handler;
pub use self::handler::SearchHandler;

pub mod afl;
pub use self::afl::AFLFuzz;
pub mod det;
pub use self::det::DetFuzz;
pub mod reusing;
pub use self::reusing::ReusingFuzz;
pub mod exploit_op;
pub use self::exploit_op::ExploitOp;
pub mod len_op;
pub use self::len_op::LenOp;
pub mod magic_bytes_op;
pub use self::magic_bytes_op::MagicBytesOp;
