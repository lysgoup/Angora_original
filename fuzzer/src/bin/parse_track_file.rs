extern crate angora;
extern crate angora_common;
use angora::track::*;
use std::{env, path::PathBuf};

fn main() {
    // Usage: path_to_file output_format [pin_mode]
    let args: Vec<String> = env::args().collect();
    if args.len() <= 2 {
        println!("Wrong command!");
        return;
    }

    let mut output_format = "json";
    if args.len() > 2 {
        output_format = match args[2].as_str() {
            "line" => "line",
            _ => "json",
        };
    }

    let mut pin_mode = false;
    if args.len() > 3 {
        pin_mode = match args[3].as_str() {
            "pin" => true,
            _ => false,
        };
    }

    let path = PathBuf::from(&args[1]);

    let log_data = match read_log_data(path.as_path(), pin_mode) {
        Result::Ok(val) => val,
        Result::Err(err) => panic!("parse track file error!! {:?}", err),
    };
    let hints = angora::hint::build_hints(&log_data, false);

    if output_format == "line" {
        for hint in &hints {
            println!(
                "cmpid {}, kind {:?}, args ({}, {}), condition {}",
                hint.cmpid, hint.kind, hint.arg1, hint.arg2, hint.condition
            );
        }
    } else {
        print!("{:#?}", hints);
    }
}
