// RELU-style "how far from satisfying this comparison" computed once from the values a
// TaintHint captured at discovery time. Ported from the old cond_stmt::CondOutput, but as a
// standalone calculation rather than a live re-execution signal -- nothing here re-runs the
// target or minimizes this iteratively; LenOp is the only caller, and it uses this once to
// size a length nudge.
use angora_common::defs;

const EPS: u64 = 1;

fn is_signed(op: u32) -> bool {
    (op & defs::COND_SIGN_MASK) > 0
        || ((op & defs::COND_BASIC_MASK) >= defs::COND_ICMP_SGT_OP
            && (op & defs::COND_BASIC_MASK) <= defs::COND_ICMP_SLE_OP)
}

pub fn get_output(op: u32, condition: u32, size: u32, arg1: u64, arg2: u64) -> u64 {
    let mut a = arg1;
    let mut b = arg2;

    if is_signed(op) {
        a = translate_signed_value(a, size);
        b = translate_signed_value(b, size);
    }

    let mut basic_op = op & defs::COND_BASIC_MASK;
    if basic_op == defs::COND_SW_OP {
        basic_op = defs::COND_ICMP_EQ_OP;
    }

    // if its condition is true, we want its opposite constraint.
    if op <= defs::COND_MAX_EXPLORE_OP && condition == defs::COND_TRUE_ST {
        basic_op = match basic_op {
            defs::COND_ICMP_EQ_OP => defs::COND_ICMP_NE_OP,
            defs::COND_ICMP_NE_OP => defs::COND_ICMP_EQ_OP,
            defs::COND_ICMP_UGT_OP => defs::COND_ICMP_ULE_OP,
            defs::COND_ICMP_UGE_OP => defs::COND_ICMP_ULT_OP,
            defs::COND_ICMP_ULT_OP => defs::COND_ICMP_UGE_OP,
            defs::COND_ICMP_ULE_OP => defs::COND_ICMP_UGT_OP,
            defs::COND_ICMP_SGT_OP => defs::COND_ICMP_SLE_OP,
            defs::COND_ICMP_SGE_OP => defs::COND_ICMP_SLT_OP,
            defs::COND_ICMP_SLT_OP => defs::COND_ICMP_SGE_OP,
            defs::COND_ICMP_SLE_OP => defs::COND_ICMP_SGT_OP,
            _ => basic_op,
        };
    }

    match basic_op {
        defs::COND_ICMP_EQ_OP => sub_abs(a, b),
        defs::COND_ICMP_NE_OP => {
            if a == b {
                1
            } else {
                0
            }
        },
        defs::COND_ICMP_SGT_OP | defs::COND_ICMP_UGT_OP => {
            if a > b {
                0
            } else {
                b - a + EPS
            }
        },
        defs::COND_ICMP_UGE_OP | defs::COND_ICMP_SGE_OP => {
            if a >= b {
                0
            } else {
                b - a
            }
        },
        defs::COND_ICMP_ULT_OP | defs::COND_ICMP_SLT_OP => {
            if a < b {
                0
            } else {
                a - b + EPS
            }
        },
        defs::COND_ICMP_ULE_OP | defs::COND_ICMP_SLE_OP => {
            if a <= b {
                0
            } else {
                a - b
            }
        },
        _ => sub_abs(a, b),
    }
}

fn sub_abs(a: u64, b: u64) -> u64 {
    if a < b {
        b - a
    } else {
        a - b
    }
}

fn translate_signed_value(v: u64, size: u32) -> u64 {
    match size {
        1 => {
            let mut s = v as i8;
            if s < 0 {
                s = s + std::i8::MAX;
                s = s + 1;
                s as u8 as u64
            } else {
                v + (std::i8::MAX as u64 + 1)
            }
        },
        2 => {
            let mut s = v as i16;
            if s < 0 {
                s = s + std::i16::MAX;
                s = s + 1;
                s as u16 as u64
            } else {
                v + (std::i16::MAX as u64 + 1)
            }
        },
        4 => {
            let mut s = v as i32;
            if s < 0 {
                s = s + std::i32::MAX;
                s = s + 1;
                s as u32 as u64
            } else {
                v + (std::i32::MAX as u64 + 1)
            }
        },
        8 => {
            let mut s = v as i64;
            if s < 0 {
                s = s + std::i64::MAX;
                s = s + 1;
                s as u64
            } else {
                v + (std::i64::MAX as u64 + 1)
            }
        },
        _ => v,
    }
}
