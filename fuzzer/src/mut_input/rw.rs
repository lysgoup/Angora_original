use super::*;

#[allow(dead_code)]
pub fn get_bytes_by_offsets(offsets: &Vec<TagSeg>, buf: &Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![];
    for off in offsets {
        if off.begin < off.end {
            let mut v_bytes = buf[off.begin as usize..off.end as usize].to_vec();
            bytes.append(&mut v_bytes);
        }
    }
    bytes
}

pub fn set_bytes_by_offsets(offsets: &Vec<TagSeg>, bytes: &Vec<u8>, buf: &mut Vec<u8>) {
    let mut cmp_off = (0, 0);
    for off in offsets {
        if off.begin < off.end {
            cmp_off.0 = cmp_off.1;
            cmp_off.1 = cmp_off.0 + (off.end - off.begin) as usize;
            let scope = &mut buf[off.begin as usize..off.end as usize];
            scope.clone_from_slice(&bytes[cmp_off.0..cmp_off.1]);
        }
    }
}

// `off` comes from arbitrary taint offsets / random havoc byte indices, so it's never
// guaranteed to be 2/4/8-byte aligned -- read_unaligned/write_unaligned (not a plain
// reference-cast-and-dereference) are the correct way to access a multi-byte value at a
// possibly-unaligned address; the naive cast is UB and modern rustc now catches it at runtime.
pub fn read_val_from_buf(buf: &Vec<u8>, off: usize, size: usize) -> Result<u64, &str> {
    match size {
        1 => Ok(buf[off] as u64),
        2 => Ok(unsafe { (&buf[off] as *const u8 as *const u16).read_unaligned() as u64 }),
        4 => Ok(unsafe { (&buf[off] as *const u8 as *const u32).read_unaligned() as u64 }),
        8 => Ok(unsafe { (&buf[off] as *const u8 as *const u64).read_unaligned() }),
        _ => Err("strange arg off and size"),
    }
}

pub fn set_val_in_buf(buf: &mut Vec<u8>, off: usize, size: usize, val: u64) {
    match size {
        1 => {
            buf[off] = val as u8;
        },
        2 => unsafe {
            (&mut buf[off] as *mut u8 as *mut u16).write_unaligned(val as u16);
        },
        4 => unsafe {
            (&mut buf[off] as *mut u8 as *mut u32).write_unaligned(val as u32);
        },
        8 => unsafe {
            (&mut buf[off] as *mut u8 as *mut u64).write_unaligned(val as u64);
        },
        _ => {
            panic!("strange arg off and size: {}, {}", off, size);
        },
    };
}

// Optional:
// saturating_add
// overflowing_add
pub fn update_val_in_buf(
    buf: &mut Vec<u8>,
    sign: bool,
    off: usize,
    size: usize,
    direction: bool,
    delta: u64,
) {
    match size {
        1 => {
            if sign {
                let v = buf[off] as i8;
                buf[off] = if direction {
                    v.wrapping_add(delta as i8) as u8
                } else {
                    v.wrapping_sub(delta as i8) as u8
                };
            } else {
                let v = &mut buf[off];
                if direction {
                    *v = v.wrapping_add(delta as u8);
                } else {
                    *v = v.wrapping_sub(delta as u8);
                }
            }
        },
        2 => {
            let ptr = &mut buf[off] as *mut u8 as *mut u16;
            if sign {
                let ptr = ptr as *mut i16;
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as i16)
                } else {
                    v.wrapping_sub(delta as i16)
                };
                unsafe { ptr.write_unaligned(v) };
            } else {
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as u16)
                } else {
                    v.wrapping_sub(delta as u16)
                };
                unsafe { ptr.write_unaligned(v) };
            }
        },
        4 => {
            let ptr = &mut buf[off] as *mut u8 as *mut u32;
            if sign {
                let ptr = ptr as *mut i32;
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as i32)
                } else {
                    v.wrapping_sub(delta as i32)
                };
                unsafe { ptr.write_unaligned(v) };
            } else {
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as u32)
                } else {
                    v.wrapping_sub(delta as u32)
                };
                unsafe { ptr.write_unaligned(v) };
            }
        },
        8 => {
            let ptr = &mut buf[off] as *mut u8 as *mut u64;
            if sign {
                let ptr = ptr as *mut i64;
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as i64)
                } else {
                    v.wrapping_sub(delta as i64)
                };
                unsafe { ptr.write_unaligned(v) };
            } else {
                let v = unsafe { ptr.read_unaligned() };
                let v = if direction {
                    v.wrapping_add(delta as u64)
                } else {
                    v.wrapping_sub(delta as u64)
                };
                unsafe { ptr.write_unaligned(v) };
            }
        },
        _ => {
            panic!("strange arg off and size: {}, {}", off, size);
        },
    };
}
