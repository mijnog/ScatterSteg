// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! The message is compressed before it is encrypted (see codec.rs) when that
//! makes it shorter: fewer bits to hide, so fewer changes. Raw DEFLATE
//! through the system zlib, as the C version does: zlib's buffers hold the
//! message, so they come from sodium_malloc, locked and wiped like the rest,
//! where a pure-Rust deflate would leave copies in ordinary heap.

use crate::sodium::{self, Secret};
use crate::zlib_sys as z;
use libsodium_sys as sys;
use std::os::raw::{c_int, c_uint, c_void};

/// The longest message encode takes, before compression; decode refuses one
/// that inflates past it (with its file name)
pub const MESSAGE_MAX: usize = 64 << 20;
/// The longest file name stored with a message
pub const NAME_MAX: usize = 255;
/// Most bytes a record inflates to: a decompression bomb stops there
const RECORD_MAX: usize = MESSAGE_MAX + 1 + NAME_MAX;

const STORED: u8 = 0;
const DEFLATED: u8 = 1;
const SCRATCH: usize = 65536;

unsafe extern "C" fn secret_alloc(_: *mut c_void, items: c_uint, size: c_uint) -> *mut c_void {
    if crate::fault::should_fail("sodium_malloc") { return std::ptr::null_mut(); }
    match (items as usize).checked_mul(size as usize) {
        Some(n) => unsafe { sys::sodium_malloc(n) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn secret_free(_: *mut c_void, p: *mut c_void) {
    unsafe { sys::sodium_free(p) }
}

/// A stream that allocates through sodium_malloc
fn stream() -> z::z_stream {
    // All zero is zlib's documented initial state (null pointers, no hooks)
    let mut s: z::z_stream = unsafe { std::mem::zeroed() };
    s.zalloc = Some(secret_alloc);
    s.zfree = Some(secret_free);
    s
}

/// A file name a record may carry: a bare name, which extract can create in
/// the current directory and print safely. 1 to NAME_MAX bytes, no '/' or
/// control characters, not "." or "..".
pub fn name_ok(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= NAME_MAX && name != b"." && name != b".."
        && !name.iter().any(|&b| b == b'/' || b < 0x20 || b == 0x7f)
}

/// The secretbox's plaintext for a message, `[encoding 1 | body]`: the body
/// raw DEFLATE (encoding 1) of the record if that made it shorter, else the
/// record as is (0). The record is `[name length 1 | name | message]` (name
/// empty for none; see `name_ok`). `level` 1-9 compresses at that level; 0
/// never does. The buffer and how much of it is used; None if out of memory.
pub fn pack(name: &[u8], msg: &[u8], level: u32) -> Option<(Secret, usize)> {
    let mut head = [0u8; 1 + NAME_MAX];
    head[0] = name.len() as u8;
    head[1..1 + name.len()].copy_from_slice(name);
    let head_len = 1 + name.len();
    let record = head_len + msg.len();

    let mut s = stream();
    if level > 0 {
        let init = unsafe {
            z::deflateInit2_(&mut s, level as c_int, z::Z_DEFLATED as c_int, -(z::MAX_WBITS as c_int), 9,
                             z::Z_DEFAULT_STRATEGY as c_int, z::ZLIB_VERSION.as_ptr().cast(),
                             size_of::<z::z_stream>() as c_int)
        };
        if init != z::Z_OK as c_int { return None; }
    }
    let bound = if level > 0 { (unsafe { z::deflateBound(&mut s, record as z::uLong) }) as usize } else { 0 };
    let packed = Secret::new(1 + bound.max(record)).map(|mut p| {
        let mut deflated = false;
        if level > 0 {
            s.next_in = head.as_mut_ptr();
            s.avail_in = head_len as c_uint;
            s.next_out = p[1..].as_mut_ptr();
            s.avail_out = (p.len() - 1) as c_uint;
            let r = unsafe { z::deflate(&mut s, z::Z_NO_FLUSH as c_int) };
            s.next_in = msg.as_ptr().cast_mut();
            s.avail_in = msg.len() as c_uint;
            deflated = r == z::Z_OK as c_int
                && unsafe { z::deflate(&mut s, z::Z_FINISH as c_int) } == z::Z_STREAM_END as c_int
                && (s.total_out as usize) < record;
        }
        if deflated {
            p[0] = DEFLATED;
            let n = s.total_out as usize;
            (p, 1 + n)
        } else {
            p[0] = STORED;
            p[1..1 + head_len].copy_from_slice(&head[..head_len]);
            p[1 + head_len..1 + record].copy_from_slice(msg);
            (p, 1 + record)
        }
    });
    if level > 0 { unsafe { z::deflateEnd(&mut s) }; }
    sodium::memzero(&mut head);
    packed
}

/// Why a message couldn't be unpacked
pub enum Unpack {
    Alloc,
    /// Only a faulty encoder, or a sender who knows the passphrase, can make
    /// one that authenticates
    Malformed,
}

/// Inflates `src`, which must be exactly one raw DEFLATE stream, into `out`;
/// or, with no `out`, only measures it. Malformed too if it inflates past
/// RECORD_MAX: a sender could make it a decompression bomb.
fn inflate(src: &[u8], out: Option<&mut [u8]>) -> Result<usize, Unpack> {
    let mut s = stream();
    let init = unsafe {
        z::inflateInit2_(&mut s, -(z::MAX_WBITS as c_int), z::ZLIB_VERSION.as_ptr().cast(),
                         size_of::<z::z_stream>() as c_int)
    };
    if init != z::Z_OK as c_int { return Err(Unpack::Alloc); }
    let mut scratch = None;
    if out.is_none() {
        scratch = Secret::new(SCRATCH);
        if scratch.is_none() {
            unsafe { z::inflateEnd(&mut s) };
            return Err(Unpack::Alloc);
        }
    }
    s.next_in = src.as_ptr().cast_mut();
    s.avail_in = src.len() as c_uint;
    if let Some(out) = out {
        s.next_out = out.as_mut_ptr();
        s.avail_out = out.len() as c_uint;
    }
    let r = loop {
        if let Some(scratch) = scratch.as_mut() {
            s.next_out = scratch.as_mut_ptr();
            s.avail_out = SCRATCH as c_uint;
        }
        let r = unsafe { z::inflate(&mut s, z::Z_NO_FLUSH as c_int) };
        if r != z::Z_OK as c_int || s.total_out as usize > RECORD_MAX { break r; }
    };
    let (total, ended) = (s.total_out as usize, s.avail_in == 0);
    unsafe { z::inflateEnd(&mut s) };
    if r == z::Z_STREAM_END as c_int && ended && total <= RECORD_MAX {
        Ok(total)
    } else if r == z::Z_MEM_ERROR {
        Err(Unpack::Alloc)
    } else {
        Err(Unpack::Malformed)
    }
}

/// The message in the secretbox's plaintext (see `pack`), and the file name
/// stored with it (empty for none)
pub fn unpack(pt: &[u8]) -> Result<(Secret, Vec<u8>), Unpack> {
    let Some((&encoding, body)) = pt.split_first() else { return Err(Unpack::Malformed) };
    let record = match encoding {
        STORED => Secret::from_slice(body).ok_or(Unpack::Alloc)?,
        DEFLATED => {
            let size = inflate(body, None)?;
            let mut record = Secret::new(size + 1).ok_or(Unpack::Alloc)?;
            inflate(body, Some(&mut record))?;
            record
        }
        _ => return Err(Unpack::Malformed),
    };
    let size = if encoding == DEFLATED { record.len() - 1 } else { record.len() };
    let Some(&name_len) = record[..size].first() else { return Err(Unpack::Malformed) };
    let name_end = 1 + name_len as usize;
    if name_end > size || (name_len > 0 && !name_ok(&record[1..name_end])) {
        return Err(Unpack::Malformed);
    }
    let msg = Secret::from_slice(&record[name_end..size]).ok_or(Unpack::Alloc)?;
    Ok((msg, record[1..name_end].to_vec()))
}
