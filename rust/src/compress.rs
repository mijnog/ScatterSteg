// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! The message is compressed before it is encrypted (see codec.rs) when that
//! makes it shorter: fewer bits to hide, so fewer changes. Raw DEFLATE
//! through the system zlib, as the C version does: zlib's buffers hold the
//! message, so they come from sodium_malloc, locked and wiped like the rest,
//! where a pure-Rust deflate would leave copies in ordinary heap.

use crate::sodium::Secret;
use crate::zlib_sys as z;
use libsodium_sys as sys;
use std::os::raw::{c_int, c_uint, c_void};

/// The longest message encode takes, before compression; decode refuses one
/// that inflates past it
pub const MESSAGE_MAX: usize = 64 << 20;

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

/// The secretbox's plaintext for a message, `[encoding 1 | body]`: the body
/// raw DEFLATE (encoding 1) if that made the message shorter, else the
/// message as is (0). The buffer and how much of it is used; None if out of
/// memory.
pub fn pack(msg: &[u8]) -> Option<(Secret, usize)> {
    let mut s = stream();
    let init = unsafe {
        z::deflateInit2_(&mut s, z::Z_BEST_COMPRESSION as c_int, z::Z_DEFLATED as c_int,
                         -(z::MAX_WBITS as c_int), 9, z::Z_DEFAULT_STRATEGY as c_int,
                         z::ZLIB_VERSION.as_ptr().cast(), size_of::<z::z_stream>() as c_int)
    };
    if init != z::Z_OK as c_int { return None; }
    let bound = unsafe { z::deflateBound(&mut s, msg.len() as z::uLong) } as usize;
    let packed = Secret::new(1 + bound.max(msg.len())).map(|mut p| {
        s.next_in = msg.as_ptr().cast_mut();
        s.avail_in = msg.len() as c_uint;
        s.next_out = p[1..].as_mut_ptr();
        s.avail_out = (p.len() - 1) as c_uint;
        let r = unsafe { z::deflate(&mut s, z::Z_FINISH as c_int) };
        let body = if r == z::Z_STREAM_END as c_int && (s.total_out as usize) < msg.len() {
            p[0] = DEFLATED;
            s.total_out as usize
        } else {
            p[0] = STORED;
            p[1..1 + msg.len()].copy_from_slice(msg);
            msg.len()
        };
        (p, 1 + body)
    });
    unsafe { z::deflateEnd(&mut s) };
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
/// MESSAGE_MAX: a sender could make it a decompression bomb.
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
        if r != z::Z_OK as c_int || s.total_out as usize > MESSAGE_MAX { break r; }
    };
    let (total, ended) = (s.total_out as usize, s.avail_in == 0);
    unsafe { z::inflateEnd(&mut s) };
    if r == z::Z_STREAM_END as c_int && ended && total <= MESSAGE_MAX {
        Ok(total)
    } else if r == z::Z_MEM_ERROR {
        Err(Unpack::Alloc)
    } else {
        Err(Unpack::Malformed)
    }
}

/// The message in the secretbox's plaintext (see `pack`), with one byte to
/// spare after it
pub fn unpack(pt: &[u8]) -> Result<Secret, Unpack> {
    let Some((&encoding, body)) = pt.split_first() else { return Err(Unpack::Malformed) };
    match encoding {
        STORED => {
            let mut msg = Secret::new(body.len() + 1).ok_or(Unpack::Alloc)?;
            msg[..body.len()].copy_from_slice(body);
            Ok(msg)
        }
        DEFLATED => {
            let size = inflate(body, None)?;
            let mut msg = Secret::new(size + 1).ok_or(Unpack::Alloc)?;
            inflate(body, Some(&mut msg))?;
            Ok(msg)
        }
        _ => Err(Unpack::Malformed),
    }
}
