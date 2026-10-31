// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! A thin safe layer over libsodium, so the rest of the crate stays free of
//! `unsafe` and raw pointers.

use libsodium_sys as sys;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_ulonglong;

pub const SALT_BYTES: usize = 16;
pub const CHACHA_KEY_BYTES: usize = 32;
pub const SECRETBOX_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const MAC_BYTES: usize = 16;
pub const KDF_KEY_BYTES: usize = 32;

#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
pub fn init() -> Result<(), ()> {
    // SAFETY: sodium_init has no preconditions; <0 means failure
    if unsafe { sys::sodium_init() } < 0 { Err(()) } else { Ok(()) }
}

pub fn random_bytes(buf: &mut [u8]) {
    unsafe { sys::randombytes_buf(buf.as_mut_ptr().cast(), buf.len()) }
}

/// Uniform in [0, bound)
pub fn random_uniform(bound: u32) -> u32 {
    unsafe { sys::randombytes_uniform(bound) }
}

pub fn memzero(buf: &mut [u8]) {
    unsafe { sys::sodium_memzero(buf.as_mut_ptr().cast(), buf.len()) }
}

/// Unkeyed BLAKE2b over data given in parts, 32 bytes of output
pub struct Hasher(sys::crypto_generichash_state);

impl Hasher {
    pub fn new() -> Hasher {
        // SAFETY: an all-zero state is valid storage for init to fill in
        let mut st: sys::crypto_generichash_state = unsafe { std::mem::zeroed() };
        let r = unsafe { sys::crypto_generichash_init(&mut st, std::ptr::null(), 0, 32) };
        assert_eq!(r, 0, "crypto_generichash_init rejected its parameters");
        Hasher(st)
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe { sys::crypto_generichash_update(&mut self.0, data.as_ptr(), data.len() as c_ulonglong) };
    }

    pub fn finish(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe { sys::crypto_generichash_final(&mut self.0, out.as_mut_ptr(), out.len()) };
        out
    }
}

impl Default for Hasher {
    fn default() -> Hasher { Hasher::new() }
}

/// Unkeyed BLAKE2b with `out.len()` bytes of output
pub fn generichash(out: &mut [u8], input: &[u8], key: &[u8]) {
    let key_ptr = if key.is_empty() { std::ptr::null() } else { key.as_ptr() };
    let r = unsafe {
        sys::crypto_generichash(out.as_mut_ptr(), out.len(), input.as_ptr(), input.len() as c_ulonglong,
                                key_ptr, key.len())
    };
    assert_eq!(r, 0, "crypto_generichash rejected its parameters");
}

/// XORs `buf` with the ChaCha20-IETF keystream (zero nonce) from `block`
pub fn chacha20_ietf_xor_ic(buf: &mut [u8], block: u32, key: &[u8; CHACHA_KEY_BYTES]) {
    let nonce = [0u8; 12];
    let r = unsafe {
        sys::crypto_stream_chacha20_ietf_xor_ic(buf.as_mut_ptr(), buf.as_ptr(), buf.len() as c_ulonglong,
                                                nonce.as_ptr(), block, key.as_ptr())
    };
    assert_eq!(r, 0);
}

#[derive(Clone, Copy)]
pub enum PwhashStrength {
    Interactive,
    Moderate,
}

/// Argon2id13. Err on out of memory.
///
/// A fuzzing build (`--cfg fuzzing`, which cargo fuzz sets) swaps in keyed
/// BLAKE2b, as the C fuzz builds do, so the fuzzer gets past key derivation
/// in microseconds; such a build must never handle a real secret.
#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
pub fn pwhash(out: &mut [u8], passphrase: &[u8], salt: &[u8; SALT_BYTES], strength: PwhashStrength)
    -> Result<(), ()> {
    if crate::fault::should_fail("crypto_pwhash") { return Err(()); }
    if cfg!(fuzzing) {
        let _ = strength;
        generichash(out, passphrase, salt);
        return Ok(());
    }
    let (ops, mem) = match strength {
        PwhashStrength::Interactive => (sys::crypto_pwhash_OPSLIMIT_INTERACTIVE, sys::crypto_pwhash_MEMLIMIT_INTERACTIVE),
        PwhashStrength::Moderate => (sys::crypto_pwhash_OPSLIMIT_MODERATE, sys::crypto_pwhash_MEMLIMIT_MODERATE),
    };
    let r = unsafe {
        sys::crypto_pwhash(out.as_mut_ptr(), out.len() as c_ulonglong, passphrase.as_ptr().cast(),
                           passphrase.len() as c_ulonglong, salt.as_ptr(), ops as c_ulonglong, mem as usize,
                           sys::crypto_pwhash_ALG_ARGON2ID13 as i32)
    };
    if r == 0 { Ok(()) } else { Err(()) }
}

pub fn kdf_derive(out: &mut [u8], id: u64, context: &[u8; 8], master: &[u8; KDF_KEY_BYTES]) {
    let r = unsafe {
        sys::crypto_kdf_derive_from_key(out.as_mut_ptr(), out.len(), id, context.as_ptr().cast(), master.as_ptr())
    };
    assert_eq!(r, 0);
}

/// `out` is `msg.len() + MAC_BYTES` long
pub fn secretbox_easy(out: &mut [u8], msg: &[u8], nonce: &[u8; NONCE_BYTES], key: &[u8; SECRETBOX_KEY_BYTES]) {
    assert_eq!(out.len(), msg.len() + MAC_BYTES);
    let r = unsafe {
        sys::crypto_secretbox_easy(out.as_mut_ptr(), msg.as_ptr(), msg.len() as c_ulonglong,
                                   nonce.as_ptr(), key.as_ptr())
    };
    assert_eq!(r, 0);
}

/// `out` is `boxed.len() - MAC_BYTES` long; false if it doesn't authenticate
pub fn secretbox_open_easy(out: &mut [u8], boxed: &[u8], nonce: &[u8; NONCE_BYTES],
                           key: &[u8; SECRETBOX_KEY_BYTES]) -> bool {
    assert_eq!(out.len() + MAC_BYTES, boxed.len());
    let r = unsafe {
        sys::crypto_secretbox_open_easy(out.as_mut_ptr(), boxed.as_ptr(), boxed.len() as c_ulonglong,
                                        nonce.as_ptr(), key.as_ptr())
    };
    r == 0
}

/// Memory from sodium_malloc: locked against swapping, fenced by guard
/// pages, wiped on drop. Holds secrets (passphrase, message, keys).
pub struct Secret {
    ptr: *mut u8,
    len: usize,
}

impl Secret {
    /// `len` zeroed-or-garbage bytes (sodium fills with 0xdb); None if out of memory
    pub fn new(len: usize) -> Option<Secret> {
        if crate::fault::should_fail("sodium_malloc") { return None; }
        let ptr = unsafe { sys::sodium_malloc(len.max(1)) } as *mut u8;
        if ptr.is_null() { return None; }
        let mut s = Secret { ptr, len };
        s.fill(0);
        Some(s)
    }

    /// Locks the first `len` bytes against swapping. sodium_malloc tries, but
    /// only within the locked memory limit (RLIMIT_MEMLOCK, often 8 MiB), and
    /// says nothing when it can't; locking again tells. False if they can't be.
    pub fn lock(&mut self, len: usize) -> bool {
        len == 0 || unsafe { sys::sodium_mlock(self.ptr.cast(), len.min(self.len)) } == 0
    }

    pub fn from_slice(data: &[u8]) -> Option<Secret> {
        let mut s = Secret::new(data.len())?;
        s.copy_from_slice(data);
        Some(s)
    }
}

impl Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] { unsafe { std::slice::from_raw_parts(self.ptr, self.len) } }
}

impl DerefMut for Secret {
    fn deref_mut(&mut self) -> &mut [u8] { unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) } }
}

impl Drop for Secret {
    fn drop(&mut self) { unsafe { sys::sodium_free(self.ptr.cast()) } }
}
