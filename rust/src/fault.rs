// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Fault injection. Every call that can fail for reasons outside the
//! program's control (opening and reading files, creating, flushing, syncing,
//! closing and renaming the output, libsodium's locked allocations and
//! Argon2id) asks `should_fail` first. Built with the `fault-injection`
//! feature and run with `FAULT_AT=N`, the Nth such call fails as the real one
//! can, so a sweep over N walks every error path one at a time. At exit the
//! program says which call failed, or `FAULT_NOT_REACHED` if the run made
//! fewer than N, which tells a sweep it is done.
//!
//! Without the feature, `should_fail` is a constant `false`.

#[cfg(feature = "fault-injection")]
mod imp {
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    static ARMED_AT: AtomicU32 = AtomicU32::new(0); // fail this call number; 0 = never
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static FIRED: Mutex<Option<&'static str>> = Mutex::new(None);

    pub fn should_fail(name: &'static str) -> bool {
        let armed = ARMED_AT.load(Ordering::SeqCst);
        if armed == 0 { return false; }
        let mut fired = FIRED.lock().unwrap();
        if fired.is_some() { return false; }
        if CALLS.fetch_add(1, Ordering::SeqCst) + 1 != armed { return false; }
        *fired = Some(name);
        true
    }

    extern "C" fn report() {
        // Not through eprintln!: it can panic once stderr is gone
        let line = match *FIRED.lock().unwrap() {
            Some(name) => format!("FAULT_FIRED {name}\n"),
            None => "FAULT_NOT_REACHED\n".to_string(),
        };
        let line = CString::new(line).unwrap();
        unsafe { libc::write(2, line.as_ptr().cast(), line.as_bytes().len()) };
    }

    pub fn init() {
        if let Some(n) = std::env::var("FAULT_AT").ok().and_then(|v| v.parse::<u32>().ok()).filter(|&n| n > 0) {
            ARMED_AT.store(n, Ordering::SeqCst);
            unsafe { libc::atexit(report) };
        }
    }
}

#[cfg(not(feature = "fault-injection"))]
mod imp {
    #[inline(always)]
    pub fn should_fail(_: &'static str) -> bool { false }
    pub fn init() {}
}

pub use imp::{init, should_fail};

use std::io;
use std::path::Path;

/// `std::fs::read`, which can fail like fopen
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    if should_fail("fopen") { return Err(io::Error::from_raw_os_error(libc::EMFILE)); }
    std::fs::read(path)
}
