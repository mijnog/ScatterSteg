// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

/// `eprintln!` panics if stderr can't be written (a closed pipe, a full disk),
/// which would turn a diagnostic into exit status 101. The C version ignored
/// the failure, as this does.
#[macro_export]
macro_rules! errln {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = writeln!(::std::io::stderr(), $($arg)*);
    }};
}

pub mod atomic_write;
pub mod codec;
pub mod cover;
pub mod embed;
pub mod fault;
pub mod png_io;
pub mod prng;
pub mod sodium;
pub mod stc;
pub mod jpeg_sys;
pub mod jpeg_io;
pub mod zlib_sys;
pub mod compress;
