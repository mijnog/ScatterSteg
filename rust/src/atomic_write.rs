// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Writes a file by writing a temp file beside `path`, then renaming it into
//! place, so a failed write never truncates or deletes an existing file
//! (e.g. -i a.png -o a.png). A symlink at `path` is written through, and an
//! existing file keeps its permissions and group. Anything at `path` other
//! than a regular file (a FIFO, device, directory...) is left alone: EINVAL.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// `write` gets the temp file; an Err from it is returned as is
pub fn atomic_write<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    // Write through a symlink to the file it points to rather than replacing
    // the link itself. A new path, or a dangling link, is used as is.
    let target = fs::canonicalize(path).ok();
    let dest = target.as_deref().unwrap_or(path);
    let existing = fs::metadata(dest).ok();
    // rename would replace a FIFO, socket or device (even /dev/null, as
    // root) with a regular file, rather than write to it: refuse
    if let Some(m) = &existing {
        if !m.is_file() { return Err(io::Error::from_raw_os_error(libc::EINVAL)); }
    }

    let mut template = dest.as_os_str().as_bytes().to_vec();
    template.extend_from_slice(b".XXXXXX");
    let template = CString::new(template).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut tmp = template.into_bytes_with_nul();
    // SAFETY: tmp is a writable NUL-terminated buffer
    let fd = unsafe { libc::mkstemp(tmp.as_mut_ptr().cast()) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    tmp.pop();
    let tmp_path = std::path::PathBuf::from(std::ffi::OsString::from_vec(tmp));
    // SAFETY: fd is a fresh descriptor we own
    let mut file = unsafe { File::from_raw_fd(fd) };

    let result = (|| -> io::Result<()> {
        // Replacing a file: keep its permissions and group, so a private
        // image stays private and a shared one stays shared. If its group
        // can't be kept (we're not a member), don't grant its group bits to
        // another. A new file gets the usual umask-based mode.
        let mode = match &existing {
            Some(m) => {
                let mut mode = m.mode() & 0o777;
                if unsafe { libc::fchown(fd, u32::MAX, m.gid()) } != 0 { mode &= !0o070; }
                mode
            }
            None => {
                let mask = unsafe { libc::umask(0) };
                unsafe { libc::umask(mask) };
                0o666 & !(mask as u32)
            }
        };
        if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 { return Err(io::Error::last_os_error()); }
        write(&mut file)?;
        // Buffered write errors (disk full, quota) only surface here
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    let result = result.and_then(|()| fs::rename(&tmp_path, dest));
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}
