// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Writes a file by writing a temp file beside `path`, then renaming it into
//! place, so a failed write never truncates or deletes an existing file
//! (e.g. -i a.png -o a.png). A symlink at `path` is written through, and an
//! existing file keeps its permissions and group. Anything at `path` other
//! than a regular file (a FIFO, device, directory...) is left alone: EINVAL.
//! SIGINT, SIGQUIT, SIGTERM and SIGHUP are held until the temp file is
//! renamed or removed, so none leaves it behind.

use crate::fault::should_fail;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn os_error(errno: i32) -> io::Error { io::Error::from_raw_os_error(errno) }

/// `write` gets the temp file; an Err from it is returned as is. It must
/// flush anything it buffers itself.
///
/// Ctrl+C (or kill, or a closed terminal) while the temp file exists would
/// leave it behind, beside the output. So those signals wait until it has
/// been renamed into place or removed; one that arrived meanwhile is
/// delivered then. The CLI writes from memory, so this holds them for the
/// write and fsync alone.
pub fn atomic_write<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    // SAFETY: plain signal-mask calls on sigset_ts we own
    let old = unsafe {
        let mut hold: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut hold);
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] { libc::sigaddset(&mut hold, sig); }
        libc::pthread_sigmask(libc::SIG_BLOCK, &hold, &mut old);
        old
    };
    let result = write_and_rename(path, write);
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    result
}

/// Make the rename itself durable: until the directory is synced, a crash
/// can lose it even though the file's data was synced. Best effort: the file
/// is already in place, and some filesystems can't sync a directory.
fn sync_dir_of(dest: &Path) {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if let Ok(d) = File::open(dir) { let _ = d.sync_all(); }
}

fn write_and_rename<F>(path: &Path, write: F) -> io::Result<()>
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
    if existing.as_ref().is_some_and(|m| !m.is_file()) { return Err(os_error(libc::EINVAL)); }

    let mut template = dest.as_os_str().as_bytes().to_vec();
    template.extend_from_slice(b".XXXXXX");
    let mut tmp = CString::new(template).map_err(|_| os_error(libc::EINVAL))?.into_bytes_with_nul();
    if should_fail("mkstemp") { return Err(os_error(libc::EEXIST)); }
    // SAFETY: tmp is a writable NUL-terminated buffer
    let fd = unsafe { libc::mkstemp(tmp.as_mut_ptr().cast()) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    tmp.pop();
    let tmp_path = PathBuf::from(std::ffi::OsString::from_vec(tmp));
    // SAFETY: fd is a fresh descriptor we own
    let mut file = unsafe { File::from_raw_fd(fd) };

    let written = (|| -> io::Result<()> {
        // Replacing a file: keep its permissions and group, so a private
        // image stays private and a shared one stays shared. If its group
        // can't be kept (we're not a member), don't grant its group bits to
        // another. A new file gets the usual umask-based mode.
        let mode = match &existing {
            Some(m) => {
                let mut mode = m.mode() & 0o777;
                if should_fail("fchown") || unsafe { libc::fchown(fd, u32::MAX, m.gid()) } != 0 { mode &= !0o070; }
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
        if should_fail("fflush") { return Err(os_error(libc::ENOSPC)); }
        file.flush()?;
        if should_fail("fsync") { return Err(os_error(libc::EIO)); }
        file.sync_all()?;
        Ok(())
    })();

    // close() can report a write error too, which File's drop would swallow.
    // It releases the descriptor even when it fails.
    let raw = file.into_raw_fd();
    let closed = if unsafe { libc::close(raw) } != 0 { Err(io::Error::last_os_error()) }
                 else if should_fail("fclose") { Err(os_error(libc::EIO)) } else { Ok(()) };
    let result = written.and(closed).and_then(|()| {
        if should_fail("rename") { return Err(os_error(libc::EXDEV)); }
        fs::rename(&tmp_path, dest)?;
        sync_dir_of(dest);
        Ok(())
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::atomic_write;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::OnceLock;

    // Ctrl+C mid-write: the signal waits until the temp file is renamed into
    // place or removed, so it is never left behind
    static PATHS: OnceLock<(CString, CString)> = OnceLock::new();  // dir, output
    static ENTRIES: AtomicI32 = AtomicI32::new(-1);
    static OUTPUT: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn count_on_signal(_: libc::c_int) {
        let (dir, out) = PATHS.get().unwrap();
        // SAFETY: valid C strings; the directory exists
        unsafe {
            let d = libc::opendir(dir.as_ptr());
            let mut n = 0;
            loop {
                let e = libc::readdir(d);
                if e.is_null() { break; }
                let name = std::ffi::CStr::from_ptr((*e).d_name.as_ptr()).to_bytes();
                if name != b"." && name != b".." { n += 1; }
            }
            libc::closedir(d);
            ENTRIES.store(n, Ordering::SeqCst);
            OUTPUT.store((libc::access(out.as_ptr(), libc::F_OK) == 0) as i32, Ordering::SeqCst);
        }
    }

    #[test]
    fn signal_waits_for_write() {
        let dir = std::env::temp_dir().join(format!("scattersteg-aw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("sig.out");
        let c = |p: &std::path::Path| CString::new(p.as_os_str().as_bytes()).unwrap();
        PATHS.set((c(&dir), c(&out))).unwrap();
        let mut on: libc::sigaction = unsafe { std::mem::zeroed() };
        on.sa_sigaction = count_on_signal as *const () as usize;
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaction(libc::SIGINT, &on, &mut old) };
        for fail in [false, true] {
            ENTRIES.store(-1, Ordering::SeqCst);
            OUTPUT.store(-1, Ordering::SeqCst);
            let r = atomic_write(&out, |f| {
                use std::io::Write;
                f.write_all(b"data")?;
                unsafe { libc::raise(libc::SIGINT) };
                if fail { Err(std::io::Error::other("failed")) } else { Ok(()) }
            });
            assert_eq!(r.is_err(), fail);
            // just the output, or nothing
            assert_eq!(ENTRIES.load(Ordering::SeqCst), if fail { 0 } else { 1 }, "fail: {fail}");
            assert_eq!(OUTPUT.load(Ordering::SeqCst), !fail as i32, "fail: {fail}");
            let _ = std::fs::remove_file(&out);
        }
        unsafe { libc::sigaction(libc::SIGINT, &old, std::ptr::null_mut()) };
        let _ = std::fs::remove_dir(&dir);
    }
}
