// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

use scattersteg::codec::{self, EmbedError};
use scattersteg::cover::Cover;
use scattersteg::sodium::{self, Secret};
use scattersteg::jpeg_io;
use std::ffi::{CStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

/// The terminal's line editor holds 4095 bytes per line and silently drops
/// the rest, so a line that long may have been cut short: refuse it.
const PASSPHRASE_MAX_LEN: usize = 4094;
/// Shorter passphrases are refused on encode (decode accepts any, for old
/// images). Length is a crude measure, so `passphrase` generates good ones.
const PASSPHRASE_MIN_LEN: usize = 12;

// Secrets (passphrase, message, keys, plaintext) live in sodium_malloc
// memory: locked so it can't be swapped to disk, fenced by guard pages, and
// wiped when dropped. They are read and written with read() and write(),
// never through a stdio buffer, which would keep a copy outside it.

/// Terminal settings to put back if a signal kills us while echo is off
static TTY_RESTORE_FD: AtomicI32 = AtomicI32::new(-1);
static mut TTY_RESTORE: MaybeUninit<libc::termios> = MaybeUninit::uninit();

const RESTORE_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// Restore echo, then die from the same signal. SA_RESETHAND has already
/// reinstated the default action, which runs once this handler returns.
extern "C" fn restore_tty_and_die(sig: libc::c_int) {
    unsafe {
        let fd = TTY_RESTORE_FD.load(Ordering::Relaxed);
        libc::tcsetattr(fd, libc::TCSANOW, (&raw const TTY_RESTORE).cast::<libc::termios>());
        let _ = libc::write(fd, b"\n".as_ptr().cast(), 1);
        libc::raise(sig);
    }
}

fn write_fd(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let w = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if w < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(e);
        }
        data = &data[w as usize..];
    }
    Ok(())
}

fn errno_message(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

/// Read a passphrase from the terminal with echo off. On EOF or error,
/// prints why and returns None.
fn read_passphrase(prompt: &str) -> Option<Secret> {
    let fail = || { eprintln!("Error: could not read passphrase"); None };
    if scattersteg::fault::should_fail("fopen") { return fail(); }
    let fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR) };
    if fd < 0 { return fail(); }
    let mut old = MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, old.as_mut_ptr()) } != 0 {
        unsafe { libc::close(fd) };
        return fail();
    }
    let old = unsafe { old.assume_init() };

    // Ctrl+C and friends would otherwise leave the terminal without echo.
    // A signal we were started ignoring (nohup, a script) stays ignored: it
    // can't kill us, so there's nothing to restore.
    TTY_RESTORE_FD.store(fd, Ordering::Relaxed);
    unsafe { (&raw mut TTY_RESTORE).cast::<libc::termios>().write(old) };
    let mut saved = [unsafe { std::mem::zeroed::<libc::sigaction>() }; 4];
    let mut on_signal: libc::sigaction = unsafe { std::mem::zeroed() };
    on_signal.sa_sigaction = restore_tty_and_die as *const () as usize;
    on_signal.sa_flags = libc::SA_RESETHAND;
    unsafe { libc::sigemptyset(&mut on_signal.sa_mask) };
    for (i, &sig) in RESTORE_SIGNALS.iter().enumerate() {
        unsafe {
            libc::sigaction(sig, std::ptr::null(), &mut saved[i]);
            if saved[i].sa_sigaction != libc::SIG_IGN { libc::sigaction(sig, &on_signal, std::ptr::null_mut()); }
        }
    }

    let mut silent = old;
    silent.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &silent) };
    let _ = write_fd(fd, prompt.as_bytes());

    // One byte at a time, unbuffered, so no copy of the passphrase is left
    // in a buffer of ours. Grows by copying; Secret wipes the old buffer.
    let mut buf = Secret::new(256);
    let mut len = 0;
    let mut hit_eof = false;
    while let Some(b) = buf.as_mut() {
        let mut c = 0u8;
        let n = unsafe { libc::read(fd, (&raw mut c).cast(), 1) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
        if n <= 0 {
            hit_eof = true;
            break;
        }
        if c == b'\n' { break; }
        if len + 1 >= b.len() {
            let mut bigger = Secret::new(b.len() + 256);
            if let Some(bg) = bigger.as_mut() { bg[..len].copy_from_slice(&b[..len]); }
            buf = bigger;
            if buf.is_none() { break; }
        }
        buf.as_mut().unwrap()[len] = c;
        len += 1;
    }

    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old) };
    for (i, &sig) in RESTORE_SIGNALS.iter().enumerate() {
        unsafe { libc::sigaction(sig, &saved[i], std::ptr::null_mut()) };
    }
    let _ = write_fd(fd, b"\n");
    unsafe { libc::close(fd) };

    let Some(buf) = buf else { return fail() }; // out of memory
    if hit_eof && len == 0 { return fail(); } // Ctrl+D
    if len > PASSPHRASE_MAX_LEN {
        eprintln!("Error: passphrase too long (max {PASSPHRASE_MAX_LEN} bytes)");
        return None;
    }
    // The C version held the passphrase as a C string, so it ends at the first
    // NUL (Ctrl+@, or pasted): keep that, or its images wouldn't decode here
    let len = buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
    match Secret::from_slice(&buf[..len]) {
        Some(p) => Some(p),
        None => fail(),
    }
}

enum ReadError {
    TooLong,
    Io(io::Error),
}

/// Read the entire contents of stdin into a Secret. Prints a prompt first if
/// stdin is a terminal. The message may hold any bytes, NUL included: its
/// length (less a final newline) is the Secret's. Stops reading once that is
/// longer than max_len, so a huge stdin can't exhaust memory or overflow the
/// payload length.
fn read_message(max_len: usize) -> Result<Secret, ReadError> {
    if unsafe { libc::isatty(0) } == 1 { eprintln!("Message (Ctrl+D when done):"); }

    let oom = || ReadError::Io(io::Error::from_raw_os_error(libc::ENOMEM));
    let mut cap = 1024;
    let mut len = 0;
    let mut buf = Secret::new(cap).ok_or_else(oom)?;

    // read(), not stdio: a buffer would keep a copy of the message in
    // ordinary heap memory, unlocked and never wiped
    loop {
        if len + 1 >= cap {
            let mut bigger = Secret::new(cap * 2).ok_or_else(oom)?;
            bigger[..len].copy_from_slice(&buf[..len]);
            buf = bigger;
            cap *= 2;
        }
        // max_len + 2 bytes in all tell a message that is too long
        let want = (cap - 1 - len).min(max_len + 2 - len);
        let n = unsafe { libc::read(0, buf[len..].as_mut_ptr().cast(), want) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(ReadError::Io(e)); // not the end: don't hide a partial message
        }
        if n == 0 { break; }
        len += n as usize;
        if len > max_len + 1 { return Err(ReadError::TooLong); } // max_len + 1 is fine if the last is '\n'
    }

    if len > 0 && buf[len - 1] == b'\n' { len -= 1; }
    if len > max_len { return Err(ReadError::TooLong); }
    let mut msg = Secret::new(len).ok_or_else(oom)?;
    msg.copy_from_slice(&buf[..len]);
    Ok(msg)
}

/// Print a random passphrase: 5 groups of 5 characters from a 31-character
/// alphabet without look-alikes (0/o, 1/l/i), about 124 bits in all.
fn generate_passphrase() -> io::Result<()> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut out = [0u8; 30];
    let mut n = 0;
    for group in 0..5 {
        if group > 0 { out[n] = b'-'; n += 1; }
        for _ in 0..5 {
            out[n] = ALPHABET[sodium::random_uniform(ALPHABET.len() as u32) as usize];
            n += 1;
        }
    }
    out[n] = b'\n';
    let r = write_fd(1, &out);
    sodium::memzero(&mut out);
    r
}

/// Keep secrets out of core dumps, and (Linux) stop other processes of the
/// same user from attaching a debugger to read them
fn protect_process() {
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn usage(prog: &str) {
    eprintln!("Usage: {prog} encode -i <cover.png|jpg> -o <output.png|jpg>");
    eprintln!("       {prog} decode -i <image.png|jpg>");
    eprintln!("       {prog} passphrase");
    eprintln!("Message is read from stdin. `passphrase` prints a strong random passphrase.");
}

/// The output has the cover's format; refuse a name that says otherwise
fn output_name_matches(input: &Path, output: &Path) -> bool {
    let name = output.as_os_str().as_bytes();
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else { return true };
    let ext = &name[dot..];
    let says_jpeg = ext.eq_ignore_ascii_case(b".jpg") || ext.eq_ignore_ascii_case(b".jpeg");
    let says_png = ext.eq_ignore_ascii_case(b".png");
    let jpeg = jpeg_io::is_jpeg_file(input);
    if if jpeg { says_png } else { says_jpeg } {
        eprintln!("Error: the output is a {}, like the cover; give it a {} name",
                  if jpeg { "JPEG" } else { "PNG" }, if jpeg { ".jpg" } else { ".png" });
        return false;
    }
    true
}

struct Args {
    input: Option<OsString>,
    output: Option<OsString>,
}

/// getopt "i:o:" over the arguments after the command; None on a bad option
fn parse_options(args: &[OsString]) -> Option<Args> {
    let mut out = Args { input: None, output: None };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_bytes();
        i += 1;
        if a == b"--" { break; }
        if a.len() < 2 || a[0] != b'-' { continue; } // a non-option: getopt permutes it past
        let slot = match a[1] { b'i' => &mut out.input, b'o' => &mut out.output, _ => return None };
        *slot = Some(if a.len() > 2 {
            OsString::from(<OsString as std::os::unix::ffi::OsStringExt>::from_vec(a[2..].to_vec()))
        } else {
            let v = args.get(i)?.clone();
            i += 1;
            v
        });
    }
    Some(out)
}

fn encode(input: &Path, output: &Path) -> ExitCode {
    if !output_name_matches(input, output) { return ExitCode::FAILURE; }
    // Checked again when writing; here, before the passphrase prompt
    if let Ok(m) = std::fs::metadata(output) {
        if !m.is_file() {
            eprintln!("Error: '{}' exists and is not a regular file", output.display());
            return ExitCode::FAILURE;
        }
    }

    let Some(passphrase) = read_passphrase("Passphrase: ") else { return ExitCode::FAILURE };
    if passphrase.len() < PASSPHRASE_MIN_LEN {
        eprintln!("Error: passphrase too short (min {PASSPHRASE_MIN_LEN} bytes); \
                   `scattersteg passphrase` generates a strong one");
        return ExitCode::FAILURE;
    }
    let Some(confirm) = read_passphrase("Confirm passphrase: ") else { return ExitCode::FAILURE };
    if *passphrase != *confirm {
        eprintln!("Error: passphrases do not match");
        return ExitCode::FAILURE;
    }
    drop(confirm);

    let Some(mut cover) = Cover::load(input) else {
        eprintln!("Error: could not load '{}'", input.display());
        return ExitCode::FAILURE;
    };

    // A PNG output is 8-bit RGB or gray: any other cover would come out in a
    // visibly different format, which gives it away
    match &mut cover {
        Cover::Png(img) => if let Some(why) = img.unsuitable {
            eprintln!("Error: '{}' has {why}, which the output can't keep; use an 8-bit RGB or \
                       grayscale PNG without transparency as the cover", input.display());
            return ExitCode::FAILURE;
        },
        Cover::Jpeg(j) => {
            if let Some(why) = j.unsuitable() {
                eprintln!("Error: '{}' has {why}, which the output can't keep; use another cover",
                          input.display());
                return ExitCode::FAILURE;
            }
            if !j.check_writable() {
                eprintln!("Error: '{}' is a JPEG that can't be rewritten losslessly; use another cover",
                          input.display());
                return ExitCode::FAILURE;
            }
        }
    }

    let prepared = match codec::prepare_encode(&cover.carrier(), &passphrase) {
        Ok(p) => p,
        Err(None) => {
            eprintln!("Error: image too small to hide a message");
            return ExitCode::FAILURE;
        }
        Err(Some(msg)) => {
            eprintln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    drop(passphrase);

    let message = match read_message(prepared.max_message()) {
        Ok(m) => m,
        Err(ReadError::TooLong) => {
            eprintln!("Error: message too long for this image");
            return ExitCode::FAILURE;
        }
        Err(ReadError::Io(e)) => {
            eprintln!("Error: could not read message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
    };
    // Empty message: nothing to hide, so write nothing
    if message.is_empty() {
        eprintln!("Message is empty; nothing written");
        return ExitCode::SUCCESS;
    }

    if let Err(e) = prepared.embed(&mut cover.carrier(), &message) {
        match e {
            EmbedError::TooLong => eprintln!("Error: message too long for this image"),
            EmbedError::Alloc => eprintln!("Error: allocation failed"),
        }
        return ExitCode::FAILURE;
    }
    drop(message);

    if let Err(e) = cover.save(output) {
        let why = match e.raw_os_error() {
            Some(0) | None => if cover.is_jpeg() { "JPEG encoding failed" } else { "PNG encoding failed" }.to_string(),
            Some(_) => errno_message(&e),
        };
        eprintln!("Error: could not write '{}': {why}", output.display());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn decode(input: &Path) -> ExitCode {
    let Some(passphrase) = read_passphrase("Passphrase: ") else { return ExitCode::FAILURE };
    let Some(mut cover) = Cover::load(input) else {
        eprintln!("Error: could not load '{}'", input.display());
        return ExitCode::FAILURE;
    };
    let carrier = cover.carrier();
    if carrier.positions() < codec::header_pixels(carrier.channels()) {
        eprintln!("Error: image too small to contain a message");
        return ExitCode::FAILURE;
    }

    let result = codec::decode(&carrier, &passphrase);
    drop(passphrase);
    drop(cover);
    let mut found = match result {
        Ok(Some(f)) => f,
        Ok(None) => {
            eprintln!("Error: decryption failed — wrong passphrase, or no message in this image");
            return ExitCode::FAILURE;
        }
        Err(msg) => {
            eprintln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    if found.v1 {
        eprintln!("Warning: this image uses the old v1 format, which protects the passphrase less \
                   well; re-encode it");
    }

    if found.len > 0 { // empty message: print nothing
        // All of it, NULs too. The newline goes in the same write, so the
        // plaintext buffer has room: it has a spare byte.
        found.plaintext[found.len] = b'\n';
        if let Err(e) = write_fd(1, &found.plaintext[..found.len + 1]) {
            // e.g. a full disk: the message was not saved
            eprintln!("Error: could not write the message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    scattersteg::fault::init();
    protect_process();
    if sodium::init().is_err() {
        eprintln!("Error: failed to initialise libsodium");
        return ExitCode::FAILURE;
    }

    let args: Vec<OsString> = std::env::args_os().collect();
    let prog = args.first().map_or_else(|| "scattersteg".into(), |a| a.to_string_lossy().into_owned());
    if args.len() < 2 {
        usage(&prog);
        return ExitCode::FAILURE;
    }
    let Some(opts) = parse_options(&args[2..]) else {
        usage(&prog);
        return ExitCode::FAILURE;
    };

    match args[1].as_bytes() {
        b"passphrase" => match generate_passphrase() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: could not write the passphrase: {}", errno_message(&e));
                ExitCode::FAILURE
            }
        },
        b"encode" => match (&opts.input, &opts.output) {
            (Some(i), Some(o)) => encode(Path::new(i), Path::new(o)),
            _ => {
                eprintln!("Error: encode requires -i and -o");
                usage(&prog);
                ExitCode::FAILURE
            }
        },
        b"decode" => match &opts.input {
            Some(i) => decode(Path::new(i)),
            None => {
                eprintln!("Error: decode requires -i");
                usage(&prog);
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("Error: unknown command '{}'", String::from_utf8_lossy(other));
            usage(&prog);
            ExitCode::FAILURE
        }
    }
}
