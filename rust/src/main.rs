// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

use scattersteg::codec::{self, EmbedError};
use scattersteg::compress;
use scattersteg::cover::{Cover, SaveError};
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
/// Shorter passphrases are refused on encode (on decode, one can only fail).
/// Length is a crude measure, so `passphrase` generates good ones.
const PASSPHRASE_MIN_LEN: usize = 12;

// Secrets (passphrase, message, keys, plaintext) live in sodium_malloc
// memory: locked so it can't be swapped to disk (within the locked memory
// limit: see warn_if_swappable), fenced by guard pages, and
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
/// prints why and returns None. One with a NUL byte (typed as Ctrl+@, or
/// pasted) is refused: the C version would end it there, silently cutting it
/// short.
fn read_passphrase(prompt: &str) -> Option<Secret> {
    let fail = || { scattersteg::errln!("Error: could not read passphrase"); None };
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
    let mut c = 0u8;
    let mut len = 0;
    let mut hit_eof = false;
    while let Some(b) = buf.as_mut() {
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
    sodium::memzero(std::slice::from_mut(&mut c)); // the last byte read

    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old) };
    for (i, &sig) in RESTORE_SIGNALS.iter().enumerate() {
        unsafe { libc::sigaction(sig, &saved[i], std::ptr::null_mut()) };
    }
    let _ = write_fd(fd, b"\n");
    unsafe { libc::close(fd) };

    let Some(buf) = buf else { return fail() }; // out of memory
    if hit_eof && len == 0 { return fail(); } // Ctrl+D
    if len > PASSPHRASE_MAX_LEN {
        scattersteg::errln!("Error: passphrase too long (max {PASSPHRASE_MAX_LEN} bytes)");
        return None;
    }
    if buf[..len].contains(&0) {
        scattersteg::errln!("Error: the passphrase contains a NUL byte (Ctrl+@), which would cut it short");
        return None;
    }
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
/// stdin is a terminal, unless quiet. The message may hold any bytes, NUL included: its
/// length (less a final newline, unless raw) is the Secret's. Stops reading once that is
/// longer than max_len, so a huge stdin can't exhaust memory or overflow the
/// payload length.
fn read_message(max_len: usize, raw: bool, quiet: bool) -> Result<Secret, ReadError> {
    if !quiet && unsafe { libc::isatty(0) } == 1 { scattersteg::errln!("Message (Ctrl+D when done):"); }

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

    if !raw && len > 0 && buf[len - 1] == b'\n' { len -= 1; }
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

/// Say so if the message's `len` bytes in `s` can't be locked against swapping
fn warn_if_swappable(s: &mut Secret, len: usize) {
    if s.lock(len) { return; }
    let mut lock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lock) } == 0 && lock.rlim_cur != libc::RLIM_INFINITY {
        scattersteg::errln!("Warning: the message is larger than the memory this process may lock \
                   ({} KiB, see `ulimit -l`), so it may be written to swap", lock.rlim_cur / 1024);
    } else {
        scattersteg::errln!("Warning: the message could not be locked in memory, so it may be written to swap");
    }
}

/// Keep secrets out of core dumps, and (Linux) stop other processes of the
/// same user from attaching a debugger to read them
fn protect_process() {
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        // Let sodium_malloc lock as much as we may: the soft limit can be
        // below the hard one
        let mut lock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lock) == 0 && lock.rlim_cur < lock.rlim_max {
            lock.rlim_cur = lock.rlim_max;
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &lock);
        }
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// To stderr after a mistake, to stdout when asked for (help)
fn usage(prog: &str, to_stdout: bool) -> io::Result<()> {
    let text = format!(
        "Usage: {prog} encode [-r] [-q] -i <cover.png|jpg> -o <output.png|jpg>\n\
         \x20      {prog} decode [-r] [-q] -i <image.png|jpg>\n\
         \x20      {prog} info -i <cover.png|jpg>\n\
         \x20      {prog} passphrase | help | version\n\
         Message is read from stdin. `passphrase` prints a strong random passphrase.\n\
         `info` says whether an image can be a cover, and the longest message it holds.\n\
         Without -r, encode drops one trailing newline and decode adds one; -r keeps the bytes exactly.\n\
         -q prints only prompts for the passphrase, warnings and errors.\n");
    if to_stdout { write_fd(1, text.as_bytes()) } else { let _ = write_fd(2, text.as_bytes()); Ok(()) }
}

/// Whether the cover can carry a message: the output would keep its format
/// and not give the changes away, and it holds at least one byte. If not,
/// prints why. Checks a JPEG can be rewritten by encoding it in memory, so it
/// costs about as much as loading it.
fn check_cover(cover: &mut Cover, input: &Path) -> bool {
    // A PNG output is 8-bit RGB or gray: any other cover would come out in a
    // visibly different format, which gives it away
    let unsuitable = match cover {
        Cover::Png(img) => img.unsuitable.map(|why| (why, "use an 8-bit RGB or grayscale PNG without transparency as the cover")),
        Cover::Jpeg(j) => j.unsuitable().map(|why| (why, "use another cover")),
    };
    if let Some((why, advice)) = unsuitable {
        scattersteg::errln!("Error: '{}' has {why}, which the output can't keep; {advice}", input.display());
        return false;
    }
    // Before check_writable, which decodes the cover again: a few bytes can
    // declare a huge frame with next to no carriers
    if codec::capacity(&cover.carrier()) == 0 {
        scattersteg::errln!("Error: image too small to hide a message");
        return false;
    }
    if let Cover::Jpeg(j) = cover && !j.check_writable() {
        scattersteg::errln!("Error: '{}' is a JPEG that can't be rewritten losslessly; use another cover",
                  input.display());
        return false;
    }
    true
}

/// info: the cover's format and size, and the longest message it holds, or
/// why it can't be a cover. Needs no passphrase: the capacity depends on the
/// image alone.
fn info(input: &Path) -> ExitCode {
    let Some(mut cover) = Cover::load(input) else {
        scattersteg::errln!("Error: could not load '{}'", input.display());
        return ExitCode::FAILURE;
    };
    if !check_cover(&mut cover, input) { return ExitCode::FAILURE; }
    let format = match &cover {
        Cover::Png(img) => format!("PNG, {}x{}, {}", img.width, img.height, if img.channels == 1 { "gray" } else { "RGB" }),
        Cover::Jpeg(j) => { let (w, h) = j.size(); format!("JPEG, {w}x{h}") }
    };
    let capacity = codec::capacity(&cover.carrier());
    drop(cover);
    if let Err(e) = write_fd(1, format!("Format:   {format}\nCapacity: {capacity} bytes (more if the message compresses)\n").as_bytes()) {
        scattersteg::errln!("Error: could not write the information: {}", errno_message(&e));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
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
        scattersteg::errln!("Error: the output is a {}, like the cover; give it a {} name",
                  if jpeg { "JPEG" } else { "PNG" }, if jpeg { ".jpg" } else { ".png" });
        return false;
    }
    true
}

struct Args {
    input: Option<OsString>,
    output: Option<OsString>,
    raw: bool, // -r: no newline stripped from the message or added to it
    quiet: bool, // -q: no progress messages
    extra: Vec<OsString>, // non-option arguments, which no command takes
}

/// getopt "i:o:rq" over the arguments after the command; None on a bad option
fn parse_options(args: &[OsString]) -> Option<Args> {
    let mut out = Args { input: None, output: None, raw: false, quiet: false, extra: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_bytes();
        i += 1;
        if a == b"--" { out.extra.extend_from_slice(&args[i..]); break; }
        if a.len() < 2 || a[0] != b'-' { out.extra.push(args[i - 1].clone()); continue; } // as getopt permutes it past
        let mut k = 1; // a cluster such as -ri file: flags, then an option that takes a value
        while k < a.len() {
            let slot = match a[k] {
                b'r' => { out.raw = true; k += 1; continue; }
                b'q' => { out.quiet = true; k += 1; continue; }
                b'i' => &mut out.input,
                b'o' => &mut out.output,
                _ => return None,
            };
            *slot = Some(if a.len() > k + 1 {
                OsString::from(<OsString as std::os::unix::ffi::OsStringExt>::from_vec(a[k + 1..].to_vec()))
            } else {
                let v = args.get(i)?.clone();
                i += 1;
                v
            });
            break;
        }
    }
    Some(out)
}

fn encode(input: &Path, output: &Path, raw: bool, quiet: bool) -> ExitCode {
    // Before the name check, which reads the input's first bytes: a missing
    // file would otherwise be called a PNG
    let opened = if scattersteg::fault::should_fail("fopen") { Err(io::Error::from_raw_os_error(libc::EMFILE)) }
                 else { std::fs::File::open(input).map(drop) };
    if let Err(e) = opened {
        scattersteg::errln!("Error: could not load '{}': {}", input.display(), errno_message(&e));
        return ExitCode::FAILURE;
    }
    if !output_name_matches(input, output) { return ExitCode::FAILURE; }
    // Checked again when writing; here, before the passphrase prompt
    if let Ok(m) = std::fs::metadata(output) {
        if !m.is_file() {
            scattersteg::errln!("Error: '{}' exists and is not a regular file", output.display());
            return ExitCode::FAILURE;
        }
    }

    let Some(passphrase) = read_passphrase("Passphrase: ") else { return ExitCode::FAILURE };
    if passphrase.len() < PASSPHRASE_MIN_LEN {
        scattersteg::errln!("Error: passphrase too short (min {PASSPHRASE_MIN_LEN} bytes); \
                   `scattersteg passphrase` generates a strong one");
        return ExitCode::FAILURE;
    }
    let Some(confirm) = read_passphrase("Confirm passphrase: ") else { return ExitCode::FAILURE };
    if *passphrase != *confirm {
        scattersteg::errln!("Error: passphrases do not match");
        return ExitCode::FAILURE;
    }
    drop(confirm);

    let Some(mut cover) = Cover::load(input) else {
        scattersteg::errln!("Error: could not load '{}'", input.display());
        return ExitCode::FAILURE;
    };

    if !check_cover(&mut cover, input) { return ExitCode::FAILURE; }

    if !quiet { scattersteg::errln!("Deriving keys..."); }
    let prepared = match codec::prepare_encode(&cover.carrier(), &passphrase) {
        Ok(p) => p,
        Err(None) => {
            scattersteg::errln!("Error: image too small to hide a message");
            return ExitCode::FAILURE;
        }
        Err(Some(msg)) => {
            scattersteg::errln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    drop(passphrase);

    let holds = prepared.max_message();
    let mut message = match read_message(compress::MESSAGE_MAX, raw, quiet) {
        Ok(m) => m,
        Err(ReadError::TooLong) => {
            scattersteg::errln!("Error: message too long (max {} MiB)", compress::MESSAGE_MAX >> 20);
            return ExitCode::FAILURE;
        }
        Err(ReadError::Io(e)) => {
            scattersteg::errln!("Error: could not read message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
    };
    // Empty message: almost always a mistake (nothing piped in, an empty
    // file, Ctrl+D too soon), and a script must not take it for a written
    // output: fail, and write nothing
    if message.is_empty() {
        scattersteg::errln!("Error: the message is empty; nothing written");
        return ExitCode::FAILURE;
    }
    let len = message.len();
    warn_if_swappable(&mut message, len);

    if let Err(e) = prepared.embed(&mut cover.carrier(), &message) {
        match e {
            EmbedError::TooLong => scattersteg::errln!("Error: message too long for this image, which holds {holds} \
                                                        bytes (more if the message compresses well)"),
            EmbedError::Alloc => scattersteg::errln!("Error: allocation failed"),
        }
        return ExitCode::FAILURE;
    }
    drop(message);

    let is_jpeg = cover.is_jpeg();
    match cover.save(output) {
        Ok(()) => {}
        Err(SaveError::Io(e)) => {
            let why = match e.raw_os_error() {
                Some(0) | None => if is_jpeg { "JPEG encoding failed" } else { "PNG encoding failed" }.to_string(),
                Some(_) => errno_message(&e),
            };
            scattersteg::errln!("Error: could not write '{}': {why}", output.display());
            return ExitCode::FAILURE;
        }
        Err(SaveError::Unreadable) => {
            scattersteg::errln!("Error: could not read the output back to check it (out of memory?); nothing written");
            return ExitCode::FAILURE;
        }
        Err(SaveError::Changed) => {
            scattersteg::errln!("Error: the output didn't read back as written, so the message would be lost; \
                       nothing written. Please report this, with the cover if you can");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn decode(input: &Path, raw: bool, quiet: bool) -> ExitCode {
    let Some(passphrase) = read_passphrase("Passphrase: ") else { return ExitCode::FAILURE };
    let Some(mut cover) = Cover::load(input) else {
        scattersteg::errln!("Error: could not load '{}'", input.display());
        return ExitCode::FAILURE;
    };
    let carrier = cover.carrier();
    if carrier.positions() < codec::header_pixels(carrier.channels()) {
        scattersteg::errln!("Error: image too small to contain a message");
        return ExitCode::FAILURE;
    }

    if !quiet { scattersteg::errln!("Deriving keys..."); }
    let result = codec::decode(&carrier, &passphrase);
    drop(passphrase);
    drop(cover);
    let mut found = match result {
        Ok(Some(f)) => f,
        Ok(None) => {
            scattersteg::errln!("Error: decryption failed — wrong passphrase, or no message in this image");
            return ExitCode::FAILURE;
        }
        Err(msg) => {
            scattersteg::errln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    warn_if_swappable(&mut found.plaintext, found.len);
    if found.len > 0 { // empty message: print nothing
        // All of it, NULs too. The newline goes in the same write, so the
        // plaintext buffer has room: it has a spare byte.
        if !raw { found.plaintext[found.len] = b'\n'; }
        if let Err(e) = write_fd(1, &found.plaintext[..found.len + usize::from(!raw)]) {
            // e.g. a full disk: the message was not saved
            scattersteg::errln!("Error: could not write the message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    scattersteg::fault::init();
    protect_process();
    if sodium::init().is_err() {
        scattersteg::errln!("Error: failed to initialise libsodium");
        return ExitCode::FAILURE;
    }

    let args: Vec<OsString> = std::env::args_os().collect();
    let prog = args.first().map_or_else(|| "scattersteg".into(), |a| a.to_string_lossy().into_owned());
    if args.len() < 2 {
        let _ = usage(&prog, false);
        return ExitCode::FAILURE;
    }
    // The usual spellings of help and version, as their commands
    let cmd: &[u8] = match args[1].as_bytes() {
        b"-h" | b"--help" => b"help",
        b"--version" => b"version",
        other => other,
    };
    let Some(opts) = parse_options(&args[2..]) else {
        let _ = usage(&prog, false);
        return ExitCode::FAILURE;
    };

    // Anything left over, or an option the command doesn't use, is a typo or
    // a misunderstanding: say so rather than ignore it
    let bare = matches!(cmd, b"passphrase" | b"help" | b"version");
    let known = bare || matches!(cmd, b"encode" | b"decode" | b"info");
    if let (true, Some(a)) = (known, opts.extra.first()) {
        scattersteg::errln!("Error: unexpected argument '{}'", a.to_string_lossy());
        let _ = usage(&prog, false);
        return ExitCode::FAILURE;
    }

    match cmd {
        _ if bare && (opts.input.is_some() || opts.output.is_some() || opts.raw || opts.quiet) => {
            scattersteg::errln!("Error: {} takes no options", String::from_utf8_lossy(cmd));
            let _ = usage(&prog, false);
            ExitCode::FAILURE
        }
        b"decode" if opts.input.is_some() && opts.output.is_some() => {
            scattersteg::errln!("Error: decode takes no -o; the message goes to stdout (redirect it with >)");
            let _ = usage(&prog, false);
            ExitCode::FAILURE
        }
        b"passphrase" => match generate_passphrase() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                scattersteg::errln!("Error: could not write the passphrase: {}", errno_message(&e));
                ExitCode::FAILURE
            }
        },
        b"help" => match usage(&prog, true) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        b"version" => match write_fd(1, concat!("scattersteg ", env!("CARGO_PKG_VERSION"), "\n").as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                scattersteg::errln!("Error: could not write the version: {}", errno_message(&e));
                ExitCode::FAILURE
            }
        },
        b"info" => match (&opts.input, &opts.output, opts.raw || opts.quiet) {
            (Some(i), None, false) => info(Path::new(i)),
            (None, _, _) => {
                scattersteg::errln!("Error: info requires -i");
                let _ = usage(&prog, false);
                ExitCode::FAILURE
            }
            _ => {
                scattersteg::errln!("Error: info takes only -i");
                let _ = usage(&prog, false);
                ExitCode::FAILURE
            }
        },
        b"encode" => match (&opts.input, &opts.output) {
            (Some(i), Some(o)) => encode(Path::new(i), Path::new(o), opts.raw, opts.quiet),
            _ => {
                scattersteg::errln!("Error: encode requires -i and -o");
                let _ = usage(&prog, false);
                ExitCode::FAILURE
            }
        },
        b"decode" => match &opts.input {
            Some(i) => decode(Path::new(i), opts.raw, opts.quiet),
            None => {
                scattersteg::errln!("Error: decode requires -i");
                let _ = usage(&prog, false);
                ExitCode::FAILURE
            }
        },
        other => {
            scattersteg::errln!("Error: unknown command '{}'", String::from_utf8_lossy(other));
            let _ = usage(&prog, false);
            ExitCode::FAILURE
        }
    }
}
