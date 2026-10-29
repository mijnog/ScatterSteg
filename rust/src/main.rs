// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

use scattersteg::codec::{self, EmbedError};
use scattersteg::compress;
use scattersteg::atomic_write::atomic_write;
use scattersteg::cover::{Cover, SaveError};
use scattersteg::sodium::{self, Secret};
use scattersteg::jpeg_io;
use std::ffi::{CStr, OsString};
use std::io::{self, Write};
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

/// Read all of `fd` into a Secret, byte for byte (NUL included). Prints a
/// prompt first if `prompt` is set and fd is a terminal. Stops reading once
/// that is longer than max_len, so a huge input can't exhaust memory or
/// overflow the payload length.
fn read_message(fd: RawFd, max_len: usize, prompt: bool) -> Result<Secret, ReadError> {
    if prompt && unsafe { libc::isatty(fd) } == 1 { scattersteg::errln!("Message (Ctrl+D when done):"); }

    let oom = || ReadError::Io(io::Error::from_raw_os_error(libc::ENOMEM));
    let mut cap = 1024;
    let mut len = 0;
    let mut buf = Secret::new(cap).ok_or_else(oom)?;

    // read(), not stdio: a buffer would keep a copy of the message in
    // ordinary heap memory, unlocked and never wiped
    loop {
        if len == cap {
            let mut bigger = Secret::new(cap * 2).ok_or_else(oom)?;
            bigger[..len].copy_from_slice(&buf[..len]);
            buf = bigger;
            cap *= 2;
        }
        // max_len + 1 bytes in all tell a message that is too long
        let want = (cap - len).min(max_len + 1 - len);
        let n = unsafe { libc::read(fd, buf[len..].as_mut_ptr().cast(), want) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(ReadError::Io(e)); // not the end: don't hide a partial message
        }
        if n == 0 { break; }
        len += n as usize;
        if len > max_len { return Err(ReadError::TooLong); }
    }
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

// The command line has steghide's syntax (its commands and option names, for
// the features ScatterSteg has), so its users find what they know; the
// wording is ScatterSteg's own. See CLAUDE.md.

/// The synopsis, to stderr after a mistake; with the options too, to stdout,
/// when asked for (help)
fn usage(prog: &str, to_stdout: bool) -> io::Result<()> {
    let mut text = format!(
        "Usage: {prog} embed -cf <cover.png|jpg> [-ef <file>] [-sf <output.png|jpg>] [options]\n\
         \x20      {prog} extract -sf <image.png|jpg> [-xf <file>] [options]\n\
         \x20      {prog} info <image.png|jpg>\n\
         \x20      {prog} passphrase | encinfo | license | version | help\n");
    if !to_stdout {
        let _ = write_fd(2, text.as_bytes());
        return Ok(());
    }
    text.push_str("\n\
        embed hides a file (-ef, or standard input) in a cover image, writing\n\
        the result to -sf, or over the cover if there's no -sf. extract gets it\n\
        back: into -xf, else into the file name stored with it, else onto\n\
        standard output (-xf - for that always). The passphrase is always typed\n\
        at the prompt. info says whether an image can be a cover, and how much\n\
        it holds; passphrase prints a strong random passphrase.\n\
        \n\
        \x20 -z, --compress [1-9]   compression level, 9 (the default) smallest\n\
        \x20 -Z, --dontcompress     store the file as is\n\
        \x20 -N, --dontembedname    don't store the file's name\n\
        \x20 -f, --force            replace files that already exist\n\
        \x20 -q, --quiet            print only prompts, warnings and errors\n\
        \x20 -v, --verbose          say what was stored, and how\n\
        Long forms of the others: --embedfile, --coverfile, --stegofile, --extractfile.\n");
    write_fd(1, text.as_bytes())
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

const CMD_EMBED: u8 = 1;
const CMD_EXTRACT: u8 = 2;
const CMD_INFO: u8 = 4;

struct OptionSpec {
    short: &'static str,
    long: &'static str,
    /// The CMD_* it belongs to
    commands: u8,
    /// 0: nothing, 1: a value, 2: a level, if one follows
    takes: u8,
    /// Why ScatterSteg doesn't take it
    refused: Option<&'static str>,
}

const OPTION_SPECS: [OptionSpec; 13] = [
    OptionSpec { short: "-ef", long: "--embedfile", commands: CMD_EMBED, takes: 1, refused: None },
    OptionSpec { short: "-cf", long: "--coverfile", commands: CMD_EMBED, takes: 1, refused: None },
    OptionSpec { short: "-sf", long: "--stegofile", commands: CMD_EMBED | CMD_EXTRACT, takes: 1, refused: None },
    OptionSpec { short: "-xf", long: "--extractfile", commands: CMD_EXTRACT, takes: 1, refused: None },
    OptionSpec { short: "-z", long: "--compress", commands: CMD_EMBED, takes: 2, refused: None },
    OptionSpec { short: "-Z", long: "--dontcompress", commands: CMD_EMBED, takes: 0, refused: None },
    OptionSpec { short: "-N", long: "--dontembedname", commands: CMD_EMBED, takes: 0, refused: None },
    OptionSpec { short: "-f", long: "--force", commands: CMD_EMBED | CMD_EXTRACT, takes: 0, refused: None },
    OptionSpec { short: "-q", long: "--quiet", commands: CMD_EMBED | CMD_EXTRACT, takes: 0, refused: None },
    OptionSpec { short: "-v", long: "--verbose", commands: CMD_EMBED | CMD_EXTRACT, takes: 0, refused: None },
    OptionSpec { short: "-p", long: "--passphrase", commands: 0, takes: 1, refused: Some(
        "the passphrase is never taken on the command line, where other users (ps) and the shell \
         history could read it; type it at the prompt") },
    OptionSpec { short: "-e", long: "--encryption", commands: 0, takes: 1, refused: Some(
        "the encryption is fixed (XSalsa20-Poly1305) and always on (see encinfo)") },
    OptionSpec { short: "-K", long: "--nochecksum", commands: 0, takes: 0, refused: Some(
        "the message is always authenticated (Poly1305), which checks its integrity; there is no \
         separate checksum") },
];

struct Options {
    embed_file: Option<OsString>,
    cover_file: Option<OsString>,
    stego_file: Option<OsString>,
    extract_file: Option<OsString>,
    /// info's image
    operand: Option<OsString>,
    /// Compression level 1-9, or 0 for -Z
    level: u32,
    no_name: bool,
    force: bool,
    quiet: bool,
    verbose: bool,
}

/// The options after the command; None, having said why, if they don't make
/// sense for it
fn parse_options(cmd: u8, cmd_name: &str, args: &[OsString]) -> Option<Options> {
    let mut o = Options { embed_file: None, cover_file: None, stego_file: None, extract_file: None,
                          operand: None, level: 9, no_name: false, force: false, quiet: false, verbose: false };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_bytes();
        let shown = args[i].to_string_lossy();
        i += 1;
        let Some(spec) = OPTION_SPECS.iter().find(|s| a == s.short.as_bytes() || a == s.long.as_bytes()) else {
            if a.len() > 1 && a[0] == b'-' {
                scattersteg::errln!("Error: unknown option '{shown}'");
                return None;
            }
            if cmd == CMD_INFO && o.operand.is_none() {
                o.operand = Some(args[i - 1].clone());
                continue;
            }
            scattersteg::errln!("Error: unexpected argument '{shown}'");
            return None;
        };
        if let Some(why) = spec.refused {
            scattersteg::errln!("Error: {shown} isn't supported: {why}");
            return None;
        }
        if spec.commands & cmd == 0 {
            scattersteg::errln!("Error: {shown} is not an option of {cmd_name}");
            return None;
        }
        let mut value = None;
        if spec.takes == 1 {
            let Some(v) = args.get(i) else {
                scattersteg::errln!("Error: {shown} needs a value");
                return None;
            };
            value = Some(v.clone());
            i += 1;
        }
        match spec.short {
            "-ef" => o.embed_file = value,
            "-cf" => o.cover_file = value,
            "-sf" => o.stego_file = value,
            "-xf" => o.extract_file = value,
            "-z" => {
                o.level = 9;
                if let Some(&[d]) = args.get(i).map(|v| v.as_bytes()) && (b'1'..=b'9').contains(&d) {
                    o.level = (d - b'0') as u32;
                    i += 1;
                }
            }
            "-Z" => o.level = 0,
            "-N" => o.no_name = true,
            "-f" => o.force = true,
            "-q" => o.quiet = true,
            _ => o.verbose = true,
        }
    }
    Some(o)
}

/// Whether a and b name the same existing file
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

/// Says so and returns true if path exists (a dangling link too) and force
/// isn't set: only -f replaces a file
fn refuse_existing(path: &Path, force: bool, hint: &str) -> bool {
    if force || std::fs::symlink_metadata(path).is_err() { return false; }
    scattersteg::errln!("Error: '{}' already exists; use -f to replace it{hint}", path.display());
    true
}

fn embed(o: &Options) -> ExitCode {
    let Some(cover_file) = &o.cover_file else {
        scattersteg::errln!("Error: embed needs a cover image: -cf <cover.png|jpg>");
        return ExitCode::FAILURE;
    };
    let output = o.stego_file.as_ref().unwrap_or(cover_file);
    if cover_file == "-" || output == "-" {
        scattersteg::errln!("Error: the cover and the output must be files, not standard input or output");
        return ExitCode::FAILURE;
    }
    let (input, output) = (Path::new(cover_file), Path::new(output));
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
    if let Ok(m) = std::fs::metadata(output) && !m.is_file() {
        scattersteg::errln!("Error: '{}' exists and is not a regular file", output.display());
        return ExitCode::FAILURE;
    }
    // Writing over the cover is what embed without -sf is for
    if !same_file(input, output) && refuse_existing(output, o.force, "") { return ExitCode::FAILURE; }

    // The message: -ef's file, with its name unless -N, or standard input
    let from_stdin = o.embed_file.as_ref().is_none_or(|f| f == "-");
    let mut file = None;
    let mut name: &[u8] = &[];
    if let Some(ef) = o.embed_file.as_ref().filter(|_| !from_stdin) {
        match std::fs::File::open(ef) {
            Ok(f) => file = Some(f),
            Err(e) => {
                scattersteg::errln!("Error: could not read '{}': {}", Path::new(ef).display(), errno_message(&e));
                return ExitCode::FAILURE;
            }
        }
        let path = ef.as_bytes();
        name = if o.no_name { &[] } else { &path[path.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1)..] };
        if !o.no_name && !compress::name_ok(name) {
            scattersteg::errln!("Error: the file's name can't be stored with it (at most {} bytes, no control \
                       characters); rename it, or use -N", compress::NAME_MAX);
            return ExitCode::FAILURE;
        }
    }
    let fd = file.as_ref().map_or(0, std::os::fd::AsRawFd::as_raw_fd);

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
    if !o.quiet { scattersteg::errln!("Deriving keys..."); }
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
    let mut message = match read_message(fd, compress::MESSAGE_MAX, from_stdin && !o.quiet) {
        Ok(m) => m,
        Err(ReadError::TooLong) => {
            scattersteg::errln!("Error: message too long (max {} MiB)", compress::MESSAGE_MAX >> 20);
            return ExitCode::FAILURE;
        }
        Err(ReadError::Io(e)) => {
            scattersteg::errln!("Error: could not read the message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
    };
    drop(file);
    let len = message.len();
    warn_if_swappable(&mut message, len);
    // Empty message: almost always a mistake (nothing piped in, an empty
    // file, Ctrl+D too soon), and a script must not take it for a written
    // output: fail, and write nothing
    if message.is_empty() {
        scattersteg::errln!("Error: the message is empty; nothing written");
        return ExitCode::FAILURE;
    }

    let stored = match prepared.embed(&mut cover.carrier(), name, &message, o.level) {
        Ok(s) => s,
        Err(EmbedError::TooLong) => {
            scattersteg::errln!("Error: message too long for this image, which holds {holds} bytes (more if the \
                       message compresses well{})", if name.is_empty() { "" } else { ", less the file name's length" });
            return ExitCode::FAILURE;
        }
        Err(EmbedError::Alloc) => {
            scattersteg::errln!("Error: allocation failed");
            return ExitCode::FAILURE;
        }
    };
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
    if o.verbose {
        let from = if name.is_empty() { String::new() } else { format!(" from '{}'", String::from_utf8_lossy(name)) };
        scattersteg::errln!("Stored {len} bytes{from} as {} ({}), in an image that holds {holds} as is",
                  stored.hidden, if stored.compressed { "compressed" } else { "not compressed" });
    }
    if !o.quiet { scattersteg::errln!("Wrote '{}'", output.display()); }
    ExitCode::SUCCESS
}

fn extract(o: &Options) -> ExitCode {
    let Some(stego_file) = &o.stego_file else {
        scattersteg::errln!("Error: extract needs an image: -sf <image.png|jpg>");
        return ExitCode::FAILURE;
    };
    if stego_file == "-" {
        scattersteg::errln!("Error: the image must be a file, not standard input");
        return ExitCode::FAILURE;
    }
    let to_stdout = o.extract_file.as_ref().is_some_and(|f| f == "-");
    if let Some(xf) = o.extract_file.as_ref().filter(|_| !to_stdout)
        && refuse_existing(Path::new(xf), o.force, "") { return ExitCode::FAILURE; }

    let input = Path::new(stego_file);
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

    if !o.quiet { scattersteg::errln!("Deriving keys..."); }
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

    // Where it goes: -xf, else the name stored with it, else stdout
    let stored_name = std::ffi::OsStr::from_bytes(&found.name);
    let dest = if to_stdout { None }
               else if let Some(xf) = &o.extract_file { Some(Path::new(xf)) }
               else if !found.name.is_empty() { Some(Path::new(stored_name)) }
               else { None };
    let len = found.plaintext.len();
    warn_if_swappable(&mut found.plaintext, len);
    if o.verbose {
        let stored = if found.name.is_empty() { String::new() }
                     else { format!(", stored as '{}'", String::from_utf8_lossy(&found.name)) };
        scattersteg::errln!("Found {len} bytes{stored}");
    }
    let Some(dest) = dest else {
        // All of it, NULs too, unbuffered (write_fd)
        if let Err(e) = write_fd(1, &found.plaintext) {
            scattersteg::errln!("Error: could not write the message: {}", errno_message(&e));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    };
    if o.extract_file.is_none() && refuse_existing(dest, o.force, ", or -xf to choose another name") {
        return ExitCode::FAILURE;
    }
    if let Err(e) = atomic_write(dest, |f| f.write_all(&found.plaintext)) {
        scattersteg::errln!("Error: could not write '{}': {}", dest.display(), errno_message(&e));
        return ExitCode::FAILURE;
    }
    if !o.quiet { scattersteg::errln!("Wrote '{}'", dest.display()); }
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

    // Each command also as --command, and help as -h
    let first = args[1].as_bytes();
    let cmd: &[u8] = if first.starts_with(b"--") && first != b"--passphrase" { &first[2..] }
                     else if first == b"-h" { b"help" }
                     else { first };
    let which = match cmd { b"embed" => CMD_EMBED, b"extract" => CMD_EXTRACT, b"info" => CMD_INFO, _ => 0 };
    if which != 0 {
        let cmd_name = String::from_utf8_lossy(cmd);
        let Some(o) = parse_options(which, &cmd_name, &args[2..]) else {
            let _ = usage(&prog, false);
            return ExitCode::FAILURE;
        };
        return match which {
            CMD_EMBED => embed(&o),
            CMD_EXTRACT => extract(&o),
            _ => match &o.operand {
                Some(f) => info(Path::new(f)),
                None => {
                    scattersteg::errln!("Error: info needs an image: info <image.png|jpg>");
                    let _ = usage(&prog, false);
                    ExitCode::FAILURE
                }
            },
        };
    }

    if !matches!(cmd, b"passphrase" | b"encinfo" | b"license" | b"version" | b"help") {
        scattersteg::errln!("Error: unknown command '{}'", args[1].to_string_lossy());
        let _ = usage(&prog, false);
        return ExitCode::FAILURE;
    }
    if args.len() > 2 {
        scattersteg::errln!("Error: {} takes no options or arguments", String::from_utf8_lossy(cmd));
        let _ = usage(&prog, false);
        return ExitCode::FAILURE;
    }
    let version = env!("CARGO_PKG_VERSION");
    let text = match cmd {
        b"passphrase" => return match generate_passphrase() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                scattersteg::errln!("Error: could not write the passphrase: {}", errno_message(&e));
                ExitCode::FAILURE
            }
        },
        b"help" => return if usage(&prog, true).is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE },
        b"version" => format!("scattersteg {version}\n"),
        b"encinfo" => "ScatterSteg always encrypts and authenticates the message with XSalsa20-Poly1305\n\
                       (libsodium's secretbox), keyed by Argon2id from the passphrase: there is no\n\
                       algorithm or mode to choose.\n".to_string(),
        _ => format!("ScatterSteg {version}\n\
                      Copyright (C) 2026 Maxime de Montbron\n\
                      Free software under the GNU Affero General Public License v3.0 or later: you may\n\
                      use, change and share it on its terms. It comes with NO WARRANTY. See the\n\
                      LICENSE file, or <https://www.gnu.org/licenses/agpl-3.0.html>.\n"),
    };
    if let Err(e) = write_fd(1, text.as_bytes()) {
        scattersteg::errln!("Error: could not write: {}", errno_message(&e));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
