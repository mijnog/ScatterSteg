// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! PNG covers: decoded to 8-bit gray or RGB, and written back as the same
//! kind of file, with the cover's ancillary chunks and interlacing.

use crate::atomic_write::atomic_write;
use crate::zlib_sys as z;
use std::io::{self, Cursor, Write};
use std::os::raw::c_int;
use std::path::Path;

/// Largest decoded pixel buffer png_load will allocate (1 GiB)
const MAX_PIXEL_BYTES: usize = 1 << 30;
/// Most pixels png_load will take: each also has a 4-byte slot in the
/// message permutation, so this keeps that to 1 GiB too.
const MAX_PIXELS: u64 = 1 << 28;
/// Largest single ancillary chunk kept
const MAX_CHUNK_BYTES: usize = 16 << 20;
/// Most ancillary chunks kept
const MAX_CHUNKS: usize = 1000;
/// Most ancillary chunk bytes kept in all
const MAX_META_TOTAL: usize = 128 << 20;

/// The reasons for `unsuitable` that are about the content (pixels, chunks)
/// rather than the format: what `save` writes can still have them
pub const LOW_SBIT: &str = "fewer than 8 significant bits (an sBIT chunk)";
pub const GRAY_AS_RGB: &str = "only gray pixels, stored as RGB (save it as grayscale)";

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// An ancillary chunk of the cover, kept for `save` to write back
struct Chunk {
    name: [u8; 4],
    data: Vec<u8>,
    after_idat: bool,
}

/// The cover's compressed image data (its first run of IDAT chunks,
/// joined), for `save` to compress the new pixels the same way
struct Idat {
    data: Vec<u8>,
    /// the first IDAT's size
    first: u32,
    /// how many there were
    count: u32,
}

/// The cover's ancillary chunks, interlacing and image data
pub struct PngMeta {
    interlaced: bool,
    chunks: Vec<Chunk>,
    /// None unless the cover is 8-bit gray or RGB, the only kind `save` writes
    idat: Option<Idat>,
}

pub struct Image {
    pub width: u32,
    pub height: u32,
    /// samples per pixel: 1 (gray) or 3 (RGB)
    pub channels: u32,
    /// `pixels[(y * width + x) * channels + channel]`
    pub pixels: Vec<u8>,
    /// why a cover this way would come out visibly changed, or give its
    /// changes away, e.g. "transparency"; None for 8-bit RGB or gray without
    /// transparency, sBIT < 8, animation or RGB that is all gray
    pub unsuitable: Option<&'static str>,
    pub meta: Option<PngMeta>,
}

/// Ancillary chunks the PNG spec defines whose meaning doesn't depend on the
/// exact pixel values, so they stay true once LSBs change. Many are marked
/// unsafe to copy (uppercase 4th letter), but that rule is for editors that
/// don't know the chunk.
const KEPT_CHUNKS: [&[u8; 4]; 20] = [
    b"cHRM", b"cICP", b"cLLI", b"gAMA", b"iCCP", b"mDCV", b"sBIT", b"sRGB", b"bKGD", b"pHYs",
    b"sPLT", b"eXIf", b"tIME", b"tEXt", b"zTXt", b"iTXt", b"oFFs", b"pCAL", b"sCAL", b"sTER",
];

fn keep_chunk(name: &[u8; 4]) -> bool {
    name[3] & 0x20 != 0 || KEPT_CHUNKS.contains(&name)
}

/// The cover's ancillary chunks, in order, with whether each follows the
/// image data, and whether it is an animated PNG (an acTL chunk, see
/// `from_bytes`). Stops at the first damaged chunk. One failing its CRC is kept,
/// as libpng keeps it (and so the C version writes it back, CRC fixed).
fn parse_chunks(file: &[u8]) -> Option<(Vec<Chunk>, bool)> {
    let mut out = Vec::new();
    let mut animated = false;
    let mut total = 0usize;
    let mut pos = 8;
    let mut after_idat = false;
    while pos + 12 <= file.len() && out.len() < MAX_CHUNKS {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        if len > i32::MAX as usize || pos + 12 + len > file.len() { break; }
        let name: [u8; 4] = file[pos + 4..pos + 8].try_into().unwrap();
        let data = &file[pos + 8..pos + 8 + len];
        pos += 12 + len;
        // libpng refuses the whole file over a name that isn't four letters;
        // so must we, or we'd write such a chunk back out and C couldn't read
        // the result. A lowercase third letter (reserved) is refused only by
        // newer libpng: load the file, but don't write that chunk back.
        if !name.iter().all(u8::is_ascii_alphabetic) {
            if after_idat { break; } // the pixels are in: C stops reading here, keeping what it has
            return None;
        }
        if name[2] & 0x20 != 0 { continue; }
        match &name {
            b"IDAT" => { after_idat = true; continue; }
            b"IEND" => break,
            b"IHDR" | b"PLTE" | b"tRNS" => continue,
            _ => {}
        }
        if name[0] & 0x20 == 0 { continue; } // an unknown critical chunk
        if len > MAX_CHUNK_BYTES || total + len > MAX_META_TOTAL { continue; }
        total += len;
        // A well-formed acTL (8 bytes, at least one frame): viewers show a
        // malformed one's still image
        animated |= &name == b"acTL" && len == 8 && data[..4] != [0; 4];
        if keep_chunk(&name) {
            out.push(Chunk { name, data: data.to_vec(), after_idat });
        }
    }
    Some((out, animated))
}

/// The file's first run of IDAT chunks' data, joined, and the run's chunk
/// sizes. Stops at a chunk that doesn't fit in the file. As png_io.c's
/// take_idat.
fn idat_run(file: &[u8]) -> Idat {
    let (mut pos, mut data, mut first, mut count) = (8, Vec::new(), 0u32, 0u32);
    while pos + 12 <= file.len() {
        let n = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap());
        if n > i32::MAX as u32 || n as usize > file.len() - pos - 12 { break; }
        let name = &file[pos + 4..pos + 8];
        let idat = name == b"IDAT";
        if (!idat && count > 0) || name == b"IEND" { break; }
        if idat {
            if count == 0 { first = n; }
            count += 1;
            data.extend_from_slice(&file[pos + 8..pos + 8 + n as usize]);
        }
        pos += 12 + n as usize;
    }
    Idat { data, first, count }
}

/// Rewrites `file` in place to the chunks the decoder needs: IHDR, PLTE, tRNS,
/// IDAT and a closing IEND. The `png` crate parses and rejects ancillary
/// chunks (a gAMA of the wrong length, a bad fcTL, ...) that libpng only
/// warns about, and wants an IEND libpng doesn't; none of that may decide
/// whether a cover loads. Like libpng, a repeated PLTE or tRNS and a tRNS of
/// the wrong size are ignored, and so is image data that follows another chunk.
/// False if a critical chunk before the image data ends has a bad CRC.
fn decoder_view(file: &mut Vec<u8>) -> bool {
    let (mut pos, mut out) = (8, 8);
    let (mut seen_plte, mut seen_trns, mut in_idat, mut idat_done) = (false, false, false, false);
    let (mut color, mut depth, mut plte_entries) = (0u8, 0u8, 0usize);
    while pos + 12 <= file.len() {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        if len > i32::MAX as usize || pos + 12 + len > file.len() { break; }
        let name: [u8; 4] = file[pos + 4..pos + 8].try_into().unwrap();
        let end = pos + 12 + len;
        if &name == b"IEND" { break; }
        if !name.iter().all(u8::is_ascii_alphabetic) { break; } // libpng stops reading here
        if &name != b"IDAT" && in_idat { in_idat = false; idat_done = true; }
        let keep = match &name {
            b"IHDR" => {
                let first = out == 8;
                if first && len == 13 { depth = file[pos + 8 + 8]; color = file[pos + 8 + 9]; }
                if !first && !in_idat && !idat_done { return false; } // libpng: duplicate IHDR
                first // one after the image data is ignored
            }
            b"PLTE" if !seen_plte => {
                seen_plte = true;
                plte_entries = len / 3;
                if color == 3 {
                    // libpng fails on a palette that isn't whole entries or
                    // is empty; one with more entries than the bit depth
                    // allows is only cut short (written below)
                    if !len.is_multiple_of(3) || len == 0 || len > 768 { return false; }
                    plte_entries = plte_entries.min(1usize << depth.min(8));
                    true
                } else {
                    false // ignored for other color types
                }
            }
            b"tRNS" if !seen_trns => {
                // libpng discards one of the wrong size or with a bad CRC
                // (a warning, as it is ancillary) and takes a later one
                let sized = match color { 0 => len == 2, 2 => len == 6, 3 => seen_plte && len <= plte_entries, _ => false };
                let ok = sized && crc32fast::hash(&file[pos + 4..pos + 8 + len])
                    == u32::from_be_bytes(file[pos + 8 + len..end].try_into().unwrap());
                seen_trns |= ok;
                ok
            }
            b"IDAT" => {
                // More image data after another chunk: libpng reads it only if
                // the image isn't complete yet. Dropping it gives the decoder
                // the same data, so it fails exactly when libpng would.
                !idat_done && { in_idat = true; true }
            }
            _ => {
                // libpng fails on a bad CRC in any critical chunk before the
                // image data ends (after it, the pixels are in: a failure
                // there is ignored)
                if name[0] & 0x20 == 0 && !idat_done {
                    let mut h = crc32fast::Hasher::new();
                    h.update(&file[pos + 4..pos + 8 + len]);
                    if h.finalize() != u32::from_be_bytes(file[pos + 8 + len..end].try_into().unwrap()) { return false; }
                }
                false
            }
        };
        if keep && &name == b"PLTE" && plte_entries * 3 < len {
            // Keep the entries the bit depth allows, with a CRC to match
            let n = plte_entries * 3;
            file.copy_within(pos + 4..pos + 8 + n, out + 4);
            file[out..out + 4].copy_from_slice(&(n as u32).to_be_bytes());
            let crc = crc32fast::hash(&file[out + 4..out + 8 + n]);
            file[out + 8 + n..out + 12 + n].copy_from_slice(&crc.to_be_bytes());
            out += 12 + n;
        } else if keep {
            file.copy_within(pos..end, out);
            out += end - pos;
        }
        pos = end;
    }
    file.truncate(out);
    file.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
    true
}

/// An sBIT chunk saying a channel has fewer than 8 significant bits: such
/// images have structured low bits (zeros, or the high bits repeated), which
/// +-1 changes break, and the chunk itself, kept in the output, tells a
/// warden to look
fn low_sbit(chunks: &[Chunk]) -> bool {
    chunks.iter().any(|c| &c.name == b"sBIT" && c.data.iter().any(|&b| b < 8))
}

/// Gray stored as RGB: R = G = B in every pixel. Changing the channels
/// independently breaks that, which a one-line check finds.
fn all_gray(pixels: &[u8], channels: u32) -> bool {
    channels == 3 && pixels.as_chunks::<3>().0.iter().all(|&[r, g, b]| r == g && g == b)
}

pub fn load(path: &Path) -> Option<Image> {
    from_bytes(crate::fault::read_file(path, &SIGNATURE).ok()?)
}

/// The same from a PNG file's bytes
pub fn from_bytes(mut file: Vec<u8>) -> Option<Image> {
    if !is_png_signature(&file) { return None; }
    let (chunks, animated) = parse_chunks(&file)?;
    let idat = idat_run(&file);
    if !decoder_view(&mut file) { return None; }
    let mut decoder = png::Decoder::new(Cursor::new(&file[..]));
    // Text and profile chunks are copied as raw bytes (see parse_chunks), so
    // the decoder needn't parse them, and a malformed one can't stop the load
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    // The decoder buffers the chunks it parses (and refuses past 64 MiB by
    // default); an oversized one is dropped by parse_chunks, not a reason to
    // refuse the image. The file is already in memory and capped, so that
    // bounds this too.
    decoder.set_limits(png::Limits { bytes: crate::fault::MAX_FILE_BYTES as usize });
    let mut reader = decoder.read_info().ok()?;
    let info = reader.info();
    let (width, height) = (info.width, info.height);

    // Everything loads as 8-bit gray or 8-bit RGB. Only those two, without
    // transparency, come back out of `save` in the same format; anything
    // else would visibly change as a cover. Note why.
    let color = info.color_type;
    let depth = info.bit_depth;
    let unsuitable = if matches!(color, png::ColorType::GrayscaleAlpha | png::ColorType::Rgba) || info.trns.is_some() {
        Some("transparency")
    } else if depth == png::BitDepth::Sixteen {
        Some("16-bit color")
    } else if color == png::ColorType::Indexed {
        Some("a color palette")
    } else if (depth as u8) < 8 {
        Some("fewer than 8 bits per sample")
    } else {
        None
    };
    let channels: u32 = if matches!(color, png::ColorType::Grayscale | png::ColorType::GrayscaleAlpha) { 1 } else { 3 };
    let interlaced = info.interlaced;
    // The cover's compressed image data, if `save` can use it
    let idat = (depth == png::BitDepth::Eight && matches!(color, png::ColorType::Grayscale | png::ColorType::Rgb))
        .then_some(idat);

    // The header's dimensions are untrusted: cap the total allocation before
    // making it, so a tiny file can't request terabytes
    // (the buffer holds what the decoder outputs, up to 4 samples a pixel when
    // it expands a palette or tRNS to alpha; the alpha is dropped after)
    let out_channels = reader.output_color_type().0.samples();
    let row_size = width as usize * out_channels;
    if width == 0 || height == 0 || row_size > MAX_PIXEL_BYTES / height as usize
        || width as u64 * height as u64 > MAX_PIXELS {
        return None;
    }

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buf).ok()?;
    let src = &buf[..frame.buffer_size()];
    let src_channels = frame.color_type.samples();
    if frame.bit_depth != png::BitDepth::Eight || src.len() != width as usize * height as usize * src_channels {
        return None;
    }
    // Drop the alpha channel if present
    let pixels = if src_channels == channels as usize {
        buf.truncate(src.len());
        buf
    } else {
        src.chunks_exact(src_channels).flat_map(|px| px[..channels as usize].iter().copied()).collect()
    };

    // Covers the output would give away: an animated PNG (APNG), as the
    // decoder reads only its first frame and the output drops the chunks that
    // hold the rest (acTL, fcTL, fdAT); or low bits visibly structured, where
    // the changes would stand out
    let unsuitable = unsuitable.or_else(|| {
        if animated {
            Some("an animation (APNG)")
        } else if low_sbit(&chunks) {
            Some(LOW_SBIT)
        } else if all_gray(&pixels, channels) {
            Some(GRAY_AS_RGB)
        } else {
            None
        }
    });

    Some(Image {
        width, height, channels, pixels, unsuitable,
        meta: Some(PngMeta { interlaced, chunks, idat }),
    })
}

fn write_chunk(w: &mut impl Write, name: &[u8; 4], data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(name)?;
    w.write_all(data)?;
    let mut h = crc32fast::Hasher::new();
    h.update(name);
    h.update(data);
    w.write_all(&h.finalize().to_be_bytes())
}

/// How `save` compresses the image data: each row's filter, zlib's settings
/// and the IDAT chunks' size. Copied from the cover, so the output is written
/// the way the cover was: its encoder's choices, not ours. png_io.c's Layout
/// is the same, step for step, so both builds write the same bytes.
struct Layout {
    /// one per row (Adam7: pass by pass); None: choose
    filters: Option<Vec<u8>>,
    /// bytes per IDAT, the last one shorter; 0: one IDAT
    chunk: usize,
    /// deflateInit2's
    level: c_int,
    window: c_int,
    mem: c_int,
    strategy: c_int,
    /// the cover's zlib header, written in place of zlib's
    header: Option<[u8; 2]>,
}

/// libpng's defaults, for an image with no cover data to copy
impl Default for Layout {
    fn default() -> Self {
        Layout { filters: None, chunk: 8192, level: 6, window: 15, mem: 8, strategy: z::Z_FILTERED as c_int, header: None }
    }
}

/// Each pass's first column and row, and steps across and down: Adam7's
/// seven, or one with every row
const ADAM7: [(usize, usize, usize, usize); 7] =
    [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)];
const ONE_PASS: [(usize, usize, usize, usize); 1] = [(0, 0, 1, 1)];

fn passes(interlaced: bool) -> &'static [(usize, usize, usize, usize)] {
    if interlaced { &ADAM7 } else { &ONE_PASS }
}

/// Pixels across and rows in a pass: none if the image is too small for it,
/// as then it has no rows at all
fn pass_size(&(x0, y0, dx, dy): &(usize, usize, usize, usize), w: usize, h: usize) -> (usize, usize) {
    let pw = if w > x0 { (w - x0).div_ceil(dx) } else { 0 };
    let ph = if h > y0 { (h - y0).div_ceil(dy) } else { 0 };
    if pw == 0 || ph == 0 { (0, 0) } else { (pw, ph) }
}

/// Inflated data piece by piece, and how much of it the trials see: past
/// that, the first still matching is taken
const PIECE: usize = 1 << 16;
const TRIAL_BYTES: usize = 8 << 20;

/// The zlib configurations tried, most common first: libpng's default (6,
/// Z_FILTERED), then the other levels, memLevel 8 (zlib's default) and 9
/// (Pillow's), then Z_RLE and Z_HUFFMAN_ONLY (which optipng tries; their
/// output doesn't depend on the level) and no compression. The first that
/// reproduces the cover's data wins.
const N_TRIALS: usize = 41;
fn trial_params(i: usize) -> (c_int, c_int, c_int) {
    const LEVELS: [c_int; 9] = [6, 9, 1, 2, 3, 4, 5, 7, 8];
    let (filtered, default) = (z::Z_FILTERED as c_int, z::Z_DEFAULT_STRATEGY as c_int);
    if i == N_TRIALS - 1 { return (0, 8, default); }
    if i >= 36 {
        let strategy = if i < 38 { z::Z_RLE } else { z::Z_HUFFMAN_ONLY } as c_int;
        return (6, if i % 2 == 1 { 9 } else { 8 }, strategy);
    }
    (LEVELS[i / 4], if i % 4 < 2 { 8 } else { 9 }, if i % 2 == 1 { default } else { filtered })
}

/// A zlib deflate stream, and a buffer for its output. Boxed: zlib keeps a
/// pointer back to it, so it mustn't move.
struct Deflater(Box<z::z_stream>, Vec<u8>);

impl Deflater {
    fn new(level: c_int, window: c_int, mem: c_int, strategy: c_int) -> Option<Self> {
        // All zero is zlib's documented initial state (its own allocator)
        let mut s: Box<z::z_stream> = Box::new(unsafe { std::mem::zeroed() });
        let r = unsafe {
            z::deflateInit2_(&mut *s, level, z::Z_DEFLATED as c_int, window, mem, strategy,
                             z::ZLIB_VERSION.as_ptr().cast(), size_of::<z::z_stream>() as c_int)
        };
        (r == z::Z_OK as c_int).then(|| Deflater(s, vec![0u8; PIECE]))
    }

    /// Compresses `input`, flushing as told, handing each piece of output to
    /// `out`; false if zlib fails or `out` returns false
    fn run(&mut self, input: &[u8], flush: c_int, mut out: impl FnMut(&[u8]) -> bool) -> bool {
        let buf = &mut self.1;
        self.0.next_in = input.as_ptr().cast_mut();
        self.0.avail_in = input.len() as u32;
        loop {
            self.0.next_out = buf.as_mut_ptr();
            self.0.avail_out = PIECE as u32;
            let r = unsafe { z::deflate(&mut *self.0, flush) };
            let got = PIECE - self.0.avail_out as usize;
            if !out(&buf[..got]) { return false; }
            if self.0.avail_out != 0 {
                return r != z::Z_STREAM_ERROR && (flush != z::Z_FINISH as c_int || r == z::Z_STREAM_END as c_int);
            }
        }
    }
}

impl Drop for Deflater {
    fn drop(&mut self) { unsafe { z::deflateEnd(&mut *self.0) }; }
}

/// One zlib configuration being tried on the cover's image data: how much it
/// has produced, while that still matches
struct Trial {
    z: Deflater,
    out: usize,
}

impl Trial {
    /// Compresses `input` and checks the output against `want`, the cover's
    /// data (the 2-byte header aside, as the trial's own may differ)
    fn feed(&mut self, input: &[u8], flush: c_int, want: &[u8]) -> bool {
        let out = &mut self.out;
        self.z.run(input, flush, |got| {
            for &b in got {
                if *out >= 2 && want.get(*out) != Some(&b) { return false; }
                *out += 1;
            }
            true
        })
    }
}

/// Reads the cover's layout from its compressed data: the zlib header, the
/// filter at the start of every row, and which configuration reproduces the
/// data
fn read_layout(idat: &Idat, w: usize, h: usize, ch: usize, interlaced: bool) -> Layout {
    let mut l = Layout { chunk: if idat.count >= 2 && idat.first > 0 { idat.first as usize } else { 0 }, ..Layout::default() };
    let data = &idat.data[..];
    if data.len() < 2 || data[0] & 0x0f != 8 || data[0] >> 4 > 7 || data[1] & 0x20 != 0
        || !((data[0] as u32) << 8 | data[1] as u32).is_multiple_of(31) {
        return l;
    }
    // zlib takes no window under 2^9; nor, then, the header saying so
    l.window = (data[0] >> 4) as c_int + 8;
    if l.window >= 9 { l.header = Some([data[0], data[1]]); } else { l.window = 9; }
    l.level = [1, 5, 6, 9][(data[1] >> 6) as usize];
    l.mem = 8;
    l.strategy = z::Z_DEFAULT_STRATEGY as c_int;

    let passes = passes(interlaced);
    let rows: usize = passes.iter().map(|p| pass_size(p, w, h).1).sum();
    let mut filters = vec![0u8; rows];
    let mut trials: Vec<Option<Trial>> = (0..N_TRIALS).map(|i| {
        let (level, mem, strategy) = trial_params(i);
        Deflater::new(level, l.window, mem, strategy).map(|z| Trial { z, out: 0 })
    }).collect();
    let mut inf: Box<z::z_stream> = Box::new(unsafe { std::mem::zeroed() });
    let r = unsafe {
        z::inflateInit2_(&mut *inf, z::MAX_WBITS as c_int, z::ZLIB_VERSION.as_ptr().cast(), size_of::<z::z_stream>() as c_int)
    };
    if r != z::Z_OK as c_int { return l; }
    let mut piece = vec![0u8; PIECE];

    // Where the next row starts in the inflated data, which it is, and the
    // rows left in its pass
    let (mut row, mut row_at, mut pos) = (0usize, 0usize, 0usize);
    let (mut pass, mut pw, mut left) = (0usize, 0usize, 0usize);
    let (mut bad, mut trying, mut fed) = (false, true, 0usize);
    inf.next_in = data.as_ptr().cast_mut();
    inf.avail_in = data.len().min(u32::MAX as usize) as u32;
    loop {
        inf.next_out = piece.as_mut_ptr();
        inf.avail_out = PIECE as u32;
        let r = unsafe { z::inflate(&mut *inf, z::Z_NO_FLUSH as c_int) };
        let got = PIECE - inf.avail_out as usize;
        while !bad && row < rows && row_at < pos + got {
            while left == 0 {
                (pw, left) = pass_size(&passes[pass], w, h);
                pass += 1;
            }
            left -= 1;
            let f = piece[row_at - pos];
            bad = f > 4;
            filters[row] = f;
            row += 1;
            row_at += 1 + pw * ch;
        }
        pos += got;
        if trying && got > 0 {
            for t in &mut trials {
                if t.as_mut().is_some_and(|t| !t.feed(&piece[..got], z::Z_NO_FLUSH as c_int, data)) { *t = None; }
            }
            fed += got;
            if fed >= TRIAL_BYTES { trying = false; }
        }
        if r == z::Z_STREAM_END as c_int && trying {
            for t in &mut trials {
                if t.as_mut().is_some_and(|t| !t.feed(&[], z::Z_FINISH as c_int, data) || t.out != inf.total_in as usize) {
                    *t = None;
                }
            }
        }
        if r != z::Z_OK as c_int || (!trying && (bad || row == rows)) { break; }
    }
    unsafe { z::inflateEnd(&mut *inf) };

    if let Some(i) = trials.iter().position(Option::is_some) {
        (l.level, l.mem, l.strategy) = trial_params(i);
    }
    if !bad && row == rows { l.filters = Some(filters); }
    l
}

/// Filters a row (`bpp` bytes per pixel; `prev` is the row above, zeros for
/// the first) with PNG filter type `t`, onto `out`: the type, then the bytes
fn filter_row(row: &[u8], prev: &[u8], bpp: usize, t: u8, out: &mut Vec<u8>) {
    let paeth = |a: u8, b: u8, c: u8| -> u8 {
        let (ia, ib, ic) = (a as i32, b as i32, c as i32);
        let p = ia + ib - ic;
        let (pa, pb, pc) = ((p - ia).abs(), (p - ib).abs(), (p - ic).abs());
        if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
    };
    out.push(t);
    for i in 0..row.len() {
        let a = if i >= bpp { row[i - bpp] } else { 0 };
        let b = prev[i];
        let c = if i >= bpp { prev[i - bpp] } else { 0 };
        out.push(row[i].wrapping_sub(match t {
            0 => 0,
            1 => a,
            2 => b,
            3 => ((a as u16 + b as u16) / 2) as u8,
            _ => paeth(a, b, c),
        }));
    }
}

/// For an image with no cover to copy: the filter giving the smallest sum of
/// absolute (signed) bytes, libpng's heuristic; ties to the lower type
fn choose_filter(row: &[u8], prev: &[u8], bpp: usize, tmp: &mut Vec<u8>) -> u8 {
    let mut best = (0u8, u64::MAX);
    for t in 0..5u8 {
        tmp.clear();
        filter_row(row, prev, bpp, t, tmp);
        let sum: u64 = tmp[1..].iter().map(|&v| (v as i8).unsigned_abs() as u64).sum();
        if sum < best.1 { best = (t, sum); }
    }
    best.0
}

/// The image data as one zlib stream, and the IDAT size. Done before `save`
/// makes its temp file: it is the large allocation, and a failure there must
/// not leave one behind.
fn compress(img: &Image) -> io::Result<(Vec<u8>, usize)> {
    let (w, h, ch) = (img.width as usize, img.height as usize, img.channels as usize);
    if w == 0 || h == 0 || w > i32::MAX as usize || h > i32::MAX as usize {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let interlaced = img.meta.as_ref().is_some_and(|m| m.interlaced); // like the cover
    let layout = match img.meta.as_ref().and_then(|m| m.idat.as_ref()) {
        Some(idat) => read_layout(idat, w, h, ch, interlaced),
        None => Layout::default(),
    };
    let mut d = Deflater::new(layout.level, layout.window, layout.mem, layout.strategy)
        .ok_or(io::ErrorKind::OutOfMemory)?;
    let mut out = Vec::new();
    let mut append = |got: &[u8]| { out.extend_from_slice(got); true };
    let (mut f, mut tmp, mut r) = (Vec::new(), Vec::new(), 0);
    for p in passes(interlaced) {
        let (pw, ph) = pass_size(p, w, h);
        let mut prev = vec![0u8; pw * ch];
        let mut cur = Vec::with_capacity(pw * ch);
        for k in 0..ph {
            let y = p.1 + k * p.3;
            cur.clear();
            for x in (0..pw).map(|x| p.0 + x * p.2) {
                cur.extend_from_slice(&img.pixels[(y * w + x) * ch..(y * w + x + 1) * ch]);
            }
            let t = match &layout.filters {
                Some(fs) => fs[r],
                None => choose_filter(&cur, &prev, ch, &mut tmp),
            };
            f.clear();
            filter_row(&cur, &prev, ch, t, &mut f);
            if !d.run(&f, z::Z_NO_FLUSH as c_int, &mut append) { return Err(io::ErrorKind::OutOfMemory.into()); }
            std::mem::swap(&mut prev, &mut cur);
            r += 1;
        }
    }
    if !d.run(&[], z::Z_FINISH as c_int, &mut append) { return Err(io::ErrorKind::OutOfMemory.into()); }
    if let Some(head) = layout.header { out[..2].copy_from_slice(&head); }
    Ok((out, layout.chunk))
}

fn write_png(img: &Image, zlib: &[u8], chunk: usize, w: &mut impl Write) -> io::Result<()> {
    let interlaced = img.meta.as_ref().is_some_and(|m| m.interlaced); // like the cover
    w.write_all(&SIGNATURE)?;
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&img.width.to_be_bytes());
    ihdr.extend_from_slice(&img.height.to_be_bytes());
    ihdr.extend_from_slice(&[8, if img.channels == 1 { 0 } else { 2 }, 0, 0, interlaced as u8]);
    write_chunk(w, b"IHDR", &ihdr)?;
    // The cover's ancillary chunks, byte for byte and where they were
    // (before or after the image data), so the output looks like the same file
    if let Some(m) = &img.meta {
        for c in m.chunks.iter().filter(|c| !c.after_idat) { write_chunk(w, &c.name, &c.data)?; }
    }
    for part in zlib.chunks(if chunk == 0 { zlib.len() } else { chunk }) { write_chunk(w, b"IDAT", part)?; }
    if let Some(m) = &img.meta {
        for c in m.chunks.iter().filter(|c| c.after_idat) { write_chunk(w, &c.name, &c.data)?; }
    }
    write_chunk(w, b"IEND", &[])
}

/// The image as a PNG file's bytes
pub fn encode(img: &Image) -> io::Result<Vec<u8>> {
    let (zlib, chunk) = compress(img)?;
    let mut out = Vec::new();
    write_png(img, &zlib, chunk, &mut out)?;
    Ok(out)
}

pub fn save(img: &Image, path: &Path) -> io::Result<()> {
    let (zlib, chunk) = compress(img)?;
    atomic_write(path, |f| {
        let mut w = io::BufWriter::new(f);
        write_png(img, &zlib, chunk, &mut w)?;
        w.flush() // BufWriter's drop would swallow a failure here
    })
}

pub fn is_png_signature(bytes: &[u8]) -> bool { bytes.starts_with(&SIGNATURE) }
