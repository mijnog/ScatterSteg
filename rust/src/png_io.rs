// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! PNG covers: decoded to 8-bit gray or RGB, and written back as the same
//! kind of file, with the cover's ancillary chunks and interlacing.

use crate::atomic_write::atomic_write;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{self, Cursor, Write};
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

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// An ancillary chunk of the cover, kept for `save` to write back
struct Chunk {
    name: [u8; 4],
    data: Vec<u8>,
    after_idat: bool,
}

/// The cover's ancillary chunks and interlacing
pub struct PngMeta {
    interlaced: bool,
    chunks: Vec<Chunk>,
}

pub struct Image {
    pub width: u32,
    pub height: u32,
    /// samples per pixel: 1 (gray) or 3 (RGB)
    pub channels: u32,
    /// `pixels[(y * width + x) * channels + channel]`
    pub pixels: Vec<u8>,
    /// why a cover this way would come out visibly changed, e.g.
    /// "transparency"; None for 8-bit RGB or gray without transparency
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
    name[3] & 0x20 != 0 || KEPT_CHUNKS.iter().any(|k| *k == name)
}

/// The cover's ancillary chunks, in order, with whether each follows the
/// image data. Stops at the first damaged chunk; chunks failing their CRC
/// are dropped.
fn parse_chunks(file: &[u8]) -> Option<Vec<Chunk>> {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut pos = 8;
    let mut after_idat = false;
    while pos + 12 <= file.len() && out.len() < MAX_CHUNKS {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        if len > i32::MAX as usize || pos + 12 + len > file.len() { break; }
        let name: [u8; 4] = file[pos + 4..pos + 8].try_into().unwrap();
        let data = &file[pos + 8..pos + 8 + len];
        let crc = u32::from_be_bytes(file[pos + 8 + len..pos + 12 + len].try_into().unwrap());
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
        let mut h = crc32fast::Hasher::new();
        h.update(&name);
        h.update(data);
        if h.finalize() != crc || len > MAX_CHUNK_BYTES || total + len > MAX_META_TOTAL { continue; }
        total += len;
        if keep_chunk(&name) {
            out.push(Chunk { name, data: data.to_vec(), after_idat });
        }
    }
    Some(out)
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
                    if len % 3 != 0 || len == 0 || len > 768 { return false; }
                    plte_entries = plte_entries.min(1usize << depth.min(8));
                    true
                } else {
                    false // ignored for other color types
                }
            }
            b"tRNS" if !seen_trns => {
                seen_trns = true;
                match color { 0 => len == 2, 2 => len == 6, 3 => seen_plte && len <= plte_entries, _ => false }
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

pub fn load(path: &Path) -> Option<Image> {
    let mut file = crate::fault::read_file(path, &SIGNATURE).ok()?;
    let chunks = parse_chunks(&file)?;
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

    Some(Image {
        width, height, channels, pixels, unsuitable,
        meta: Some(PngMeta { interlaced, chunks }),
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

/// Filters one scanline with whichever of the five PNG filters gives the
/// smallest sum of absolute (signed) bytes, libpng's heuristic. Appends the
/// filter type and the filtered bytes.
fn filter_row(row: &[u8], prev: &[u8], bpp: usize, out: &mut Vec<u8>) {
    let paeth = |a: u8, b: u8, c: u8| -> u8 {
        let (ia, ib, ic) = (a as i32, b as i32, c as i32);
        let p = ia + ib - ic;
        let (pa, pb, pc) = ((p - ia).abs(), (p - ib).abs(), (p - ic).abs());
        if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
    };
    let mut best: Option<(u64, u8, Vec<u8>)> = None;
    for ft in 0..5u8 {
        let mut f = Vec::with_capacity(row.len());
        for i in 0..row.len() {
            let a = if i >= bpp { row[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            f.push(row[i].wrapping_sub(match ft {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((a as u16 + b as u16) / 2) as u8,
                _ => paeth(a, b, c),
            }));
        }
        let sum: u64 = f.iter().map(|&v| (v as i8).unsigned_abs() as u64).sum();
        if best.as_ref().is_none_or(|(s, _, _)| sum < *s) { best = Some((sum, ft, f)); }
    }
    let (_, ft, f) = best.unwrap();
    out.push(ft);
    out.extend_from_slice(&f);
}

fn filtered_image(img: &Image, interlaced: bool) -> Vec<u8> {
    let ch = img.channels as usize;
    let (w, h) = (img.width as usize, img.height as usize);
    let mut out = Vec::with_capacity(h * (w * ch + 1));
    if !interlaced {
        let zero = vec![0u8; w * ch];
        for y in 0..h {
            let prev = if y == 0 { &zero[..] } else { &img.pixels[(y - 1) * w * ch..y * w * ch] };
            filter_row(&img.pixels[y * w * ch..(y + 1) * w * ch], prev, ch, &mut out);
        }
        return out;
    }
    const XS: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];
    const YS: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];
    const DX: [usize; 7] = [8, 8, 4, 4, 2, 2, 1];
    const DY: [usize; 7] = [8, 8, 8, 4, 4, 2, 2];
    for p in 0..7 {
        if w <= XS[p] || h <= YS[p] { continue; }
        let pw = (w - XS[p]).div_ceil(DX[p]);
        let mut prev = vec![0u8; pw * ch];
        let mut y = YS[p];
        while y < h {
            let mut row = Vec::with_capacity(pw * ch);
            let mut x = XS[p];
            while x < w {
                row.extend_from_slice(&img.pixels[(y * w + x) * ch..(y * w + x + 1) * ch]);
                x += DX[p];
            }
            filter_row(&row, &prev, ch, &mut out);
            prev = row;
            y += DY[p];
        }
    }
    out
}

/// The image data as one zlib stream. Done before `save` makes its temp file:
/// it is the large allocation, and a failure there must not leave one behind.
fn compress(img: &Image) -> io::Result<Vec<u8>> {
    let interlaced = img.meta.as_ref().is_some_and(|m| m.interlaced);
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(&filtered_image(img, interlaced))?;
    z.finish()
}

fn write_png(img: &Image, zlib: &[u8], w: &mut impl Write) -> io::Result<()> {
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
    for part in zlib.chunks(1 << 16) { write_chunk(w, b"IDAT", part)?; }
    if let Some(m) = &img.meta {
        for c in m.chunks.iter().filter(|c| c.after_idat) { write_chunk(w, &c.name, &c.data)?; }
    }
    write_chunk(w, b"IEND", &[])
}

pub fn save(img: &Image, path: &Path) -> io::Result<()> {
    let zlib = compress(img)?;
    atomic_write(path, |f| {
        let mut w = io::BufWriter::new(f);
        write_png(img, &zlib, &mut w)?;
        w.flush() // BufWriter's drop would swallow a failure here
    })
}

pub fn is_png_signature(bytes: &[u8]) -> bool { bytes.starts_with(&SIGNATURE) }
