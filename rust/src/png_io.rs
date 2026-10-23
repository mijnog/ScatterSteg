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
fn parse_chunks(file: &[u8]) -> Vec<Chunk> {
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
    out
}

pub fn load(path: &Path) -> Option<Image> {
    let file = crate::fault::read_file(path).ok()?;
    let mut decoder = png::Decoder::new(Cursor::new(&file[..]));
    // Text and profile chunks are copied as raw bytes (see parse_chunks), so
    // the decoder needn't parse them, and a malformed one can't stop the load
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
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
    let row_size = width as usize * channels as usize;
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
        meta: Some(PngMeta { interlaced, chunks: parse_chunks(&file) }),
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

fn write_png(img: &Image, w: &mut impl Write) -> io::Result<()> {
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
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(&filtered_image(img, interlaced))?;
    for part in z.finish()?.chunks(1 << 16) { write_chunk(w, b"IDAT", part)?; }
    if let Some(m) = &img.meta {
        for c in m.chunks.iter().filter(|c| c.after_idat) { write_chunk(w, &c.name, &c.data)?; }
    }
    write_chunk(w, b"IEND", &[])
}

pub fn save(img: &Image, path: &Path) -> io::Result<()> {
    atomic_write(path, |f| {
        let mut w = io::BufWriter::new(f);
        write_png(img, &mut w)?;
        w.flush() // BufWriter's drop would swallow a failure here
    })
}

pub fn is_png_signature(bytes: &[u8]) -> bool { bytes.starts_with(&SIGNATURE) }
