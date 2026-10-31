// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! A JPEG's quantized DCT coefficients and markers, read and written
//! losslessly: nothing is decoded to pixels and re-compressed, so only the
//! coefficients we change differ in the output.
//!
//! libjpeg reports errors by calling `error_exit`, which must not return.
//! The C original longjmps; here it unwinds with a private payload that the
//! callers of libjpeg catch (`guarded`).

use crate::atomic_write::atomic_write;
use crate::embed::Carrier;
use crate::jpeg_sys::*;
use std::io::{self, Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::os::raw::{c_int, c_ulong};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;

/// UERD's cost where the block and its neighbours have no AC energy at all
/// (every AC coefficient 0): q / 0. A large finite "wet" cost instead, as
/// UERD implementations use, so the trellis can still pass through such
/// carriers when it must. As C's JPEG_WET_COST.
const WET_COST: f32 = 1e13;
/// Largest coefficient storage load will allocate (1 GiB)
const MAX_COEF_BYTES: usize = 1 << 30;
/// Most carriers load will take. Each costs memory of its own beyond its
/// 2-byte coefficient: its cost here, its slot in the message permutation,
/// and the bits and cost STC works on. About 50 megapixels of a 4:2:0 JPEG;
/// it must equal the C version's cap.
const CARRIER_BYTES: usize = size_of::<f32>() + size_of::<u32>() + 2 + size_of::<f32>();
const MAX_CARRIERS: usize = MAX_COEF_BYTES / CARRIER_BYTES;
/// Progressive JPEGs can have any number of scans, each a full pass over the
/// coefficients; a crafted file with thousands of tiny scans takes minutes to
/// read. Real files have a few dozen at most (djpeg suggests the same cap).
const MAX_SCANS: c_int = 500;
/// Nor is the scan cap enough on its own, as each scan costs in proportion to
/// the frame: 500 empty scans of a 23000x23000 frame, 5 KB in all, took 16 s
/// to read. So the blocks the scans visit are capped too. Real files visit
/// each block about ten times (the largest image allowed here, some 84
/// million visits); past this, one costs about a second.
const MAX_SCAN_BLOCKS: u64 = 1 << 28;

/// And a frame's size is only what its header claims: a 330-byte file can
/// declare 15144x32800 with no entropy data, which libjpeg fills with zeros,
/// at 1.5 s and ~1 GB. Huffman coding spends at least 1 bit on every block
/// (its DC code), so a frame of more blocks than the file has bits is refused
/// before anything is allocated. Arithmetic coding can spend far less than a
/// bit on a block, so it isn't bound this way.
///
/// # Safety
/// `s` has read its header.
unsafe fn hollow_frame(s: *const jpeg_decompress_struct, bytes_left: u64) -> bool {
    if unsafe { (*s).arith_code } != 0 { return false; }
    let n = unsafe { (*s).num_components } as usize;
    let blocks: u64 = (0..n)
        .map(|ci| unsafe { &*(*s).comp_info.add(ci) })
        .map(|c| c.width_in_blocks as u64 * c.height_in_blocks as u64)
        .sum();
    bytes_left * 8 < blocks
}
/// What an 8-bit encoder can write: DC in [-1024, 1023], so block-to-block
/// differences fit its 11 bits; AC values that fit 10 bits
const MIN_DC: i16 = -1024;
const MAX_DC: i16 = 1023;
const MAX_AC: i16 = 1023;

const DCTSIZE2: usize = 64;

struct JpegFail;

/// Run libjpeg calls, turning an `error_exit` unwind into Err
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        if !p.is::<JpegFail>() { resume_unwind(p); }
    })
}

unsafe extern "C-unwind" fn error_exit(_: j_common_ptr) {
    resume_unwind(Box::new(JpegFail));
}

/// After load returns, nothing should make libjpeg fail on the source struct
/// (only reads and destroy follow); if it does, stop loudly rather than
/// unwind into nothing
unsafe extern "C-unwind" fn unexpected_error(_: j_common_ptr) {
    std::process::abort();
}

/// Warnings about recoverable corruption: keep going
unsafe extern "C-unwind" fn silent(_: j_common_ptr) {}

/// The progress monitor, with what limit_scans has counted
#[repr(C)]
struct Progress {
    mgr: jpeg_progress_mgr, // first: libjpeg hands back a pointer to it
    /// the scan last counted
    scan: c_int,
    /// blocks the scans so far visit
    blocks: u64,
}

/// Called before each step of reading, so at least once per scan, after its
/// header is read
unsafe extern "C-unwind" fn limit_scans(cinfo: j_common_ptr) {
    unsafe {
        if (*cinfo).is_decompressor == 0 { return; }
        let d = cinfo as j_decompress_ptr;
        let p = &mut *((*cinfo).progress as *mut Progress);
        if (*d).input_scan_number > MAX_SCANS { error_exit(cinfo); }
        if (*d).input_scan_number != p.scan {
            p.scan = (*d).input_scan_number;
            for i in 0..(*d).comps_in_scan as usize {
                let comp = (*d).cur_comp_info[i];
                p.blocks += (*comp).width_in_blocks as u64 * (*comp).height_in_blocks as u64;
            }
            if p.blocks > MAX_SCAN_BLOCKS { error_exit(cinfo); }
        }
    }
}

/// Where libjpeg writes the JPEG: a buffer we own, so a failure partway
/// leaves nothing for us to guess about. (`jpeg_mem_dest` only updates the
/// caller's pointer when it finishes, so after an error that pointer can name
/// a buffer it has already freed.)
#[repr(C)]
struct Dest {
    mgr: jpeg_destination_mgr, // first: libjpeg hands back a pointer to it
    buf: Vec<u8>,
}

const DEST_CHUNK: usize = 64 << 10;

/// Grows the buffer by at least `by` bytes and points libjpeg at the new space
unsafe fn dest_grow(cinfo: j_compress_ptr, by: usize) {
    unsafe {
        let d = &mut *((*cinfo).dest as *mut Dest);
        let used = d.buf.len();
        if d.buf.try_reserve_exact(by).is_err() { error_exit(cinfo as j_common_ptr); }
        d.buf.resize(used + by, 0);
        d.mgr.next_output_byte = d.buf.as_mut_ptr().add(used);
        d.mgr.free_in_buffer = by;
    }
}

unsafe extern "C-unwind" fn dest_init(cinfo: j_compress_ptr) { unsafe { dest_grow(cinfo, DEST_CHUNK) } }

unsafe extern "C-unwind" fn dest_empty(cinfo: j_compress_ptr) -> boolean {
    unsafe {
        let len = (*((*cinfo).dest as *mut Dest)).buf.len();
        dest_grow(cinfo, len); // doubles
    }
    1
}

unsafe extern "C-unwind" fn dest_term(cinfo: j_compress_ptr) {
    unsafe {
        let d = &mut *((*cinfo).dest as *mut Dest);
        let unused = d.mgr.free_in_buffer;
        d.buf.truncate(d.buf.len() - unused);
    }
}

fn zeroed_box<T>() -> Box<T> {
    // SAFETY: only used for libjpeg's plain-C structs, for which all-zero is valid
    unsafe { Box::new(MaybeUninit::<T>::zeroed().assume_init()) }
}

pub fn is_jpeg_file(path: &Path) -> bool {
    let mut sig = [0u8; 3];
    if crate::fault::should_fail("fopen") { return false; }
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut sig)).is_ok() && sig == [0xFF, 0xD8, 0xFF]
}

/// Where one component's blocks start in `coefs`
struct Component {
    offset: usize,
    width_in_blocks: usize,
    height_in_blocks: usize,
}

pub struct JpegImage {
    src: Box<jpeg_decompress_struct>,
    _err: Box<jpeg_error_mgr>,
    _progress: Box<Progress>,
    /// The file, which libjpeg reads from for as long as `src` lives
    _data: Vec<u8>,
    virt: *mut jvirt_barray_ptr,
    comps: Vec<Component>,
    /// Every component's blocks, 64 coefficients each, block rows in order
    pub coefs: Vec<i16>,
    /// The cost of changing each carrier. The carriers are every AC
    /// coefficient, zeros included, in component, block-row, block,
    /// coefficient order (see `Carrier::jpeg`), as UED, UERD and J-UNIWARD
    /// use them; the costs keep changes out of smooth blocks. DC
    /// coefficients are never used: changing them shows as blocking.
    pub costs: Vec<f32>,
    /// How many AC coefficients aren't 0: what JPEG payloads are measured in
    pub nonzero_ac: u64,
    /// Bytes after the EOI marker
    trailing_data: bool,
}

impl JpegImage {
    /// Loads an 8-bit DCT JPEG (baseline or progressive, Huffman or
    /// arithmetic coded). None if it can't be read, is lossless or not 8-bit,
    /// or would need more than 1 GiB of coefficients, or of memory for its
    /// carriers.
    pub fn load(path: &Path) -> Option<JpegImage> {
        Self::from_bytes(crate::fault::read_file(path, &[0xFF, 0xD8, 0xFF]).ok()?)
    }

    /// The same from a JPEG file's bytes
    pub fn from_bytes(data: Vec<u8>) -> Option<JpegImage> {
        let mut err: Box<jpeg_error_mgr> = zeroed_box();
        let mut progress: Box<Progress> = zeroed_box();
        progress.mgr.progress_monitor = Some(limit_scans);
        let mut src: Box<jpeg_decompress_struct> = zeroed_box();
        // SAFETY: the boxes give libjpeg stable addresses for as long as the struct lives
        unsafe {
            src.err = jpeg_std_error(&mut *err);
            err.error_exit = Some(error_exit);
            err.output_message = Some(silent);
        }
        let s: *mut jpeg_decompress_struct = &mut *src;
        let read = guarded(|| unsafe {
            jpeg_CreateDecompress(s, JPEG_LIB_VERSION as c_int, size_of::<jpeg_decompress_struct>());
        });
        read.ok()?;
        // From here on, `destroy` cleans up
        let destroy = |s: *mut jpeg_decompress_struct| unsafe { jpeg_destroy_decompress(s) };

        let loaded = guarded(|| unsafe {
            (*s).progress = &mut progress.mgr;
            (*(*s).mem).max_memory_to_use = (MAX_COEF_BYTES + (16 << 20)) as _;
            jpeg_mem_src(s, data.as_ptr(), data.len() as c_ulong);
            // Keep comments and every APPn (EXIF, ICC profile, XMP...) to write back
            jpeg_save_markers(s, JPEG_COM as c_int, 0xFFFF);
            for m in 0..16 { jpeg_save_markers(s, JPEG_APP0 as c_int + m, 0xFFFF); }
            jpeg_read_header(s, 1);

            // 2 bytes per coefficient, one coefficient per sample: an upper
            // bound even before subsampling, checked before anything is allocated
            if (*s).data_precision != 8
                || (*s).image_width as u64 * (*s).image_height as u64 * (*s).num_components as u64 * 2
                    > MAX_COEF_BYTES as u64 {
                error_exit(s as j_common_ptr);
            }
            // (from memory, so what libjpeg has left is the rest of the file)
            if hollow_frame(s, (*(*s).src).bytes_in_buffer as u64) { error_exit(s as j_common_ptr); }
            let virt = jpeg_read_coefficients(s);
            if virt.is_null() { error_exit(s as j_common_ptr); }
            virt
        });
        let Ok(virt) = loaded else {
            destroy(s);
            return None;
        };

        let mut img = JpegImage {
            src, _err: err, _progress: progress,
            virt, comps: Vec::new(), coefs: Vec::new(), costs: Vec::new(),
            nonzero_ac: 0,
            trailing_data: false,
            _data: Vec::new(),
        };
        // `img` owns the struct now: take the pointer from there (the Box's
        // address is the same, but a pointer taken before the move is not
        // derived from the Box that holds it)
        let s: *mut jpeg_decompress_struct = &mut *img.src;
        // Reading stops at EOI: anything left in the buffer comes after
        img.trailing_data = unsafe { (*(*s).src).bytes_in_buffer } > 0;
        let collected = guarded(|| img.collect_carriers());
        if !matches!(collected, Ok(true)) { return None; } // dropping img destroys the decompressor
        img._data = data;
        unsafe {
            img._err.error_exit = Some(unexpected_error);
            (*s).progress = ptr::null_mut();
        }
        Some(img)
    }

    /// Copies out the coefficients and finds the carriers. Also checks every
    /// coefficient is one the encoder can write back: corrupt entropy data
    /// can decode to values beyond its 11-bit DC / 10-bit AC range, and then
    /// saving would fail. False if one is out of range or there are too many
    /// carriers.
    fn collect_carriers(&mut self) -> bool {
        let s: *mut jpeg_decompress_struct = &mut *self.src;
        let access = unsafe { (*(*s).mem).access_virt_barray.unwrap() };
        let n_comps = unsafe { (*s).num_components } as usize;
        for ci in 0..n_comps {
            let comp = unsafe { &*(*s).comp_info.add(ci) };
            let (wb, hb) = (comp.width_in_blocks as usize, comp.height_in_blocks as usize);
            self.comps.push(Component { offset: self.coefs.len(), width_in_blocks: wb, height_in_blocks: hb });
            let start = self.coefs.len();
            if self.costs.len() + wb * hb * (DCTSIZE2 - 1) > MAX_CARRIERS { return false; }
            self.coefs.reserve(wb * hb * DCTSIZE2);
            for by in 0..hb {
                let row = unsafe { access(s as j_common_ptr, *self.virt.add(ci), by as u32, 1, 1) };
                let blocks = unsafe { std::slice::from_raw_parts(*row, wb) };
                for block in blocks {
                    if !(MIN_DC..=MAX_DC).contains(&block[0]) { return false; }
                    if block[1..].iter().any(|&c| !(-MAX_AC..=MAX_AC).contains(&c)) { return false; }
                    self.coefs.extend_from_slice(block);
                }
            }
            // (a corrupt file's component may lack a table)
            let quant = unsafe { comp.quant_table.as_ref() };
            let q = |k: usize| { let q = quant.map_or(1.0, |t| t.quantval[k] as f32); if q > 0.0 { q } else { 1.0 } };
            // UERD (Guo, Ni, Su, Tang and Shi, 2015): a block's energy is the
            // sum of its dequantized AC magnitudes, and a change costs the
            // coefficient's quantization step over the energy of the block
            // and, at a quarter weight, its 8 neighbours: cheap in busy
            // blocks and low frequencies, dear in smooth ones
            // Or J-UNIWARD, in builds with it (see distortion)
            if cfg!(jpeg_costs = "juniward") && wb * hb * 64 > crate::distortion::JUNIWARD_MAX_PIXELS { return false; }
            let juniward = cfg!(jpeg_costs = "juniward").then(|| {
                let quant: [u16; 64] = std::array::from_fn(|k| quant.map_or(1, |t| if t.quantval[k] > 0 { t.quantval[k] } else { 1 }));
                let pw = wb * 8;
                let mut pixels = vec![0f32; pw * hb * 8];
                for (b, block) in self.coefs[start..].as_chunks::<DCTSIZE2>().0.iter().enumerate() {
                    let (bx, by) = (b % wb, b / wb);
                    let px = crate::distortion::idct_block(block, &quant);
                    for y in 0..8 {
                        let at = (by * 8 + y) * pw + bx * 8;
                        pixels[at..at + 8].copy_from_slice(&px[y * 8..y * 8 + 8]);
                    }
                }
                crate::distortion::JUniward::new(&pixels, pw, hb * 8, &quant)
            });
            let energy: Vec<f32> = self.coefs[start..].as_chunks::<DCTSIZE2>().0.iter()
                .map(|b| (1..DCTSIZE2).fold(0f32, |e, k| e + (b[k] as i32).abs() as f32 * q(k)))
                .collect();
            for (i, &c) in self.coefs[start..].iter().enumerate() {
                let k = i % DCTSIZE2;
                if k != 0 && c != 0 { self.nonzero_ac += 1; }
                if k == 0 { continue; }
                let (bx, by) = ((i / DCTSIZE2) % wb, (i / DCTSIZE2) / wb);
                let mut around = 0f32;
                for dy in -1..=1isize {
                    for dx in -1..=1isize {
                        let (y, x) = (by as isize + dy, bx as isize + dx);
                        if y < 0 || x < 0 || y >= hb as isize || x >= wb as isize { continue; }
                        let e = energy[y as usize * wb + x as usize];
                        around += if dy != 0 || dx != 0 { 0.25 * e } else { e };
                    }
                }
                self.costs.push(match &juniward {
                    Some(j) => j.cost(bx, by, k),
                    None if around > 0.0 => q(k) / around,
                    None => WET_COST,
                });
            }
        }
        true
    }

    pub fn carrier(&mut self) -> Carrier<'_> {
        Carrier::jpeg(&mut self.coefs, &self.costs)
    }

    /// Width and height in pixels
    pub fn size(&self) -> (u32, u32) {
        (self.src.image_width, self.src.image_height)
    }

    /// Why a cover this way would come out visibly changed, or None. Data
    /// after the EOI marker (MPF secondary images, Ultra HDR gain maps, depth
    /// maps) isn't kept, while the markers indexing it would be. A content
    /// credential (C2PA) would be kept, but no longer match the pixels.
    pub fn unsuitable(&self) -> Option<&'static str> {
        if self.trailing_data {
            return Some("data after the end of the image (such as a second image or an HDR gain map)");
        }
        self.c2pa_manifest().then_some("a content credential (C2PA) signing its pixels")
    }

    /// A C2PA manifest (content credentials, which some phones and cameras
    /// now sign their photos with): JUMBF boxes in APP11 segments, the first
    /// one labelled "c2pa". It signs a hash of the image data, so any change
    /// to the coefficients shows as tampering to anyone who checks it.
    fn c2pa_manifest(&self) -> bool {
        let mut m = self.src.marker_list;
        while !m.is_null() {
            // SAFETY: libjpeg's saved-marker list, kept until the decompressor is destroyed
            let mk = unsafe { &*m };
            let data = unsafe { std::slice::from_raw_parts(mk.data, mk.data_length as usize) };
            if mk.marker == JPEG_APP0 as u8 + 11 && data.starts_with(b"JP") && data.windows(4).any(|w| w == b"c2pa") {
                return true;
            }
            m = mk.next;
        }
        false
    }

    /// Some JPEGs decode fine but libjpeg won't write their coefficients back
    /// (a quantization table redefined between scans, sampling factors too
    /// big for the scans it would generate, ...: each found by fuzzing).
    /// Encodes to nowhere to find out. True if `save` would succeed (barring I/O).
    ///
    /// And that what it writes reads back as the same coefficients: a
    /// truncated progressive file (a first AC scan at Al=1 and no refinement)
    /// is written with different values, which would corrupt a message hidden
    /// in them.
    pub fn check_writable(&mut self) -> bool {
        let Some(bytes) = self.encode() else { return false };
        let Some(back) = JpegImage::from_bytes(bytes) else { return false };
        back.coefs == self.coefs
    }

    /// Writes the coefficients and markers as a JPEG, atomically
    pub fn save(&mut self, path: &Path) -> io::Result<()> {
        let bytes = self.encode().ok_or_else(|| io::Error::other("JPEG encoding failed"))?;
        atomic_write(path, |f| f.write_all(&bytes))
    }

    /// Copies `coefs` back into libjpeg's arrays
    fn sync_to_libjpeg(&mut self) {
        let s: *mut jpeg_decompress_struct = &mut *self.src;
        let access = unsafe { (*(*s).mem).access_virt_barray.unwrap() };
        for (ci, comp) in self.comps.iter().enumerate() {
            for by in 0..comp.height_in_blocks {
                let row = unsafe { access(s as j_common_ptr, *self.virt.add(ci), by as u32, 1, 1) };
                let blocks = unsafe { std::slice::from_raw_parts_mut(*row, comp.width_in_blocks) };
                let at = comp.offset + by * comp.width_in_blocks * DCTSIZE2;
                for (bx, block) in blocks.iter_mut().enumerate() {
                    block.copy_from_slice(&self.coefs[at + bx * DCTSIZE2..at + (bx + 1) * DCTSIZE2]);
                }
            }
        }
    }

    /// The coefficients and markers as a JPEG file's bytes
    pub fn encode(&mut self) -> Option<Vec<u8>> {
        self.sync_to_libjpeg();
        let mut err: Box<jpeg_error_mgr> = zeroed_box();
        let mut dst: Box<jpeg_compress_struct> = zeroed_box();
        unsafe {
            dst.err = jpeg_std_error(&mut *err);
            err.error_exit = Some(error_exit);
            err.output_message = Some(silent);
        }
        let d: *mut jpeg_compress_struct = &mut *dst;
        let s: *mut jpeg_decompress_struct = &mut *self.src;
        guarded(|| unsafe { jpeg_CreateCompress(d, JPEG_LIB_VERSION as c_int, size_of::<jpeg_compress_struct>()) }).ok()?;

        // Declared before the compressor is destroyed below, so it outlives it
        let mut dest = Box::new(Dest {
            mgr: jpeg_destination_mgr {
                next_output_byte: ptr::null_mut(),
                free_in_buffer: 0,
                init_destination: Some(dest_init),
                empty_output_buffer: Some(dest_empty),
                term_destination: Some(dest_term),
            },
            buf: Vec::new(),
        });
        let virt = self.virt;
        let done = guarded(|| unsafe {
            (*d).dest = &mut dest.mgr;

            // Same quantization, sampling, color space and coding as the cover
            jpeg_copy_critical_parameters(s, d);
            // It turns on the JFIF (or Adobe) header for the color space;
            // write one only if the cover had one, as a camera's Exif-only
            // file doesn't
            (*d).write_JFIF_header = (*s).saw_JFIF_marker;
            (*d).write_Adobe_marker = (*s).saw_Adobe_marker;
            (*d).arith_code = (*s).arith_code;
            (*d).restart_interval = (*s).restart_interval;
            if (*s).progressive_mode != 0 { jpeg_simple_progression(d); }
            // A changed coefficient may need a Huffman code an optimized
            // table lacks, so the cover's own tables can't be reused. Keep
            // the standard tables if it had them, else optimize like its
            // encoder did.
            (*d).optimize_coding = ((*d).arith_code == 0 && !standard_tables(s, d)) as boolean;

            jpeg_write_coefficients(d, virt);

            // Markers, as jpegtran copies them: libjpeg writes the JFIF and
            // Adobe headers itself when the cover had them, so skip the
            // cover's copies
            let mut m = (*s).marker_list;
            while !m.is_null() {
                let mk = &*m;
                let data = std::slice::from_raw_parts(mk.data, mk.data_length as usize);
                let skip = ((*d).write_JFIF_header != 0 && is_marker(mk, data, JPEG_APP0 as u8, b"JFIF\0"))
                    || ((*d).write_Adobe_marker != 0 && is_marker(mk, data, JPEG_APP0 as u8 + 14, b"Adobe"));
                if !skip { jpeg_write_marker(d, mk.marker as c_int, mk.data, mk.data_length); }
                m = mk.next;
            }
            jpeg_finish_compress(d);
        });
        // jpeg_finish_compress ran dest_term, which trimmed the buffer to the output
        unsafe { jpeg_destroy_compress(d) };
        done.is_ok().then(|| std::mem::take(&mut dest.buf))
    }
}

impl Drop for JpegImage {
    fn drop(&mut self) {
        let s: *mut jpeg_decompress_struct = &mut *self.src;
        unsafe { jpeg_destroy_decompress(s) };
    }
}

fn is_marker(m: &jpeg_marker_struct, data: &[u8], code: u8, tag: &[u8]) -> bool {
    m.marker == code && data.len() >= tag.len() && &data[..tag.len()] == tag
}

/// Did the cover use the standard Huffman tables (as most cameras do)?
/// Compared against the defaults jpeg_copy_critical_parameters set up.
unsafe fn standard_tables(s: *const jpeg_decompress_struct, d: *const jpeg_compress_struct) -> bool {
    unsafe {
        for i in 0..NUM_HUFF_TBLS as usize {
            let pairs = [((*s).dc_huff_tbl_ptrs[i], (*d).dc_huff_tbl_ptrs[i]),
                         ((*s).ac_huff_tbl_ptrs[i], (*d).ac_huff_tbl_ptrs[i])];
            for (a, b) in pairs {
                if a.is_null() { continue; }
                if b.is_null() || (*a).bits != (*b).bits || (*a).huffval != (*b).huffval { return false; }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As jpeg_io.c's JPEG_CARRIER_BYTES. A different cap here lets us write
    /// JPEGs C refuses to read.
    #[test]
    fn carrier_cap_matches_c() {
        assert_eq!(CARRIER_BYTES, 14);
        assert_eq!(MAX_CARRIERS, (1usize << 30) / 14);
    }
}
