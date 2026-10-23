// SPDX-License-Identifier: AGPL-3.0-or-later
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

/// Largest coefficient storage load will allocate (1 GiB)
const MAX_COEF_BYTES: usize = 1 << 30;
/// Most carriers load will take. Each costs memory of its own beyond its
/// 2-byte coefficient: its index and cost here, its slot in the message
/// permutation, and the bits and cost STC works on.
const CARRIER_BYTES: usize = size_of::<u32>() + size_of::<f32>() + size_of::<u32>() + 2 + size_of::<f32>();
const MAX_CARRIERS: usize = MAX_COEF_BYTES / CARRIER_BYTES;
/// Progressive JPEGs can have any number of scans, each a full pass over the
/// coefficients; a crafted file with thousands of tiny scans takes minutes to
/// read. Real files have a few dozen at most (djpeg suggests the same cap).
const MAX_SCANS: c_int = 500;
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

unsafe extern "C-unwind" fn limit_scans(cinfo: j_common_ptr) {
    unsafe {
        if (*cinfo).is_decompressor != 0 && (*(cinfo as j_decompress_ptr)).input_scan_number > MAX_SCANS {
            error_exit(cinfo);
        }
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
    _progress: Box<jpeg_progress_mgr>,
    /// The file, which libjpeg reads from for as long as `src` lives
    _data: Vec<u8>,
    virt: *mut jvirt_barray_ptr,
    comps: Vec<Component>,
    /// Every component's blocks, 64 coefficients each, block rows in order
    pub coefs: Vec<i16>,
    /// Indices into `coefs` of the carriers: every AC coefficient with
    /// |value| >= 2, in component, block-row, block, coefficient order. DC
    /// coefficients, zeros and +-1 are never used: changing them shows
    /// (blocking, and the count of zeros that JPEG steganalysis watches).
    pub carriers: Vec<u32>,
    pub costs: Vec<f32>,
    /// Bytes after the EOI marker
    trailing_data: bool,
}

impl JpegImage {
    /// Loads an 8-bit DCT JPEG (baseline or progressive, Huffman or
    /// arithmetic coded). None if it can't be read, is lossless or not 8-bit,
    /// or would need more than 1 GiB of coefficients, or of memory for its
    /// carriers.
    pub fn load(path: &Path) -> Option<JpegImage> {
        let data = crate::fault::read_file(path, &[0xFF, 0xD8, 0xFF]).ok()?;
        let mut err: Box<jpeg_error_mgr> = zeroed_box();
        let mut progress: Box<jpeg_progress_mgr> = zeroed_box();
        progress.progress_monitor = Some(limit_scans);
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
            (*s).progress = &mut *progress;
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
            virt, comps: Vec::new(), coefs: Vec::new(), carriers: Vec::new(), costs: Vec::new(),
            trailing_data: false,
            _data: Vec::new(),
        };
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
            self.coefs.reserve(wb * hb * DCTSIZE2);
            for by in 0..hb {
                let row = unsafe { access(s as j_common_ptr, *self.virt.add(ci), by as u32, 1, 1) };
                let blocks = unsafe { std::slice::from_raw_parts(*row, wb) };
                for block in blocks {
                    if block[0] < MIN_DC || block[0] > MAX_DC { return false; }
                    if block[1..].iter().any(|&c| c < -MAX_AC || c > MAX_AC) { return false; }
                    self.coefs.extend_from_slice(block);
                }
            }
            // (a corrupt file's component may lack a table)
            let quant = unsafe { comp.quant_table.as_ref() };
            for (i, &c) in self.coefs[start..].iter().enumerate() {
                let k = i % DCTSIZE2;
                if k == 0 || (c > -2 && c < 2) { continue; }
                if self.carriers.len() >= MAX_CARRIERS { return false; }
                // A change of 1 moves the block's pixels in proportion to the
                // quantization step. And 2 can only go to 3, shifting the 2:3
                // ratio detectors watch: 1.5x keeps the ratio within ~0.5% of
                // the cover's in testing (1x lets it fall, 2-3x pushes it up)
                let q = quant.map_or(1.0, |t| t.quantval[k] as f32);
                self.carriers.push((start + i) as u32);
                self.costs.push(if q > 0.0 { q } else { 1.0 } * if c == 2 || c == -2 { 1.5 } else { 1.0 });
            }
        }
        true
    }

    pub fn carrier(&mut self) -> Carrier<'_> {
        Carrier::jpeg(&mut self.coefs, &self.carriers, &self.costs)
    }

    /// Why a cover this way would come out visibly changed, or None. Data
    /// after the EOI marker (MPF secondary images, Ultra HDR gain maps, depth
    /// maps) isn't kept, while the markers indexing it would be.
    pub fn unsuitable(&self) -> Option<&'static str> {
        self.trailing_data.then_some("data after the end of the image (such as a second image or an HDR gain map)")
    }

    /// Some JPEGs decode fine but libjpeg won't write their coefficients back
    /// (a quantization table redefined between scans, sampling factors too
    /// big for the scans it would generate, ...: each found by fuzzing).
    /// Encodes to nowhere to find out. True if `save` would succeed (barring I/O).
    pub fn check_writable(&mut self) -> bool {
        self.encode().is_some()
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
    fn encode(&mut self) -> Option<Vec<u8>> {
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

        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let virt = self.virt;
        let done = guarded(|| unsafe {
            jpeg_mem_dest(d, &mut out, &mut out_len);

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
        let bytes = if done.is_ok() {
            // SAFETY: jpeg_finish_compress left the whole output in `out`
            Some(unsafe { std::slice::from_raw_parts(out, out_len as usize) }.to_vec())
        } else {
            None
        };
        unsafe {
            jpeg_destroy_compress(d);
            if !out.is_null() { libc::free(out.cast()); }
        }
        bytes
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
