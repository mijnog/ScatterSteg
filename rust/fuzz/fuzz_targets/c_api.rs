//! The C implementation's loaders, for the differential targets
#![allow(dead_code)]
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;

#[repr(C)]
pub struct CImage {
    pub width: u32,
    pub height: u32,
    pub channels: u32,
    pub rows: *mut *mut u8,
    pub unsuitable: *const c_char,
    pub meta: *mut c_void,
}

#[repr(C)]
pub struct CCarrier {
    pub img: *mut c_void,
    pub coefs: *mut *mut i16,
    pub n_coefs: u32,
    pub costs: *const f32,
}

unsafe extern "C" {
    fn png_load(path: *const c_char) -> *mut CImage;
    fn image_free(img: *mut CImage);
    fn png_save(img: *const CImage, path: *const c_char) -> c_int;
    fn jpeg_load(path: *const c_char) -> *mut c_void;
    fn jpeg_free(j: *mut c_void);
    fn jpeg_carrier(j: *mut c_void) -> CCarrier;
    fn jpeg_unsuitable(j: *const c_void) -> *const c_char;
    fn jpeg_check_writable(j: *mut c_void) -> c_int;
    fn jpeg_save(j: *const c_void, path: *const c_char) -> c_int;
}

fn cpath(p: &Path) -> CString { CString::new(p.to_str().unwrap()).unwrap() }

pub struct CPng(*mut CImage);
impl CPng {
    pub fn load(p: &Path) -> Option<CPng> {
        let r = unsafe { png_load(cpath(p).as_ptr()) };
        (!r.is_null()).then_some(CPng(r))
    }
    pub fn width(&self) -> u32 { unsafe { (*self.0).width } }
    pub fn height(&self) -> u32 { unsafe { (*self.0).height } }
    pub fn channels(&self) -> u32 { unsafe { (*self.0).channels } }
    pub fn unsuitable(&self) -> Option<String> {
        let u = unsafe { (*self.0).unsuitable };
        (!u.is_null()).then(|| unsafe { CStr::from_ptr(u) }.to_string_lossy().into_owned())
    }
    /// Pixels, rows concatenated
    pub fn pixels(&self) -> Vec<u8> {
        let (w, h, c) = (self.width() as usize, self.height() as usize, self.channels() as usize);
        let mut out = Vec::with_capacity(w * h * c);
        for y in 0..h { out.extend_from_slice(unsafe { std::slice::from_raw_parts(*(*self.0).rows.add(y), w * c) }); }
        out
    }
    pub fn save(&self, p: &Path) -> bool { unsafe { png_save(self.0, cpath(p).as_ptr()) == 0 } }
}
impl Drop for CPng { fn drop(&mut self) { unsafe { image_free(self.0) } } }

pub struct CJpeg(*mut c_void);
impl CJpeg {
    pub fn load(p: &Path) -> Option<CJpeg> {
        let r = unsafe { jpeg_load(cpath(p).as_ptr()) };
        (!r.is_null()).then_some(CJpeg(r))
    }
    /// The value of every carrier
    pub fn carrier_values(&self) -> Vec<i16> {
        let c = unsafe { jpeg_carrier(self.0) };
        (0..c.n_coefs as usize).map(|i| unsafe { **c.coefs.add(i) }).collect()
    }
    pub fn unsuitable(&self) -> bool { !unsafe { jpeg_unsuitable(self.0) }.is_null() }
    pub fn writable(&mut self) -> bool { unsafe { jpeg_check_writable(self.0) == 0 } }
    pub fn save(&self, p: &Path) -> bool { unsafe { jpeg_save(self.0, cpath(p).as_ptr()) == 0 } }
}
impl Drop for CJpeg { fn drop(&mut self) { unsafe { jpeg_free(self.0) } } }

// The C file format (codec.h), on a carrier that borrows Rust's samples
unsafe extern "C" {
    fn codec_decode(c: *const CCarrier, passphrase: *const c_char, plaintext: *mut *mut u8,
                    pt_len: *mut u32, v1: *mut c_int) -> c_int;
    fn codec_prepare(c: *const CCarrier, passphrase: *const c_char) -> *mut c_void;
    fn codec_max_message(p: *const c_void) -> usize;
    fn codec_embed(p: *mut c_void, c: *const CCarrier, message: *const u8, msg_len: u32) -> c_int;
    fn codec_prepared_free(p: *mut c_void);
    fn sodium_free(p: *mut c_void);
}

const DECODED: c_int = 0;
const NO_MATCH: c_int = 1;

pub struct CCodecCover<'a> {
    _img: Option<Box<CImage>>,
    _rows: Vec<*mut u8>,
    _coefs: Vec<*mut i16>,
    carrier: CCarrier,
    _samples: std::marker::PhantomData<&'a mut ()>,
}

impl<'a> CCodecCover<'a> {
    pub fn pixels(pixels: &'a mut [u8], w: u32, h: u32, channels: u32) -> Self {
        let stride = (w * channels) as usize;
        let mut rows: Vec<*mut u8> = pixels.chunks_exact_mut(stride).map(|r| r.as_mut_ptr()).collect();
        let mut img = Box::new(CImage {
            width: w, height: h, channels, rows: rows.as_mut_ptr(),
            unsuitable: std::ptr::null(), meta: std::ptr::null_mut(),
        });
        let carrier = CCarrier { img: (&mut *img as *mut CImage).cast(), coefs: std::ptr::null_mut(),
                                 n_coefs: 0, costs: std::ptr::null() };
        CCodecCover { _img: Some(img), _rows: rows, _coefs: Vec::new(), carrier, _samples: Default::default() }
    }

    pub fn coefs(values: &'a mut [i16], costs: &'a [f32]) -> Self {
        let mut coefs: Vec<*mut i16> = values.iter_mut().map(|v| v as *mut i16).collect();
        let carrier = CCarrier { img: std::ptr::null_mut(), coefs: coefs.as_mut_ptr(),
                                 n_coefs: coefs.len() as u32, costs: costs.as_ptr() };
        CCodecCover { _img: None, _rows: Vec::new(), _coefs: coefs, carrier, _samples: Default::default() }
    }

    /// Ok(None) if nothing is found, Err if C's decode failed
    pub fn decode(&mut self, passphrase: &[u8]) -> Result<Option<(Vec<u8>, bool)>, ()> {
        let pass = CString::new(passphrase).unwrap();
        let (mut pt, mut len, mut v1) = (std::ptr::null_mut(), 0u32, 0 as c_int);
        match unsafe { codec_decode(&self.carrier, pass.as_ptr(), &mut pt, &mut len, &mut v1) } {
            DECODED => {
                let msg = unsafe { std::slice::from_raw_parts(pt, len as usize) }.to_vec();
                unsafe { sodium_free(pt.cast()) };
                Ok(Some((msg, v1 != 0)))
            }
            NO_MATCH => Ok(None),
            _ => Err(()),
        }
    }

    /// None if the carrier is too small
    pub fn max_message(&mut self, passphrase: &[u8]) -> Option<usize> {
        let pass = CString::new(passphrase).unwrap();
        let p = unsafe { codec_prepare(&self.carrier, pass.as_ptr()) };
        if p.is_null() { return None; }
        let max = unsafe { codec_max_message(p) };
        unsafe { codec_prepared_free(p) };
        Some(max)
    }

    pub fn embed(&mut self, passphrase: &[u8], message: &[u8]) -> bool {
        let pass = CString::new(passphrase).unwrap();
        let p = unsafe { codec_prepare(&self.carrier, pass.as_ptr()) };
        !p.is_null() && unsafe { codec_embed(p, &self.carrier, message.as_ptr(), message.len() as u32) } == 0
    }
}
