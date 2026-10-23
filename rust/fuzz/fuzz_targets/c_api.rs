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
