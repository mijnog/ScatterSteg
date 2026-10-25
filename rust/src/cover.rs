// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! A loaded cover in either format, and the carrier its bits go into.

use crate::atomic_write::atomic_write;
use crate::embed::Carrier;
use crate::jpeg_io::{self, JpegImage};
use crate::png_io::{self, Image};
use std::io::{self, Write};
use std::path::Path;

pub enum Cover {
    Png(Image),
    Jpeg(JpegImage),
}

pub enum SaveError {
    /// Writing failed; an error with no OS code means the encoder did
    Io(io::Error),
    /// What was encoded didn't load (also what running out of memory gives)
    Unreadable,
    /// It loaded, but a decoder would see a different carrier
    Changed,
}

impl Cover {
    /// Loads a PNG or JPEG (by its first bytes). png_io caps images at 1 GiB,
    /// so positions fit in 32 bits.
    pub fn load(path: &Path) -> Option<Cover> {
        if jpeg_io::is_jpeg_file(path) {
            JpegImage::load(path).map(Cover::Jpeg)
        } else {
            png_io::load(path).map(Cover::Png)
        }
    }

    pub fn is_jpeg(&self) -> bool { matches!(self, Cover::Jpeg(_)) }

    pub fn carrier(&mut self) -> Carrier<'_> {
        match self {
            Cover::Png(img) => {
                let count = img.width * img.height;
                Carrier::png(&mut img.pixels, count, img.channels)
            }
            Cover::Jpeg(j) => j.carrier(),
        }
    }

    /// Encodes the cover in memory and reads that back: only if a decoder
    /// sees the same carrier does it go to `path` (atomically), so an encoder
    /// that changes a sample on the way out can't lose the message
    /// unnoticed. Drops the cover first, so only one image is in memory at a
    /// time.
    pub fn save(mut self, path: &Path) -> Result<(), SaveError> {
        let want = self.carrier().digest();
        let bytes = match &mut self {
            Cover::Png(img) => png_io::encode(img).map_err(SaveError::Io)?,
            Cover::Jpeg(j) => j.encode().ok_or_else(|| SaveError::Io(io::Error::other("JPEG encoding failed")))?,
        };
        let is_jpeg = self.is_jpeg();
        drop(self);

        let mut back = if is_jpeg {
            JpegImage::from_bytes(bytes.clone()).map(Cover::Jpeg)
        } else {
            png_io::from_bytes(bytes.clone()).map(Cover::Png)
        }
        .ok_or(SaveError::Unreadable)?;
        // The fault sweeps fail this as C's sodium_memcmp
        if crate::fault::should_fail("sodium_memcmp") || back.carrier().digest() != want {
            return Err(SaveError::Changed);
        }
        drop(back);
        atomic_write(path, |f| f.write_all(&bytes)).map_err(SaveError::Io)
    }
}
