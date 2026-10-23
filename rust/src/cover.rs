// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! A loaded cover in either format, and the carrier its bits go into.

use crate::embed::Carrier;
use crate::jpeg_io::{self, JpegImage};
use crate::png_io::{self, Image};
use std::io;
use std::path::Path;

pub enum Cover {
    Png(Image),
    Jpeg(JpegImage),
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

    pub fn save(&mut self, path: &Path) -> io::Result<()> {
        match self {
            Cover::Png(img) => png_io::save(img, path),
            Cover::Jpeg(j) => j.save(path),
        }
    }
}
