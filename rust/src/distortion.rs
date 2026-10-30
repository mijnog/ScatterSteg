// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! Distortion models beyond the defaults (HILL for PNG, `Carrier::hill_costs`;
//! UERD for JPEG, in jpeg_io): the wavelet-based models of Holub and Fridrich,
//! as `distortion.c`, which has the details. Each gives the cost of a +-1
//! change to every sample, which only the encoder uses: a message embedded
//! with any model reads back with any build.
//!
//! A build picks its models with the environment variables
//! `SCATTERSTEG_PNG_COSTS` (hill, wow or suniward) and `SCATTERSTEG_JPEG_COSTS`
//! (uerd or juniward) at compile time, as the C build's `PNG_COSTS` and
//! `JPEG_COSTS`; see build.rs.

/// The Daubechies 8 decomposition filters, low and high pass, to the digits
/// the references give them
const LO: [f64; TAPS] = [
    -0.00011747678400228192, 0.00067544940599855677, -0.00039174037299597711,
    -0.0048703529930106603, 0.0087460940470156547, 0.013981027917015516,
    -0.044088253931064719, -0.017369301002022108, 0.12874742662018601,
    0.00047248457399797254, -0.28401554296242809, -0.015829105256023893,
    0.58535468365486909, 0.67563073629801285, 0.31287159091446592,
    0.054415842243081609];
const HI: [f64; TAPS] = [
    -0.054415842243081609, 0.31287159091446592, -0.67563073629801285,
    0.58535468365486909, 0.015829105256023893, -0.28401554296242809,
    -0.00047248457399797254, 0.12874742662018601, 0.017369301002022108,
    -0.044088253931064719, -0.013981027917015516, 0.0087460940470156547,
    0.0048703529930106603, -0.00039174037299597711, -0.00067544940599855677,
    -0.00011747678400228192];
const TAPS: usize = 16;

/// The three directional sub-bands, LH, HL and HH: vertical filter,
/// horizontal filter
const BANDS: [[&[f64; TAPS]; 2]; 3] = [[&LO, &HI], [&HI, &LO], [&HI, &HI]];

/// Planes are mirrored out by this much on every side, as the references pad
/// them
const PAD: usize = 16;

/// As the references write it
const PI: f64 = 3.14159265358979323846;
/// 2^-6, the J-UNIWARD paper's and MATLAB reference's; S-UNIWARD uses 1
const SIGMA_JPEG: f64 = 0.015625;
const SIGMA_SPATIAL: f64 = 1.0;

/// Costs above these are capped, as the references cap theirs
pub const WET_SPATIAL: f32 = 1e10;
pub const WET_JPEG: f32 = 1e13;

/// Index j mirrored into 0..n (MATLAB's 'symmetric'), repeatedly for planes
/// narrower than PAD
fn mirror(mut j: isize, n: isize) -> usize {
    while j < 0 || j >= n { j = if j < 0 { -j - 1 } else { 2 * n - j - 1 }; }
    j as usize
}

/// out[i] = sum over t of in[i + t - 8] * k[t], zero outside 0..n, along a
/// line of n samples `step` apart
fn corr_line(input: &[f32], out: &mut [f32], n: usize, step: usize, k: &[f64; TAPS]) {
    for i in 0..n {
        let mut s = 0f64;
        for (t, kt) in k.iter().enumerate() {
            let j = i as isize + t as isize - 8;
            if j >= 0 && j < n as isize { s += input[j as usize * step] as f64 * kt; }
        }
        out[i * step] = s as f32;
    }
}

/// The same in double precision, for J-UNIWARD (see distortion.c)
fn corr_line_d(input: &[f64], out: &mut [f64], n: usize, step: usize, k: &[f64; TAPS]) {
    for i in 0..n {
        let mut s = 0f64;
        for (t, kt) in k.iter().enumerate() {
            let j = i as isize + t as isize - 8;
            if j >= 0 && j < n as isize { s += input[j as usize * step] * kt; }
        }
        out[i * step] = s;
    }
}

/// Separable correlation of a w x h plane: down the columns with kv (into
/// tmp), then along the rows with kh (into out)
fn corr2(input: &[f32], tmp: &mut [f32], out: &mut [f32], w: usize, h: usize, kv: &[f64; TAPS], kh: &[f64; TAPS]) {
    for x in 0..w { corr_line(&input[x..], &mut tmp[x..], h, w, kv); }
    for y in 0..h { corr_line(&tmp[y * w..], &mut out[y * w..], w, 1, kh); }
}

/// WOW and S-UNIWARD (see distortion.c), for `channels` interleaved samples
/// per pixel, each channel costed on its own
fn wavelet_costs(px: &[u8], w: usize, h: usize, ch: usize, uniward: bool) -> Vec<f32> {
    let (pw, ph) = (w + 2 * PAD, h + 2 * PAD);
    let mut pad = vec![0f32; pw * ph];
    let mut tmp = vec![0f32; pw * ph];
    let mut r = vec![0f32; pw * ph];
    let mut costs = vec![0f32; w * h * ch];
    for c in 0..ch {
        for y in 0..ph {
            let sy = mirror(y as isize - PAD as isize, h as isize);
            for x in 0..pw {
                let sx = mirror(x as isize - PAD as isize, w as isize);
                pad[y * pw + x] = px[(sy * w + sx) * ch + c] as f32;
            }
        }
        for band in BANDS {
            let mut rv = [0f64; TAPS];
            let mut rh = [0f64; TAPS];
            let mut av = [0f64; TAPS];
            let mut ah = [0f64; TAPS];
            for t in 0..TAPS {
                rv[t] = band[0][TAPS - 1 - t]; // convolution: the filter reversed
                rh[t] = band[1][TAPS - 1 - t];
                av[t] = band[0][t].abs();
                ah[t] = band[1][t].abs();
            }
            corr2(&pad, &mut tmp, &mut r, pw, ph, &rv, &rh);
            for v in r.iter_mut() {
                *v = if uniward { (1.0 / ((*v as f64).abs() + SIGMA_SPATIAL)) as f32 } else { v.abs() };
            }
            let input = std::mem::take(&mut r);
            r = vec![0f32; pw * ph];
            corr2(&input, &mut tmp, &mut r, pw, ph, &av, &ah);
            // The references' crop, one sample off centre (see distortion.c)
            for y in 0..h {
                for x in 0..w {
                    let xi = r[(y + PAD + 1) * pw + x + PAD + 1];
                    costs[(y * w + x) * ch + c] += if uniward { xi } else { 1.0 / xi };
                }
            }
        }
    }
    for v in costs.iter_mut() {
        if !(*v <= WET_SPATIAL) { *v = WET_SPATIAL; } // and NaN
    }
    costs
}

/// WOW (Holub and Fridrich, 2012) for every sample, in pixel order
pub fn wow(px: &[u8], w: usize, h: usize, ch: usize) -> Vec<f32> {
    wavelet_costs(px, w, h, ch, false)
}

/// S-UNIWARD (Holub, Fridrich and Denemark, 2014) for every sample, in pixel order
pub fn suniward(px: &[u8], w: usize, h: usize, ch: usize) -> Vec<f32> {
    wavelet_costs(px, w, h, ch, true)
}

/// J-UNIWARD's planes take about 28 bytes per pixel of the component, so
/// builds with it refuse a component larger than this (see distortion.h)
pub const JUNIWARD_MAX_PIXELS: usize = 1 << 26;

/// The 23 x 23 window of sub-band coefficients a block's change reaches
const REACH: usize = 8 + TAPS - 1;

/// J-UNIWARD (same paper) for one JPEG component, from its decompressed plane
/// (see distortion.c)
pub struct JUniward {
    pw: usize,
    rinv: [Vec<f32>; 3],
    impact: Vec<[f64; REACH * REACH]>, // band * 64 + DCT mode
}

/// The 8-point DCT basis: alpha(u) cos(pi/8 (x + 1/2) u)
fn dct_basis() -> [[f64; 8]; 8] {
    let mut b = [[0f64; 8]; 8];
    for (x, row) in b.iter_mut().enumerate() {
        for (u, v) in row.iter_mut().enumerate() {
            let alpha = if u > 0 { (2.0f64 / 8.0).sqrt() } else { (1.0f64 / 8.0).sqrt() };
            *v = alpha * (PI / 8.0 * (x as f64 + 0.5) * u as f64).cos();
        }
    }
    b
}

/// One block's pixels as decompression gives them: the inverse DCT of
/// coef[k] * quant[k], plus 128, rounded and clamped to 0..255
pub fn idct_block(coef: &[i16], quant: &[u16; 64]) -> [f32; 64] {
    let basis = dct_basis();
    let mut tmp = [[0f64; 8]; 8];
    for x in 0..8 {
        for v in 0..8 {
            let mut s = 0f64;
            for u in 0..8 { s += basis[x][u] * coef[u * 8 + v] as f64 * quant[u * 8 + v] as f64; }
            tmp[x][v] = s;
        }
    }
    let mut out = [0f32; 64];
    for x in 0..8 {
        for y in 0..8 {
            let mut s = 128f64;
            for v in 0..8 { s += tmp[x][v] * basis[y][v]; }
            out[x * 8 + y] = (s + 0.5).floor().clamp(0.0, 255.0) as f32;
        }
    }
    out
}

/// "Full"-size correlation of n samples `step` apart: out[i] = sum over t of
/// in[i + t - 15] * k[t], for i in 0..n+15
fn full_line(input: &[f64], out: &mut [f64], n: usize, step: usize, k: &[f64; TAPS]) {
    for i in 0..n + TAPS - 1 {
        let mut s = 0f64;
        for (t, kt) in k.iter().enumerate() {
            let j = i as isize + t as isize - (TAPS as isize - 1);
            if j >= 0 && j < n as isize { s += input[j as usize * step] * kt; }
        }
        out[i * step] = s;
    }
}

impl JUniward {
    /// From a w x h plane (whole blocks), row by row; quant in natural order
    pub fn new(pixels: &[f32], w: usize, h: usize, quant: &[u16; 64]) -> JUniward {
        let (pw, ph) = (w + 2 * PAD, h + 2 * PAD);
        let mut pad = vec![0f64; pw * ph];
        for y in 0..ph {
            let sy = mirror(y as isize - PAD as isize, h as isize);
            for x in 0..pw {
                pad[y * pw + x] = pixels[sy * w + mirror(x as isize - PAD as isize, w as isize)] as f64;
            }
        }
        // The J-UNIWARD reference correlates rather than convolving
        let mut tmp = vec![0f64; pw * ph];
        let mut r = vec![0f64; pw]; // one row
        let rinv = BANDS.map(|band| {
            for x in 0..pw { corr_line_d(&pad[x..], &mut tmp[x..], ph, pw, band[0]); }
            let mut rinv = Vec::with_capacity(pw * ph);
            for y in 0..ph {
                corr_line_d(&tmp[y * pw..], &mut r, pw, 1, band[1]);
                rinv.extend(r.iter().map(|v| (1.0 / (v.abs() + SIGMA_JPEG)) as f32));
            }
            rinv
        });
        drop((pad, tmp, r));

        // What a change of 1 in each DCT mode does to each sub-band
        let basis = dct_basis();
        let mut impact = vec![[0f64; REACH * REACH]; 3 * 64];
        for k in 0..64 {
            let (u, v) = (k / 8, k % 8);
            let mut pattern = [0f64; 64];
            for x in 0..8 {
                for y in 0..8 { pattern[x * 8 + y] = basis[x][u] * basis[y][v]; }
            }
            for (b, band) in BANDS.iter().enumerate() {
                let mut cols = [0f64; REACH * 8];
                let mut out = [0f64; REACH * REACH];
                for y in 0..8 { full_line(&pattern[y..], &mut cols[y..], 8, 8, band[0]); }
                for x in 0..REACH { full_line(&cols[x * 8..], &mut out[x * REACH..], 8, 1, band[1]); }
                for (i, o) in out.iter().enumerate() { impact[b * 64 + k][i] = (o * quant[k] as f64).abs(); }
            }
        }
        JUniward { pw, rinv, impact }
    }

    /// The cost of changing coefficient k (natural order, 1-63) of block
    /// (bx, by) by 1
    pub fn cost(&self, bx: usize, by: usize, k: usize) -> f32 {
        let (r0, c0) = (by * 8 + PAD - 6, bx * 8 + PAD - 6);
        let mut rho = 0f64;
        for b in 0..3 {
            let imp = &self.impact[b * 64 + k];
            for rs in 0..REACH {
                let rinv = &self.rinv[b][(r0 + rs) * self.pw + c0..];
                for cs in 0..REACH { rho += imp[rs * REACH + cs] * rinv[cs] as f64; }
            }
        }
        if rho <= WET_JPEG as f64 { rho as f32 } else { WET_JPEG }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As tests/test_distortion.c's pattern()
    fn pattern(w: usize, h: usize, ch: usize) -> Vec<u8> {
        let mut px = vec![0u8; w * h * ch];
        for y in 0..h {
            for x in 0..w {
                for c in 0..ch {
                    px[(y * w + x) * ch + c] = (((y * 37 + x * 11 + (x * y) % 7) * 13) + c * 71) as u8;
                }
            }
        }
        px
    }

    fn close_to(got: f32, want: f32) -> bool { (got - want).abs() <= 1e-5 * want.abs() }

    // The same known answers as tests/test_distortion.c: from the C
    // implementation, which matched the authors' reference code

    #[test]
    fn wow_matches_c() {
        let want = [0.0141366525f32, 0.0145788305, 0.0143218692, 0.0129158907, 0.0106896516,
            0.014331637, 0.0144222546, 0.0116113629, 0.0166720171, 0.0135587277, 0.0129521862,
            0.0161323864, 0.0165558197];
        let costs = wow(&pattern(24, 20, 1), 24, 20, 1);
        for (i, w) in want.iter().enumerate() { assert!(close_to(costs[i * 37], *w), "sample {}: {} vs {w}", i * 37, costs[i * 37]); }
    }

    #[test]
    fn suniward_matches_c() {
        let want = [0.766949177f32, 0.539925933, 0.641394734, 0.507885456, 0.700752497,
            0.777545214, 1.01516366, 0.426031649, 0.770571947, 0.693113446, 0.76456368,
            0.588670015, 0.764136136];
        let costs = suniward(&pattern(24, 20, 1), 24, 20, 1);
        for (i, w) in want.iter().enumerate() { assert!(close_to(costs[i * 37], *w), "sample {}: {} vs {w}", i * 37, costs[i * 37]); }
    }

    const Q75: [u16; 64] = [8, 6, 5, 8, 12, 20, 26, 31, 6, 6, 7, 10, 13, 29, 30, 28, 7, 7, 8, 12,
        20, 29, 35, 28, 7, 9, 11, 15, 26, 44, 40, 31, 9, 11, 19, 28, 34, 55, 52, 39, 12, 18, 28, 32,
        41, 52, 57, 46, 25, 32, 39, 44, 52, 61, 60, 51, 36, 46, 48, 49, 56, 50, 52, 50];

    #[test]
    fn juniward_matches_c() {
        let cases = [(0, 0, 1, 5.34709358f32), (0, 0, 9, 7.0657196), (1, 0, 63, 90.6809921),
            (0, 1, 8, 6.65914679), (1, 1, 27, 29.6261711), (1, 1, 2, 3.98322415)];
        let px: Vec<f32> = pattern(16, 16, 1).iter().map(|&v| v as f32).collect();
        let j = JUniward::new(&px, 16, 16, &Q75);
        for (bx, by, k, want) in cases { assert!(close_to(j.cost(bx, by, k), want), "{bx} {by} {k}: {} vs {want}", j.cost(bx, by, k)); }
    }

    #[test]
    fn tiny_images_finite() {
        for (w, h) in [(1, 1), (2, 1), (1, 7), (3, 5), (15, 16), (17, 2)] {
            let px = pattern(w, h, 3);
            for c in wow(&px, w, h, 3).into_iter().chain(suniward(&px, w, h, 3)) {
                assert!(c > 0.0 && c <= WET_SPATIAL, "{w}x{h}: {c}");
            }
        }
    }

    #[test]
    fn flat_image_wow_wet() {
        let px = vec![77u8; 400];
        assert!(wow(&px, 20, 20, 1).iter().all(|&c| c == WET_SPATIAL));
        assert!(suniward(&px, 20, 20, 1).iter().all(|&c| c > 0.0 && c < WET_SPATIAL));
    }

    #[test]
    fn idct_dc_and_clamp() {
        let mut coef = [0i16; 64];
        let mut q = [1u16; 64];
        assert!(idct_block(&coef, &q).iter().all(|&v| v == 128.0));
        coef[0] = 80;
        q[0] = 2;
        assert!(idct_block(&coef, &q).iter().all(|&v| v == 148.0));
        coef[0] = -1023;
        q[0] = 16;
        assert!(idct_block(&coef, &q).iter().all(|&v| v == 0.0));
    }
}
