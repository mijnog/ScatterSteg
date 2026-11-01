// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! The file format (FORMAT.md): how a message is keyed, laid out in a
//! cover's carriers, and found again.
//!
//!   salt     16 random bytes, as the STC syndrome (see stc.rs) of the
//!            samples of a public salt region: the first salt_region_pixels
//!            pixels of a public permutation (prng::permutation keyed with
//!            BLAKE2b of SALT_LABEL). Public, so the decoder can find it
//!            before it has a key; syndrome-coded, so its ~18 changes are as
//!            sparse as the payload's.
//!   keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
//!            256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
//!            and 2 of master, context KDF_CONTEXT
//!   order    prng::permutation(scatter key) with the salt pixels removed
//!   payload  secretbox, nonce all zeros: its 32-bit little-endian length,
//!            and the 32-bit count of its bits in the first ternary layer,
//!            as the STC syndrome of the first length_samples samples in
//!            that order; then its bits in two layers over the samples after
//!            them, the second LSBs then the LSBs (see embed_payload), all
//!            with the same costs
//!   message  the secretbox's plaintext: [encoding 1 | body], the body raw
//!            DEFLATE (encoding 1) of the record if that made it shorter,
//!            else the record as is (0); the record is [name length 1 | file
//!            name | message] (see compress.rs)
//!
//! Every sample (R, G, B or gray; a JPEG's carrier coefficients) changes by at
//! most 1. There is no header or version marker, which
//! would itself give the image away.

use crate::embed::{self, Carrier, EmbedPlan};
use crate::sodium::{self, Secret, PwhashStrength, MAC_BYTES, NONCE_BYTES, SALT_BYTES};
use crate::compress::{self, Unpack};
use crate::{prng, stc};
use zeroize::Zeroizing;

/// The salt region, in samples, when the image allows
const SALT_SAMPLES: u32 = 8192;
/// The length's, in samples, when the image allows: the salt's density
const LENGTH_SAMPLES: usize = 2048;
/// The length region's bits: the box's length, then how many of its bits the
/// first ternary layer holds, 32 bits each. As C's LENGTH_BITS.
const LENGTH_BITS: usize = 64;
// The labels are part of the format; "v2" is history, not a version
const SALT_LABEL: &[u8] = b"ScatterSteg v2 salt positions";
const KDF_CONTEXT: &[u8; 8] = b"ScatStg2";
pub const BOX_OVERHEAD: usize = MAC_BYTES;
/// The secretbox nonce: always zero. Each message's encryption key comes from
/// a fresh random salt (prepare_encode), so no key is used twice and the
/// nonce needn't vary; storing one would cost 24 bytes of embedding.
const ZERO_NONCE: [u8; NONCE_BYTES] = [0; NONCE_BYTES];
/// The suggested most to store (advice, not a limit; README, "Keep the
/// message small"). By the square root law, what an image hides at a given
/// risk grows with the square root of its size: everything stored, the fixed
/// overhead included, is at most this many bytes per square root of the
/// pixels (PNG) or non-zero AC coefficients (JPEG). Anchored on the lightest
/// payloads the benchmarks measured on BOSSbase (256x256): about 0.1 bits per
/// pixel and 0.08 bits per non-zero AC coefficient, overhead included.
pub const SUGGESTED_PNG_BYTES: u64 = 3;
pub const SUGGESTED_JPEG_BYTES: u64 = 1;
/// What every message stores besides its text and file name: salt 16,
/// length region 8 (the length, and layer A's share), MAC 16, encoding 1,
/// name length 1
pub const FIXED_BYTES: u64 = 42;
/// A cover this smooth gets no suggestion, as a trained detector finds almost
/// any message in it: a mean prediction residual (|4x - the four neighbours|
/// / 4 per sample) under 1.7 (PNG: the smoothest fifth of BOSSbase, caught
/// 84% of the time at 0.1 bits per pixel, 94% at 0.2), or under 14% of AC
/// coefficients non-zero (JPEG: the smoothest third, caught 93-98% of the
/// time at any payload measured).
pub const SMOOTH_PNG_RESIDUAL_X10: u64 = 17;
pub const SMOOTH_JPEG_PERCENT: u64 = 14;

/// The suggestion for a cover of `units` pixels (PNG) or non-zero AC
/// coefficients (JPEG), before the smoothness check: 0 if the fixed overhead
/// alone is over it
pub fn suggested(units: u64, jpeg: bool) -> u64 {
    let most = units.isqrt() * if jpeg { SUGGESTED_JPEG_BYTES } else { SUGGESTED_PNG_BYTES };
    most.saturating_sub(FIXED_BYTES)
}

/// Pixels in the salt region: SALT_SAMPLES samples' worth, but at most 1/16
/// of the image, and never fewer than one sample per salt bit
pub fn salt_region_pixels(count: u32, channels: u32) -> u32 {
    let want = SALT_SAMPLES.div_ceil(channels);
    let k = want.min(count / 16);
    k.max((SALT_BYTES as u32 * 8).div_ceil(channels))
}

/// The salt's carriers: all of the region's samples, up to STC's cap
fn salt_carriers(k: u32, channels: u32) -> usize {
    stc::carriers(k as usize * channels as usize, SALT_BYTES * 8)
}

/// The fewest positions a payload order needs: one sample per length bit
pub fn header_pixels(channels: u32) -> u32 {
    (LENGTH_BITS as u32).div_ceil(channels)
}

/// The salt, read from the region's sample bits
fn read_salt(c: &Carrier, salt_px: &[u32], k: u32) -> [u8; SALT_BYTES] {
    let used = salt_carriers(k, c.channels());
    let mut y = vec![0u8; used];
    let mut m = [0u8; SALT_BYTES * 8];
    embed::get_bits(c, salt_px, 0, &mut y);
    stc::extract(&y, SALT_BYTES * 8, used, &mut m);
    let mut salt = [0u8; SALT_BYTES];
    for i in 0..SALT_BYTES * 8 { salt[i / 8] |= m[i] << (i % 8); }
    salt
}

/// Records the changes that make the region carry the salt
fn write_salt(c: &Carrier, salt_px: &[u32], k: u32, salt: &[u8; SALT_BYTES], plan: &mut EmbedPlan)
    -> Result<(), ()> {
    let used = salt_carriers(k, c.channels());
    let mut m = [0u8; SALT_BYTES * 8];
    for i in 0..SALT_BYTES * 8 { m[i] = (salt[i / 8] >> (i % 8)) & 1; }
    let mut x = vec![0u8; used];
    let mut y = vec![0u8; used];
    let mut costs = vec![0f32; used];
    embed::get_bits(c, salt_px, 0, &mut x);
    embed::costs(c, salt_px, 0, &mut costs);
    stc::embed(&x, &costs, &m, SALT_BYTES * 8, used, &mut y)?;
    embed::set_bits(c, salt_px, 0, &y, plan);
    Ok(())
}

struct Keys {
    /// scatter key (32) then encryption key (32)
    buf: Secret,
}

impl Keys {
    fn scatter(&self) -> &[u8; 32] { self.buf[..32].try_into().unwrap() }
    fn enc(&self) -> &[u8; 32] { self.buf[32..].try_into().unwrap() }
}

/// Both keys from one Argon2id run, so every passphrase guess costs one
fn derive_keys(passphrase: &[u8], salt: &[u8; SALT_BYTES]) -> Result<Keys, String> {
    let oom = || "key derivation failed (out of memory)".to_string();
    let mut buf = Secret::new(64).ok_or_else(oom)?;
    let mut master = Secret::new(sodium::KDF_KEY_BYTES).ok_or_else(oom)?;
    sodium::pwhash(&mut master, passphrase, salt, PwhashStrength::Moderate).map_err(|_| oom())?;
    let master_key: &[u8; 32] = (&master[..]).try_into().unwrap();
    sodium::kdf_derive(&mut buf[..32], 1, KDF_CONTEXT, master_key);
    sodium::kdf_derive(&mut buf[32..], 2, KDF_CONTEXT, master_key);
    Ok(Keys { buf })
}

/// The first k pixels of the public permutation, where the salt goes: public,
/// so the decoder can find it before it has any key.
fn salt_pixels(count: u32, k: u32) -> Option<Vec<u32>> {
    let mut key = [0u8; 32];
    sodium::generichash(&mut key, SALT_LABEL, &[]);
    prng::sample(&key, count, k)
}

/// The message order: the secret permutation with the k salt pixels taken
/// out, count - k entries. It says where the message is, so it is wiped
/// when dropped.
fn payload_order(scatter_key: &[u8; 32], count: u32, salt_px: &[u32]) -> Option<Zeroizing<Vec<u32>>> {
    let mut sorted = salt_px.to_vec();
    sorted.sort_unstable();
    let mut order = Zeroizing::new(prng::permutation(scatter_key, count)?);
    order.retain(|p| sorted.binary_search(p).is_err());
    Some(order)
}

// The payload's layout over n positions of ch samples, shared by encode and
// decode so it can't drift between them: the length region is the STC
// syndrome of the first length_samples samples, and the payload's bits the
// STC syndrome of the samples after them. Writing the length straight into 32
// samples' bits would change about 16 of them wherever they fall, whatever
// their cost: in a JPEG mostly zeros in flat blocks, which an off-the-shelf
// detector (Aletheia's ALASKA2 J-MiPOD model) picked up on its own, in every
// file. As C's codec.c.

/// Samples carrying the length: LENGTH_SAMPLES, at most 1/16 of the n
/// positions' samples, never fewer than one per length bit
fn length_samples(n: u32, ch: u32) -> usize {
    (n as usize * ch as usize / 16).clamp(LENGTH_BITS, LENGTH_SAMPLES)
}

/// Samples after the length's; 0 if the length doesn't fit
fn payload_samples(n: u32, ch: u32) -> usize {
    (n as usize * ch as usize).saturating_sub(length_samples(n, ch))
}

/// The length and the first layer's bit count (split), from the first
/// length_samples samples
fn read_length(c: &Carrier, order: &[u32], n: u32) -> (u32, u32) {
    let used = stc::carriers(length_samples(n, c.channels()), LENGTH_BITS);
    let mut y = vec![0u8; used];
    let mut m = [0u8; LENGTH_BITS];
    embed::get_bits(c, order, 0, &mut y);
    stc::extract(&y, LENGTH_BITS, used, &mut m);
    let word = |from: usize| (0..32).fold(0u32, |w, i| w | (m[from + i] as u32) << i);
    (word(0), word(32))
}

/// Records the changes that make the first length_samples samples carry len
/// and split
fn write_length(c: &Carrier, order: &[u32], n: u32, len: u32, split: u32, plan: &mut EmbedPlan)
    -> Result<(), ()> {
    let used = stc::carriers(length_samples(n, c.channels()), LENGTH_BITS);
    let m: [u8; LENGTH_BITS] = std::array::from_fn(|i| {
        let w = if i < 32 { len } else { split };
        ((w >> (i % 32)) & 1) as u8
    });
    let mut x = vec![0u8; used];
    let mut y = vec![0u8; used];
    let mut costs = vec![0f32; used];
    embed::get_bits(c, order, 0, &mut x);
    embed::costs(c, order, 0, &mut costs);
    stc::embed(&x, &costs, &m, LENGTH_BITS, used, &mut y)?;
    embed::set_bits(c, order, 0, &y, plan);
    Ok(())
}

// Ternary embedding by two binary STC layers (Filler, Judas and Fridrich
// 2011, the multi-layered construction). A +-1 change flips a value's LSB
// either way, and its second bit (floor(v / 2) mod 2) in exactly one
// direction: +1 from an odd value, -1 from an even one. So layer A carries mA
// bits as the syndrome of the second bits, and layer B the rest as the
// syndrome of the LSBs, where a sample whose second bit flipped must flip its
// LSB too, and any other can still change the other way, flipping its LSB
// alone. Both run over the same samples; layer A first, so every sample can
// carry it (the other order would leave layer B only the few samples layer A
// changed).
//
// With symmetric costs rho, the changes that minimize distortion for m bits
// change each sample by +1 and by -1 with probability q = e / (1 + 2e) each,
// e = exp(-lambda rho), lambda set so the ternary entropies add up to m.
// Layer A then flips a second bit with probability q (cost
// ln(1 + exp(lambda rho)), mA = sum of h(q)), layer B an LSB alone with
// q / (1 - q) (cost lambda rho). As C's codec.c: the split needn't match C's
// to the bit, as it is stored, but the arithmetic is the same.

/// floor(v / 2) mod 2
fn second_bit(v: i32) -> u8 { (v.div_euclid(2) & 1) as u8 }

fn h2(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 { 0.0 } else { -p * p.log2() - (1.0 - p) * (1.0 - p).log2() }
}

/// The ternary entropy sum (bits) at lambda, and the first layer's share
fn ternary_bits(rho: &[f32], lambda: f64) -> (f64, f64) {
    let (mut total, mut a) = (0.0, 0.0);
    for &r in rho {
        let e = (-lambda * r as f64).exp();
        let q = e / (1.0 + 2.0 * e);
        if q <= 0.0 { continue; }
        total += -2.0 * q * q.log2() - (1.0 - 2.0 * q) * (1.0 - 2.0 * q).log2();
        a += h2(q);
    }
    (total, a)
}

/// lambda with ternary_bits = m, by bisection, and the first layer's share
fn ternary_split(rho: &[f32], m: usize) -> (usize, f64) {
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    while ternary_bits(rho, hi).0 > m as f64 && hi < 1e30 { hi *= 2.0; }
    for _ in 0..60 {
        let mid = (lo + hi) / 2.0;
        if ternary_bits(rho, mid).0 > m as f64 { lo = mid; } else { hi = mid; }
    }
    let a = ternary_bits(rho, hi).1;
    let mut share = a / m as f64; // about a half at low payloads
    if share.is_nan() || share < 0.0 { share = 0.5; }
    if share > 1.0 { share = 1.0; }
    ((share * m as f64 + 0.5) as usize, hi)
}

/// Samples the layers run over, from the n_avail after the length's: as many
/// as a layer of half the message can use (STC_MAX_W per bit)
fn ternary_samples(n_avail: usize, mlen: usize) -> usize {
    stc::carriers(n_avail, mlen.div_ceil(2))
}

/// The payload, from both layers. None if the length or split doesn't fit,
/// as for a wrong passphrase.
fn read_payload(c: &Carrier, order: &[u32], n: u32) -> Option<Vec<u8>> {
    let ch = c.channels();
    if n < header_pixels(ch) { return None; }
    let (len, split) = read_length(c, order, n);
    let (mlen, avail) = (len as usize * 8, payload_samples(n, ch));
    let ma = split as usize;
    if (len as usize) < BOX_OVERHEAD || mlen > avail || ma > mlen { return None; }
    let u = ternary_samples(avail, mlen);
    let mb = mlen - ma;
    let na = if ma > 0 { stc::carriers(u, ma) } else { 0 };
    let nb = if mb > 0 { stc::carriers(u, mb) } else { 0 };
    if u == 0 || (ma > 0 && na == 0) || (mb > 0 && nb == 0) { return None; }

    let mut v = vec![0i32; u];
    embed::get_values(c, order, length_samples(n, ch), &mut v);
    let mut m = vec![0u8; mlen];
    if ma > 0 {
        let y: Vec<u8> = v[..na].iter().map(|&x| second_bit(x)).collect();
        stc::extract(&y, ma, na, &mut m[..ma]);
    }
    if mb > 0 {
        let y: Vec<u8> = v[..nb].iter().map(|&x| (x & 1) as u8).collect();
        stc::extract(&y, mb, nb, &mut m[ma..]);
    }
    let mut payload = vec![0u8; len as usize];
    for i in 0..mlen { payload[i / 8] |= m[i] << (i % 8); }
    Some(payload)
}

/// How a message was stored
pub struct Embedded {
    /// Bytes stored: the record, compressed or not
    pub hidden: usize,
    pub compressed: bool,
}

pub enum EmbedError {
    TooLong,
    Alloc,
}

/// A large finite cost (as jpeg_io's wet carriers): the trellis avoids it
/// unless it has no other way, and embed_layers checks it didn't
const TERNARY_WET: f32 = 1e13;

/// Both layers, with ma of the mlen bits in layer A: the changes into delta.
/// Ok(true), Ok(false) if they can't be made by +-1 (the trellis had to pay a
/// wet cost), Err if the trellis failed. The costs are finite (wet ones too),
/// so that is no reason to retry. As C's embed_layers.
#[allow(clippy::too_many_arguments)]
fn embed_layers(v: &[i32], rho: &[f32], (lo, hi): (i32, i32), lambda: f64, m: &[u8], ma: usize,
                delta: &mut [i8]) -> Result<bool, ()> {
    let (u, mlen) = (v.len(), m.len());
    let mb = mlen - ma;
    let na = if ma > 0 { stc::carriers(u, ma) } else { 0 };
    let nb = if mb > 0 { stc::carriers(u, mb) } else { 0 };
    if (ma > 0 && na == 0) || (mb > 0 && nb == 0) { return Ok(false); }
    delta.fill(0);
    let mut x = vec![0u8; u];
    let mut cost = vec![0f32; u];
    let mut ya = vec![0u8; u];
    let mut yb = vec![0u8; u];

    // Layer A: second bits; flipping one takes +1 from odd, -1 from even
    for i in 0..na {
        let t = v[i] + if v[i] & 1 != 0 { 1 } else { -1 };
        let lr = lambda * rho[i] as f64;
        let k = if lr > 30.0 { lr } else { lr.exp().ln_1p() }; // ln(1 + e^(lambda rho))
        x[i] = second_bit(v[i]);
        cost[i] = if t < lo || t > hi || k > TERNARY_WET as f64 { TERNARY_WET } else { k as f32 };
    }
    if ma > 0 { stc::embed(&x[..na], &cost[..na], &m[..ma], ma, na, &mut ya[..na])?; }
    for i in 0..na { ya[i] = (ya[i] != x[i]) as u8; } // now: flipped

    // Layer B: LSBs. A sample layer A flipped must flip its LSB too (its
    // starting bit given as the flipped one, kept at a wet cost); any other
    // can flip it alone, the way that keeps its second bit (from an odd value
    // -1, from an even +1), or either way past layer A.
    for i in 0..nb {
        let lsb = (v[i] & 1) as u8;
        if i < na && ya[i] != 0 {
            x[i] = 1 - lsb;
            cost[i] = TERNARY_WET;
        } else {
            let t = v[i] + if lsb != 0 { -1 } else { 1 };
            x[i] = lsb;
            cost[i] = if i < na && (t < lo || t > hi) { TERNARY_WET } else { rho[i] };
        }
    }
    if mb > 0 { stc::embed(&x[..nb], &cost[..nb], &m[ma..], mb, nb, &mut yb[..nb])?; }

    // The changes; a wet cost the trellis had to pay means no +-1 change
    // gives both layers' bits: no change by 2, the caller tries again
    for i in 0..u {
        let a = i < na && ya[i] != 0;
        let b = i < nb && yb[i] != (v[i] & 1) as u8;
        if a && i < nb && !b { return Ok(false); }
        delta[i] = if a {
            if v[i] & 1 != 0 { 1 } else { -1 }
        } else if b && i < na {
            if v[i] & 1 != 0 { -1 } else { 1 }
        } else if b {
            let mut coin = [0u8; 1];
            sodium::random_bytes(&mut coin);
            if v[i] == lo { 1 } else if v[i] == hi { -1 } else if coin[0] & 1 != 0 { 1 } else { -1 }
        } else { 0 };
        let t = v[i] + delta[i] as i32;
        if t < lo || t > hi { return Ok(false); }
    }
    Ok(true)
}

/// Makes the payload's changes at once, and records the length's in plan.
/// Where layer A can't carry its share (a cover of mostly 0s or 255s, whose
/// second bit no +-1 change flips), it carries less, halving down to nothing:
/// then layer B alone is plain +-1 embedding, which any cover allows. The
/// split is stored with the length, so decoding needs no change. As C's
/// embed_payload.
fn embed_payload(c: &mut Carrier, order: &[u32], n: u32, payload: &[u8], plan: &mut EmbedPlan)
    -> Result<(), EmbedError> {
    let ch = c.channels();
    let len = payload.len() as u32;
    let (mlen, avail) = (payload.len() * 8, payload_samples(n, ch));
    if mlen == 0 || mlen > avail { return Err(EmbedError::TooLong); }
    let (u, start) = (ternary_samples(avail, mlen), length_samples(n, ch));
    if u == 0 { return Err(EmbedError::TooLong); }

    let m: Vec<u8> = (0..mlen).map(|i| (payload[i / 8] >> (i % 8)) & 1).collect();
    let mut v = vec![0i32; u];
    let mut rho = vec![0f32; u];
    embed::get_values(c, order, start, &mut v);
    embed::costs(c, order, start, &mut rho);
    let range = embed::value_range(c);

    let (mut ma, lambda) = ternary_split(&rho, mlen);
    let mut delta = vec![0i8; u];
    while !embed_layers(&v, &rho, range, lambda, &m, ma, &mut delta).map_err(|_| EmbedError::Alloc)? {
        if ma == 0 { return Err(EmbedError::TooLong); } // not even +-1 alone: too full
        ma /= 2;
    }
    write_length(c, order, n, len, ma as u32, plan).map_err(|_| EmbedError::Alloc)?;
    embed::add(c, order, start, &delta);
    Ok(())
}

/// Open the secretbox with key (and ZERO_NONCE). The plaintext has one spare byte after
/// it (for the caller's newline). None if it doesn't authenticate.
fn open_box(boxed: &[u8], key: &[u8; 32]) -> Result<Option<Secret>, String> {
    let pt_len = boxed.len() - BOX_OVERHEAD;
    let mut pt = Secret::new(pt_len + 1).ok_or("allocation failed")?;
    if !sodium::secretbox_open_easy(&mut pt[..pt_len], boxed, &ZERO_NONCE, key) { return Ok(None); }
    Ok(Some(pt))
}

pub struct Decrypted {
    /// The message
    pub plaintext: Secret,
    /// The file name stored with it, empty for none (see compress::name_ok)
    pub name: Secret,
}

/// Ok(None) for a wrong passphrase or no message; Err carries a message.
/// Costs one Argon2id run.
pub fn decode(c: &Carrier, passphrase: &[u8]) -> Result<Option<Decrypted>, String> {
    let (count, ch) = (c.positions(), c.channels());
    let k = salt_region_pixels(count, ch);
    if count < k + header_pixels(ch) { return Ok(None); }
    let salt_px = salt_pixels(count, k).ok_or("allocation failed")?;
    let salt = read_salt(c, &salt_px, k);
    let keys = derive_keys(passphrase, &salt)?;
    let order = payload_order(keys.scatter(), count, &salt_px).ok_or("allocation failed")?;
    let Some(mut payload) = read_payload(c, &order, count - k) else { return Ok(None) };
    let opened = open_box(&payload, keys.enc());
    sodium::memzero(&mut payload);
    let Some(pt) = opened? else { return Ok(None) };
    match compress::unpack(&pt[..pt.len() - 1]) {
        Ok((plaintext, name)) => Ok(Some(Decrypted { plaintext, name })),
        Err(Unpack::Alloc) => Err("allocation failed".into()),
        Err(Unpack::Malformed) => Err("the message is malformed; it authenticated, so whoever made the \
                                       image knew the passphrase".into()),
    }
}

/// Everything encode needs once the passphrase is keyed, before the message
/// is read, so the message limit is known
pub struct Prepared {
    salt: [u8; SALT_BYTES],
    keys: Keys,
    order: Zeroizing<Vec<u32>>,
    salt_px: Vec<u32>,
    k: u32,
    count: u32,
    max_msg: usize,
}

/// Whether the carrier can't hold the salt and length, whatever the message:
/// cheap, so encode checks it before slower work on the cover
pub fn too_small(c: &Carrier) -> bool {
    let (count, ch) = (c.positions(), c.channels());
    count < salt_region_pixels(count, ch) + header_pixels(ch)
}

/// The longest message that fits stored as is, with no file name, after the
/// k salt pixels: one payload bit per sample after the length's, less
/// the box, the encoding byte and the name length
fn max_message(count: u32, k: u32, ch: u32) -> usize {
    (payload_samples(count - k, ch) / 8).saturating_sub(BOX_OVERHEAD + 2)
}

/// The longest message the carrier holds stored as is, with no file name (a
/// compressible one can be longer, a name takes its length), which needs no
/// passphrase: what `Prepared::max_message` gives.
/// 0 if `too_small`.
pub fn capacity(c: &Carrier) -> usize {
    if too_small(c) { return 0; }
    let (count, ch) = (c.positions(), c.channels());
    max_message(count, salt_region_pixels(count, ch), ch)
}

/// Err(None) if the image is too small to hide a message; Err(Some(msg)) on
/// other failures
pub fn prepare_encode(c: &Carrier, passphrase: &[u8]) -> Result<Prepared, Option<String>> {
    let (count, ch) = (c.positions(), c.channels());
    let k = salt_region_pixels(count, ch);
    if too_small(c) { return Err(None); }

    let mut salt = [0u8; SALT_BYTES];
    sodium::random_bytes(&mut salt);
    let keys = derive_keys(passphrase, &salt)?;
    let salt_px = salt_pixels(count, k).ok_or_else(|| Some("allocation failed".to_string()))?;
    let order = payload_order(keys.scatter(), count, &salt_px)
        .ok_or_else(|| Some("allocation failed".to_string()))?;

    let max_msg = max_message(count, k, ch);
    Ok(Prepared { salt, keys, order, salt_px, k, count, max_msg })
}

impl Prepared {
    /// The longest message this cover holds stored as is (a compressible
    /// one can be longer)
    pub fn max_message(&self) -> usize { self.max_msg }

    /// Stores the (non-empty) message with its file name (empty for none; see
    /// compress::name_ok), compressed at `level` 1-9 if that makes it
    /// shorter (0: never), encrypts it, and changes the cover to carry it.
    /// TooLong if it doesn't fit even compressed.
    pub fn embed(self, c: &mut Carrier, name: &[u8], message: &[u8], level: u32) -> Result<Embedded, EmbedError> {
        // payload = secretbox([encoding | body]), nonce ZERO_NONCE
        let (packed, packed_len) = compress::pack(name, message, level).ok_or(EmbedError::Alloc)?;
        let stored = Embedded { hidden: packed_len - 1, compressed: packed[0] != 0 };
        if packed_len > self.max_msg + 2 { return Err(EmbedError::TooLong); }
        let mut payload = vec![0u8; BOX_OVERHEAD + packed_len];
        sodium::secretbox_easy(&mut payload, &packed[..packed_len], &ZERO_NONCE, self.keys.enc());
        drop(packed);

        // PNG: HILL costs (see embed::costs), or the build's other model;
        // JPEG keeps its own
        let hill = c.png_costs();
        let c = &mut c.with_png_costs(&hill);

        // Record every change (payload and salt), then make them together so
        // they can be paired up to keep the histogram (see embed::apply)
        let mut plan = EmbedPlan::new();
        let embedded = embed_payload(c, &self.order, self.count - self.k, &payload, &mut plan);
        sodium::memzero(&mut payload);
        embedded?;
        write_salt(c, &self.salt_px, self.k, &self.salt, &mut plan).map_err(|_| EmbedError::Alloc)?;
        embed::apply(c, &mut plan);
        Ok(stored)
    }
}
