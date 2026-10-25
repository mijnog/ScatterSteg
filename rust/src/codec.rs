// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! The file format: how a message is keyed, laid out in a cover's carriers,
//! and found again.
//!
//! v4 (written by encode): as v3, except for where the salt goes.
//!   salt     16 random bytes, as the STC syndrome (see stc.rs) of the
//!            samples of a public salt region: the first salt_region_pixels
//!            pixels of the public permutation below. v3 wrote them straight
//!            into 128 samples at those public positions, about 64 changes
//!            at places anyone can look; spread over ~8192 samples, the salt
//!            takes ~18 changes, as sparse as the payload's.
//!
//! v3 (decode only):
//!   salt     16 random bytes, in the first 43 pixels (RGB; 128 for gray)
//!            of a public permutation (prng::permutation keyed with BLAKE2b
//!            of V2_SALT_LABEL), so it is spread over the image
//!   keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
//!            256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
//!            and 2 of master, context V2_KDF_CONTEXT
//!   order    prng::permutation(scatter key) with the salt pixels removed
//!   payload  [nonce 24 | secretbox]: its 32-bit little-endian length in the
//!            first 32 samples in that order, then its bits as the STC
//!            syndrome of the samples after them (see v3_carriers)
//!
//! v2 (decode only): salt, keys and order as v3; the length, then the
//!   payload's bits written straight into the samples in order.
//!
//! v1 (decode only): scatter key = keyed BLAKE2b of the passphrase alone,
//!   which let a wrong passphrase be rejected without Argon2id; payload =
//!   length, then [salt 16 | nonce 24 | secretbox] in prng::scatter order;
//!   encryption key = Argon2id(passphrase, salt, "interactive").
//!
//! Every pixel carries one bit per sample (R, G, B, or gray LSBs), written by
//! LSB matching (a JPEG: one per carrier coefficient). There is no version
//! marker, which would itself give the image away: decode tries v4, then v3
//! and v2 (which share a salt layout), then v1 (RGB PNG only).

use crate::embed::{self, Carrier, EmbedPlan};
use crate::sodium::{self, Secret, PwhashStrength, MAC_BYTES, NONCE_BYTES, SALT_BYTES};
use crate::{prng, stc};
use zeroize::Zeroizing;

/// The v4 salt region, in samples, when the image allows
const V4_SALT_SAMPLES: u32 = 8192;
const V2_SALT_LABEL: &[u8] = b"ScatterSteg v2 salt positions";
const V2_KDF_CONTEXT: &[u8; 8] = b"ScatStg2";
pub const V2_OVERHEAD: usize = NONCE_BYTES + MAC_BYTES;
const V1_OVERHEAD: usize = SALT_BYTES + V2_OVERHEAD;

/// Pixels holding the v2/v3 salt, and the 32-bit length header
fn salt_pixel_count(channels: u32) -> u32 {
    (SALT_BYTES as u32 * 8).div_ceil(channels)
}

/// Pixels in the v4 salt region: V4_SALT_SAMPLES samples' worth, but at most
/// 1/16 of the image, and never fewer than one sample per salt bit
pub fn salt_region_pixels(count: u32, channels: u32) -> u32 {
    let want = V4_SALT_SAMPLES.div_ceil(channels);
    let k = want.min(count / 16);
    k.max(salt_pixel_count(channels))
}

/// The v4 salt's carriers: all of the region's samples, up to STC's cap
fn salt_carriers(k: u32, channels: u32) -> usize {
    stc::carriers(k as usize * channels as usize, SALT_BYTES * 8)
}

pub fn header_pixels(channels: u32) -> u32 {
    32u32.div_ceil(channels)
}

/// The v4 salt, read from the region's sample bits
fn read_salt_v4(c: &Carrier, salt_px: &[u32], k: u32) -> [u8; SALT_BYTES] {
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
fn write_salt_v4(c: &Carrier, salt_px: &[u32], k: u32, salt: &[u8; SALT_BYTES], plan: &mut EmbedPlan)
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

/// v2: both keys from one Argon2id run, so every passphrase guess costs one
fn derive_keys_v2(passphrase: &[u8], salt: &[u8; SALT_BYTES]) -> Result<Keys, String> {
    crate::errln!("Deriving keys...");
    let oom = || "key derivation failed (out of memory)".to_string();
    let mut buf = Secret::new(64).ok_or_else(oom)?;
    let mut master = Secret::new(sodium::KDF_KEY_BYTES).ok_or_else(oom)?;
    sodium::pwhash(&mut master, passphrase, salt, PwhashStrength::Moderate).map_err(|_| oom())?;
    let master_key: &[u8; 32] = (&master[..]).try_into().unwrap();
    sodium::kdf_derive(&mut buf[..32], 1, V2_KDF_CONTEXT, master_key);
    sodium::kdf_derive(&mut buf[32..], 2, V2_KDF_CONTEXT, master_key);
    Ok(Keys { buf })
}

/// The first k pixels of the public permutation, where the salt goes: public,
/// so the decoder can find it before it has any key.
fn salt_pixels(count: u32, k: u32) -> Option<Vec<u32>> {
    let mut key = [0u8; 32];
    sodium::generichash(&mut key, V2_SALT_LABEL, &[]);
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

/// v1 (decode only). The scatter key comes from the passphrase alone, so
/// guesses can be checked against the length header without Argon2id.
fn derive_scatter_key_v1(passphrase: &[u8], key: &mut [u8; 32]) {
    sodium::generichash(key, passphrase, b"scatter");
}

fn derive_enc_key_v1(passphrase: &[u8], salt: &[u8; SALT_BYTES]) -> Result<Secret, ()> {
    let mut key = Secret::new(32).ok_or(())?;
    sodium::pwhash(&mut key, passphrase, salt, PwhashStrength::Interactive)?;
    Ok(key)
}

/// Outcome of trying to decode with one format. `Ok(None)` is "no match",
/// the way a wrong passphrase or format shows; `Err` carries a message.
type Decoded = Result<Option<Secret>, String>;

/// Read the length-prefixed payload in `order` (n pixels). None if the
/// length is out of range, as it is for a wrong passphrase or format.
fn read_payload(c: &Carrier, order: &[u32], n: u32, min_len: usize) -> Option<Vec<u8>> {
    if n < header_pixels(c.channels()) { return None; }
    let max_len = ((n as u64 * c.channels() as u64 - 32) / 8) as u32;
    let len = embed::peek_len(c, order, n);
    if (len as usize) < min_len || len > max_len { return None; }
    let mut payload = vec![0u8; len as usize];
    embed::decode(c, order, n, &mut payload);
    Some(payload)
}

// The v3 layout over n positions of ch samples, shared by encode and decode
// so it can't drift between them: the 32-bit length goes straight into the
// first 32 samples, and the payload's bits are the STC syndrome of samples
// from 32 on.

/// Samples after the length header; 0 if the header doesn't fit
fn v3_samples(n: u32, ch: u32) -> usize {
    if n < header_pixels(ch) { 0 } else { n as usize * ch as usize - 32 }
}

/// How many samples from 32 on carry a len-byte payload's syndrome (and
/// 8 * len message bits); 0 if it doesn't fit
fn v3_carriers(n: u32, ch: u32, len: u32) -> (usize, usize) {
    let mlen = len as usize * 8;
    (stc::carriers(v3_samples(n, ch), mlen), mlen)
}

/// v3 (see v3_samples). None if the length doesn't fit.
fn read_payload_v3(c: &Carrier, order: &[u32], n: u32) -> Option<Vec<u8>> {
    if n < header_pixels(c.channels()) { return None; }
    let len = embed::peek_len(c, order, n);
    let (used, mlen) = v3_carriers(n, c.channels(), len);
    if (len as usize) < V2_OVERHEAD || used == 0 { return None; }

    let mut y = vec![0u8; used];
    let mut m = vec![0u8; mlen];
    let mut payload = vec![0u8; len as usize];
    embed::get_bits(c, order, 32, &mut y);
    stc::extract(&y, mlen, used, &mut m);
    for i in 0..mlen { payload[i / 8] |= m[i] << (i % 8); }
    Some(payload)
}

pub enum EmbedError {
    TooLong,
    Alloc,
}

/// Records the v3 changes for payload (see v3_samples) in plan: the STC
/// picks, among all sample bits with the right syndrome, the set cheapest to
/// reach under embed::costs.
fn embed_payload_v3(c: &Carrier, order: &[u32], n: u32, payload: &[u8], plan: &mut EmbedPlan)
    -> Result<(), EmbedError> {
    let len = payload.len() as u32;
    let (used, mlen) = v3_carriers(n, c.channels(), len);
    if used == 0 { return Err(EmbedError::TooLong); }
    embed::write_raw(c, order, n, &len.to_le_bytes(), plan).map_err(|_| EmbedError::TooLong)?;

    let m: Vec<u8> = (0..mlen).map(|i| (payload[i / 8] >> (i % 8)) & 1).collect();
    let mut x = vec![0u8; used];
    let mut y = vec![0u8; used];
    let mut costs = vec![0f32; used];
    embed::get_bits(c, order, 32, &mut x);
    embed::costs(c, order, 32, &mut costs);
    stc::embed(&x, &costs, &m, mlen, used, &mut y).map_err(|_| EmbedError::Alloc)?;
    embed::set_bits(c, order, 32, &y, plan);
    Ok(())
}

/// Open [nonce | secretbox] with key. The plaintext has one spare byte after
/// it (for the caller's newline). None if it doesn't authenticate.
fn open_box(boxed: &[u8], key: &[u8; 32]) -> Result<Option<Secret>, String> {
    let pt_len = boxed.len() - V2_OVERHEAD;
    let mut pt = Secret::new(pt_len + 1).ok_or("allocation failed")?;
    let nonce: &[u8; NONCE_BYTES] = boxed[..NONCE_BYTES].try_into().unwrap();
    if !sodium::secretbox_open_easy(&mut pt[..pt_len], &boxed[NONCE_BYTES..], nonce, key) { return Ok(None); }
    Ok(Some(pt))
}

/// Decodes with one salt layout: v4's (an STC-coded salt region), or the one
/// v3 and v2 share (the salt written straight into 43 pixels). Each costs an
/// Argon2id run.
fn decode_keyed(c: &Carrier, v4: bool, passphrase: &[u8]) -> Decoded {
    let (count, ch) = (c.positions(), c.channels());
    let k = if v4 { salt_region_pixels(count, ch) } else { salt_pixel_count(ch) };
    if count < k + header_pixels(ch) { return Ok(None); }
    let salt_px = salt_pixels(count, k).ok_or("allocation failed")?;
    let mut salt = [0u8; SALT_BYTES];
    if v4 {
        salt = read_salt_v4(c, &salt_px, k);
    } else {
        embed::read_raw(c, &salt_px, k, &mut salt).map_err(|_| "allocation failed")?;
    }

    let keys = derive_keys_v2(passphrase, &salt)?;
    let order = payload_order(keys.scatter(), count, &salt_px).ok_or("allocation failed")?;

    // v4 and v3 lay the payload out alike; v2 shares v3's salt and keys but
    // writes the payload straight in.
    for v3 in [true, false] {
        if !v3 && v4 { break; } // v4: v3 layout only
        let payload = if v3 {
            read_payload_v3(c, &order, count - k)
        } else {
            read_payload(c, &order, count - k, V2_OVERHEAD)
        };
        if let Some(mut payload) = payload {
            let r = open_box(&payload, keys.enc());
            sodium::memzero(&mut payload);
            if !matches!(r, Ok(None)) { return r; }
        }
    }
    Ok(None)
}

fn decode_v1(c: &Carrier, passphrase: &[u8]) -> Decoded {
    if c.is_coef() || c.channels() != 3 { return Ok(None); } // v1 only ever wrote RGB PNG
    let count = c.positions();
    let mut scatter_key = [0u8; 32]; // filled in place: a returned array would be copied
    derive_scatter_key_v1(passphrase, &mut scatter_key);
    let order = prng::scatter(&scatter_key, count).map(Zeroizing::new);
    sodium::memzero(&mut scatter_key);
    let order = order.ok_or("allocation failed")?;

    let Some(mut payload) = read_payload(c, &order, count, V1_OVERHEAD) else { return Ok(None) };
    // v1 payload = [salt | nonce | secretbox]
    let salt: [u8; SALT_BYTES] = payload[..SALT_BYTES].try_into().unwrap();
    let r = match derive_enc_key_v1(passphrase, &salt) {
        Ok(key) => open_box(&payload[SALT_BYTES..], key[..].try_into().unwrap()),
        Err(()) => Err("key derivation failed (out of memory)".to_string()),
    };
    sodium::memzero(&mut payload);
    r
}

pub struct Decrypted {
    /// The message, followed by one spare byte
    pub plaintext: Secret,
    pub len: usize,
    pub v1: bool,
}

/// Tries v4, then v3 and v2, then v1. Ok(None) if nothing matches.
pub fn decode(c: &Carrier, passphrase: &[u8]) -> Result<Option<Decrypted>, String> {
    let found = |pt: Secret, v1| Decrypted { len: pt.len() - 1, plaintext: pt, v1 };
    if let Some(pt) = decode_keyed(c, true, passphrase)? { return Ok(Some(found(pt, false))); }
    if let Some(pt) = decode_keyed(c, false, passphrase)? { return Ok(Some(found(pt, false))); }
    Ok(decode_v1(c, passphrase)?.map(|pt| found(pt, true)))
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

/// Err(None) if the image is too small to hide a message; Err(Some(msg)) on
/// other failures
/// Whether the carrier can't hold the salt and length, whatever the message:
/// cheap, so encode checks it before slower work on the cover
pub fn too_small(c: &Carrier) -> bool {
    let (count, ch) = (c.positions(), c.channels());
    count < salt_region_pixels(count, ch) + header_pixels(ch)
}

pub fn prepare_encode(c: &Carrier, passphrase: &[u8]) -> Result<Prepared, Option<String>> {
    let (count, ch) = (c.positions(), c.channels());
    let k = salt_region_pixels(count, ch);
    if too_small(c) { return Err(None); }

    let mut salt = [0u8; SALT_BYTES];
    sodium::random_bytes(&mut salt);
    let keys = derive_keys_v2(passphrase, &salt)?;
    let salt_px = salt_pixels(count, k).ok_or_else(|| Some("allocation failed".to_string()))?;
    let order = payload_order(keys.scatter(), count, &salt_px)
        .ok_or_else(|| Some("allocation failed".to_string()))?;

    // The most the v3 layout holds: one payload bit per sample after the
    // 32-bit header
    let samples = v3_samples(count - k, ch);
    let max_msg = (samples / 8).saturating_sub(V2_OVERHEAD);
    Ok(Prepared { salt, keys, order, salt_px, k, count, max_msg })
}

impl Prepared {
    /// The longest message this cover holds
    pub fn max_message(&self) -> usize { self.max_msg }

    /// Encrypts the (non-empty) message and changes the cover to carry it
    pub fn embed(self, c: &mut Carrier, message: &[u8]) -> Result<(), EmbedError> {
        // payload = [nonce | secretbox(message)]
        let mut payload = vec![0u8; V2_OVERHEAD + message.len()];
        let mut nonce = [0u8; NONCE_BYTES];
        sodium::random_bytes(&mut nonce);
        payload[..NONCE_BYTES].copy_from_slice(&nonce);
        sodium::secretbox_easy(&mut payload[NONCE_BYTES..], message, &nonce, self.keys.enc());

        // PNG: HILL costs (see embed::costs); JPEG keeps its own
        let hill = c.hill_costs();
        let c = &mut c.with_png_costs(&hill);

        // Record every change (payload and salt), then make them together so
        // they can be paired up to keep the histogram (see embed::apply)
        let mut plan = EmbedPlan::new();
        let embedded = embed_payload_v3(c, &self.order, self.count - self.k, &payload, &mut plan);
        sodium::memzero(&mut payload);
        embedded?;
        write_salt_v4(c, &self.salt_px, self.k, &self.salt, &mut plan).map_err(|_| EmbedError::Alloc)?;
        embed::apply(c, &mut plan);
        Ok(())
    }
}
