// SPDX-License-Identifier: AGPL-3.0-or-later
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
//!   payload  [nonce 24 | secretbox]: its 32-bit little-endian length in the
//!            first 32 samples in that order, then its bits as the STC
//!            syndrome of the samples after them (see payload_carriers)
//!   message  the secretbox's plaintext: [encoding 1 | body], the body raw
//!            DEFLATE (encoding 1) if that made the message shorter, else the
//!            message as is (0); see compress.rs
//!
//! Every pixel carries one bit per sample (R, G, B, or gray LSBs); a JPEG,
//! one per carrier coefficient. There is no header or version marker, which
//! would itself give the image away.

use crate::embed::{self, Carrier, EmbedPlan};
use crate::sodium::{self, Secret, PwhashStrength, MAC_BYTES, NONCE_BYTES, SALT_BYTES};
use crate::compress::{self, Unpack};
use crate::{prng, stc};
use zeroize::Zeroizing;

/// The salt region, in samples, when the image allows
const SALT_SAMPLES: u32 = 8192;
// The labels are part of the format; "v2" is history, not a version
const SALT_LABEL: &[u8] = b"ScatterSteg v2 salt positions";
const KDF_CONTEXT: &[u8; 8] = b"ScatStg2";
pub const BOX_OVERHEAD: usize = NONCE_BYTES + MAC_BYTES;

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

pub fn header_pixels(channels: u32) -> u32 {
    32u32.div_ceil(channels)
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
// decode so it can't drift between them: the 32-bit length goes straight into the
// first 32 samples, and the payload's bits are the STC syndrome of samples
// from 32 on.

/// Samples after the length header; 0 if the header doesn't fit
fn payload_samples(n: u32, ch: u32) -> usize {
    if n < header_pixels(ch) { 0 } else { n as usize * ch as usize - 32 }
}

/// How many samples from 32 on carry a len-byte payload's syndrome (and
/// 8 * len message bits); 0 if it doesn't fit
fn payload_carriers(n: u32, ch: u32, len: u32) -> (usize, usize) {
    let mlen = len as usize * 8;
    (stc::carriers(payload_samples(n, ch), mlen), mlen)
}

/// The payload (see payload_samples). None if the length doesn't fit, as for
/// a wrong passphrase.
fn read_payload(c: &Carrier, order: &[u32], n: u32) -> Option<Vec<u8>> {
    if n < header_pixels(c.channels()) { return None; }
    let len = embed::peek_len(c, order, n);
    let (used, mlen) = payload_carriers(n, c.channels(), len);
    if (len as usize) < BOX_OVERHEAD || used == 0 { return None; }

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

/// Records the changes for payload (see payload_samples) in plan: the STC
/// picks, among all sample bits with the right syndrome, the set cheapest to
/// reach under embed::costs.
fn embed_payload(c: &Carrier, order: &[u32], n: u32, payload: &[u8], plan: &mut EmbedPlan)
    -> Result<(), EmbedError> {
    let len = payload.len() as u32;
    let (used, mlen) = payload_carriers(n, c.channels(), len);
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
    let pt_len = boxed.len() - BOX_OVERHEAD;
    let mut pt = Secret::new(pt_len + 1).ok_or("allocation failed")?;
    let nonce: &[u8; NONCE_BYTES] = boxed[..NONCE_BYTES].try_into().unwrap();
    if !sodium::secretbox_open_easy(&mut pt[..pt_len], &boxed[NONCE_BYTES..], nonce, key) { return Ok(None); }
    Ok(Some(pt))
}

pub struct Decrypted {
    /// The message, followed by one spare byte
    pub plaintext: Secret,
    pub len: usize,
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
        Ok(msg) => Ok(Some(Decrypted { len: msg.len() - 1, plaintext: msg })),
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

/// The longest message that fits stored as is after the k salt pixels: one
/// payload bit per sample after the 32-bit header, less the box and the
/// encoding byte
fn max_message(count: u32, k: u32, ch: u32) -> usize {
    (payload_samples(count - k, ch) / 8).saturating_sub(BOX_OVERHEAD + 1)
}

/// The longest message the carrier holds stored as is (a compressible one can
/// be longer), which needs no passphrase: what `Prepared::max_message` gives.
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

    /// Compresses the (non-empty) message if that makes it shorter, encrypts
    /// it, and changes the cover to carry it. TooLong if it doesn't fit even
    /// compressed.
    pub fn embed(self, c: &mut Carrier, message: &[u8]) -> Result<(), EmbedError> {
        // payload = [nonce | secretbox([encoding | body])]
        let (packed, packed_len) = compress::pack(message).ok_or(EmbedError::Alloc)?;
        if packed_len > self.max_msg + 1 { return Err(EmbedError::TooLong); }
        let mut payload = vec![0u8; BOX_OVERHEAD + packed_len];
        let mut nonce = [0u8; NONCE_BYTES];
        sodium::random_bytes(&mut nonce);
        payload[..NONCE_BYTES].copy_from_slice(&nonce);
        sodium::secretbox_easy(&mut payload[NONCE_BYTES..], &packed[..packed_len], &nonce, self.keys.enc());
        drop(packed);

        // PNG: HILL costs (see embed::costs); JPEG keeps its own
        let hill = c.hill_costs();
        let c = &mut c.with_png_costs(&hill);

        // Record every change (payload and salt), then make them together so
        // they can be paired up to keep the histogram (see embed::apply)
        let mut plan = EmbedPlan::new();
        let embedded = embed_payload(c, &self.order, self.count - self.k, &payload, &mut plan);
        sodium::memzero(&mut payload);
        embedded?;
        write_salt(c, &self.salt_px, self.k, &self.salt, &mut plan).map_err(|_| EmbedError::Alloc)?;
        embed::apply(c, &mut plan);
        Ok(())
    }
}
