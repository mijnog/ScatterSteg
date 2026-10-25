//! The file format (codec.rs and the C codec.c) on hostile carriers, past key
//! derivation, which fuzzing builds make cheap (BLAKE2b in place of
//! Argon2id). Both decode the fuzzer's carrier as decode would: neither may
//! fail, and they must agree. Then each encodes a message into its own copy,
//! and both must find it there with the right passphrase and nothing with a
//! wrong one: a message hidden by one version is found by the other.
#![no_main]
mod c_api;
use c_api::CCodecCover;
use libfuzzer_sys::fuzz_target;
use scattersteg::codec::{self, Decrypted};
use scattersteg::embed::Carrier;

const PASSPHRASE: &[u8] = b"correct horse battery";
const WRONG: &[u8] = b"wrong horse battery";

/// One copy of the carrier the input describes, with the same layout as
/// fuzz_codec.c: kind (1) | w (1) | h (1) | samples, then the message
#[derive(Clone)]
enum Samples {
    /// PNG: `channels` interleaved samples per pixel
    Pixels { pixels: Vec<u8>, w: u32, h: u32, channels: u32 },
    /// JPEG: carrier coefficients, |v| from 2 to 129 as jpeg_io gives
    Coefs { values: Vec<i16>, map: Vec<u32>, costs: Vec<f32> },
}

impl Samples {
    fn new(kind: u8, w: u32, h: u32, data: &[u8]) -> Samples {
        let at = |i: usize| if data.is_empty() { 0 } else { data[i % data.len()] };
        if kind < 2 {
            let channels = if kind == 1 { 3 } else { 1 };
            let pixels = (0..(w * h * channels) as usize).map(at).collect();
            Samples::Pixels { pixels, w, h, channels }
        } else {
            let n = (w * h) as usize;
            let bytes: Vec<u8> = (0..n).map(at).collect();
            let values = bytes.iter().map(|&b| ((b & 0x7F) as i16 + 2) * if b & 0x80 != 0 { -1 } else { 1 }).collect();
            let costs = bytes.iter().map(|&b| 1.0 + (b & 0x0F) as f32).collect();
            Samples::Coefs { values, map: (0..n as u32).collect(), costs }
        }
    }

    fn carrier(&mut self) -> Carrier<'_> {
        match self {
            Samples::Pixels { pixels, w, h, channels } => Carrier::png(pixels, *w * *h, *channels),
            Samples::Coefs { values, map, costs } => Carrier::jpeg(values, map, costs),
        }
    }

    fn c_cover(&mut self) -> CCodecCover<'_> {
        match self {
            Samples::Pixels { pixels, w, h, channels } => CCodecCover::pixels(pixels, *w, *h, *channels),
            Samples::Coefs { values, costs, .. } => CCodecCover::coefs(values, costs),
        }
    }

    fn decode_rust(&mut self, passphrase: &[u8]) -> Option<(Vec<u8>, bool)> {
        let d: Option<Decrypted> = codec::decode(&self.carrier(), passphrase).expect("Rust decode failed");
        d.map(|d| (d.plaintext[..d.len].to_vec(), d.v1))
    }

    fn decode_c(&mut self, passphrase: &[u8]) -> Option<(Vec<u8>, bool)> {
        self.c_cover().decode(passphrase).expect("C decode failed")
    }
}

fuzz_target!(init: scattersteg::sodium::init().expect("sodium_init failed"), |data: &[u8]| {
    if data.len() < 3 { return; }
    let (kind, w, h) = (data[0] % 3, data[1] as u32 % 64 + 1, data[2] as u32 % 64 + 1);
    let data = &data[3..];
    let cover = Samples::new(kind, w, h, data);

    // Hostile decode: the same verdict (almost always nothing found)
    let mut s = cover.clone();
    assert_eq!(s.decode_rust(PASSPHRASE), s.decode_c(PASSPHRASE), "C and Rust decode differently");

    // Rust encodes, both decode
    let mut s = cover.clone();
    let Ok(prepared) = codec::prepare_encode(&s.carrier(), PASSPHRASE) else { return };
    let max = prepared.max_message();
    assert_eq!(s.c_cover().max_message(PASSPHRASE), Some(max), "C and Rust differ on the message limit");
    let message = &data[..data.len().min(max)];
    if message.is_empty() { return; }
    if prepared.embed(&mut s.carrier(), message).is_err() { panic!("Rust embed failed within the limit"); }
    for decoded in [s.decode_rust(PASSPHRASE), s.decode_c(PASSPHRASE)] {
        assert_eq!(decoded, Some((message.to_vec(), false)), "a Rust-encoded message didn't decode");
    }
    assert_eq!(s.decode_rust(WRONG), None);
    assert_eq!(s.decode_c(WRONG), None);

    // C encodes, both decode
    let mut s = cover.clone();
    assert!(s.c_cover().embed(PASSPHRASE, message), "C embed failed within the limit");
    for decoded in [s.decode_c(PASSPHRASE), s.decode_rust(PASSPHRASE)] {
        assert_eq!(decoded, Some((message.to_vec(), false)), "a C-encoded message didn't decode");
    }
});
