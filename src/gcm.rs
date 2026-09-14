//! AES-GCM with the non-standard parameters Apple uses for Handoff / Universal
//! Clipboard BLE advertisements.
//!
//! Two things prevent us from using the `aes-gcm` crate directly:
//!   * the IV is only 2 bytes (the advertisement counter), not the usual 12, and
//!   * the authentication tag is truncated to a single byte.
//!
//! So we implement GCM from primitives per NIST SP 800-38D. The reference
//! behaviour we must match is CryptoSwift's `GCM(iv:authenticationTag:
//! additionalAuthenticatedData:mode:.detached)` as used by seemoo-lab's
//! handoff-ble-viewer (`BLEDecryptor.swift`).
//!
//! The key is `keyData` from the keychain item, used as-is. The reference passes
//! it straight to CryptoSwift's `AES`, which selects AES-128/192/256 from the
//! key length, so we accept 16, 24 and 32 bytes the same way. Apple's Platform
//! Security guide describes the Handoff key as 256-bit AES-GCM, and a real
//! macOS 26.1 export yielded 32-byte keys.
//!
//! IMPORTANT: this path is derived from the spec for a sub-96-bit IV; it still
//! needs validation against a real captured packet from your own devices (see
//! README, "Validation"). The unit tests below pin the GCM construction to an
//! independent implementation, not to Apple's framing.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use std::fmt;

const BLOCK: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcmError {
    /// The key was not 16, 24 or 32 bytes (AES-128/192/256).
    InvalidKeyLength(usize),
    /// A tag of 0 bytes or longer than one block was requested.
    InvalidTagLength(usize),
}

impl fmt::Display for GcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GcmError::InvalidKeyLength(n) => {
                write!(f, "AES key must be 16, 24 or 32 bytes, got {n}")
            }
            GcmError::InvalidTagLength(n) => {
                write!(f, "GCM tag must be 1..={BLOCK} bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for GcmError {}

/// Check that `key` is a length this module accepts.
pub fn validate_key(key: &[u8]) -> Result<(), GcmError> {
    AesCipher::new(key).map(drop)
}

enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesCipher {
    fn new(key: &[u8]) -> Result<Self, GcmError> {
        let invalid = || GcmError::InvalidKeyLength(key.len());
        match key.len() {
            16 => Aes128::new_from_slice(key).map(Self::Aes128),
            24 => Aes192::new_from_slice(key).map(Self::Aes192),
            32 => Aes256::new_from_slice(key).map(Self::Aes256),
            _ => return Err(invalid()),
        }
        .map_err(|_| invalid())
    }

    /// Encrypt one block (ECB core), used for GHASH key H and CTR blocks.
    fn encrypt_block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = GenericArray::clone_from_slice(input);
        match self {
            Self::Aes128(c) => c.encrypt_block(&mut b),
            Self::Aes192(c) => c.encrypt_block(&mut b),
            Self::Aes256(c) => c.encrypt_block(&mut b),
        }
        b.into()
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// GHASH over a sequence of already-zero-padded 16-byte blocks.
fn ghash(h: &[u8; BLOCK], blocks: &[[u8; BLOCK]]) -> [u8; BLOCK] {
    let mut mac = GHash::new(h.into());
    for blk in blocks {
        mac.update(&[(*blk).into()]);
    }
    mac.finalize().into()
}

/// Right-pad `data` with zeros to a whole number of 16-byte blocks.
fn pad_blocks(data: &[u8], out: &mut Vec<[u8; BLOCK]>) {
    for chunk in data.chunks(BLOCK) {
        let mut b = [0u8; BLOCK];
        b[..chunk.len()].copy_from_slice(chunk);
        out.push(b);
    }
}

/// Build J0 for an IV whose length is not 96 bits (SP 800-38D §7.1, step 2b):
///   J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
fn j0_short_iv(h: &[u8; BLOCK], iv: &[u8]) -> [u8; BLOCK] {
    let mut blocks: Vec<[u8; BLOCK]> = Vec::new();
    pad_blocks(iv, &mut blocks);
    let mut len_block = [0u8; BLOCK];
    let bit_len = (iv.len() as u64) * 8;
    len_block[8..].copy_from_slice(&bit_len.to_be_bytes());
    blocks.push(len_block);
    ghash(h, &blocks)
}

fn inc32(mut j: [u8; BLOCK]) -> [u8; BLOCK] {
    let mut ctr = u32::from_be_bytes([j[12], j[13], j[14], j[15]]);
    ctr = ctr.wrapping_add(1);
    j[12..].copy_from_slice(&ctr.to_be_bytes());
    j
}

/// Decrypt-and-verify with a truncated tag.
///
/// * `key` – `keyData` from the keychain item: 16, 24 or 32 bytes
///   (AES-128/192/256).
/// * `iv` – advertisement counter bytes (little-endian on the wire; we feed
///   them here exactly as they appear in the packet).
/// * `aad` – the plaintext status byte.
/// * `ciphertext` – the encrypted payload (10 bytes for a Handoff advert).
/// * `tag` – the truncated authentication tag from the packet (1 byte).
///
/// Returns `Ok(Some(plaintext))` if the truncated tag matches, `Ok(None)` if
/// it does not, and `Err` for a key or tag length this module cannot use.
pub fn open_truncated(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Option<Vec<u8>>, GcmError> {
    if tag.is_empty() || tag.len() > BLOCK {
        return Err(GcmError::InvalidTagLength(tag.len()));
    }
    let cipher = AesCipher::new(key)?;

    // H = E_K(0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK]);

    // J0 from the short IV.
    let j0 = j0_short_iv(&h, iv);

    // S = GHASH_H(A_padded || C_padded || [len(A)]_64 || [len(C)]_64)
    let mut blocks: Vec<[u8; BLOCK]> = Vec::new();
    pad_blocks(aad, &mut blocks);
    pad_blocks(ciphertext, &mut blocks);
    let mut len_block = [0u8; BLOCK];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    blocks.push(len_block);
    let s = ghash(&h, &blocks);

    // Full tag = E_K(J0) XOR S, then truncate to the length we were given.
    let mut full_tag = cipher.encrypt_block(&j0);
    xor_into(&mut full_tag, &s);

    if full_tag[..tag.len()] != *tag {
        return Ok(None);
    }

    // CTR decrypt from inc32(J0).
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = inc32(j0);
    for chunk in ciphertext.chunks(BLOCK) {
        let ks = cipher.encrypt_block(&counter);
        let mut block = chunk.to_vec();
        xor_into(&mut block, &ks[..chunk.len()]);
        plaintext.extend_from_slice(&block);
        counter = inc32(counter);
    }
    Ok(Some(plaintext))
}

/// Encrypt-and-tag with a truncated tag — the inverse of [`open_truncated`],
/// used by M3 to build our own Handoff advert. Returns `(ciphertext, tag)`
/// where `tag` is `tag_len` bytes (1 for a Handoff advert).
///
/// Like the open path, this is spec-derived and UNVALIDATED against real Apple
/// traffic; it is checked only against an independent GCM implementation.
pub fn seal_truncated(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), GcmError> {
    if tag_len == 0 || tag_len > BLOCK {
        return Err(GcmError::InvalidTagLength(tag_len));
    }
    let cipher = AesCipher::new(key)?;
    let h = cipher.encrypt_block(&[0u8; BLOCK]);
    let j0 = j0_short_iv(&h, iv);

    // CTR encrypt from inc32(J0).
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter = inc32(j0);
    for chunk in plaintext.chunks(BLOCK) {
        let ks = cipher.encrypt_block(&counter);
        let mut block = chunk.to_vec();
        xor_into(&mut block, &ks[..chunk.len()]);
        ciphertext.extend_from_slice(&block);
        counter = inc32(counter);
    }

    // S = GHASH_H(A_padded || C_padded || [len(A)]_64 || [len(C)]_64)
    let mut blocks: Vec<[u8; BLOCK]> = Vec::new();
    pad_blocks(aad, &mut blocks);
    pad_blocks(&ciphertext, &mut blocks);
    let mut len_block = [0u8; BLOCK];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    blocks.push(len_block);
    let s = ghash(&h, &blocks);

    let mut full_tag = cipher.encrypt_block(&j0);
    xor_into(&mut full_tag, &s);
    Ok((ciphertext, full_tag[..tag_len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: encrypt with the same primitive path, confirm the truncated
    /// tag verifies and the plaintext comes back. This proves the GHASH/CTR/J0
    /// machinery is internally consistent; it does NOT prove we match Apple's
    /// exact framing (that requires a captured packet).
    #[test]
    fn truncated_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0x00u8, 0x2a];
        let aad = [0x08u8];
        let plaintext = b"0123456789"; // 10 bytes, like a Handoff payload

        // Encrypt by hand using the same helpers.
        let cipher = AesCipher::new(&key).unwrap();
        let h = cipher.encrypt_block(&[0u8; BLOCK]);
        let j0 = j0_short_iv(&h, &iv);
        let mut ct = Vec::new();
        let mut counter = inc32(j0);
        for chunk in plaintext.chunks(BLOCK) {
            let ks = cipher.encrypt_block(&counter);
            let mut b = chunk.to_vec();
            xor_into(&mut b, &ks[..chunk.len()]);
            ct.extend_from_slice(&b);
            counter = inc32(counter);
        }
        let mut blocks: Vec<[u8; BLOCK]> = Vec::new();
        pad_blocks(&aad, &mut blocks);
        pad_blocks(&ct, &mut blocks);
        let mut len_block = [0u8; BLOCK];
        len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
        blocks.push(len_block);
        let s = ghash(&h, &blocks);
        let mut full_tag = cipher.encrypt_block(&j0);
        xor_into(&mut full_tag, &s);
        let tag = [full_tag[0]]; // 1-byte truncated tag

        let out = open_truncated(&key, &iv, &aad, &ct, &tag)
            .expect("valid key")
            .expect("tag should verify");
        assert_eq!(out, plaintext);

        // A wrong tag must be rejected.
        assert_eq!(
            open_truncated(&key, &iv, &aad, &ct, &[tag[0] ^ 0xff]),
            Ok(None)
        );
    }

    #[test]
    fn seal_then_open() {
        let key = [0x22u8; 16];
        let iv = [0x13u8, 0x37];
        let aad = [0x08u8];
        let plaintext = b"clipboard!"; // 10 bytes
        let (ct, tag) = seal_truncated(&key, &iv, &aad, plaintext, 1).expect("seal");
        assert_eq!(tag.len(), 1);
        let out = open_truncated(&key, &iv, &aad, &ct, &tag)
            .expect("valid key")
            .expect("open");
        assert_eq!(out, plaintext);
    }

    /// FIPS-197 Appendix C known-answer vectors, one per key length, so the
    /// variant selected for each length is pinned to an external reference.
    #[test]
    fn fips197_block_vectors() {
        let plaintext: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        for (len, expected) in [
            (16usize, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (32, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let key: Vec<u8> = (0..len as u8).collect();
            let out = AesCipher::new(&key).unwrap().encrypt_block(&plaintext);
            assert_eq!(hex::encode(out), expected, "key length {len}");
        }
    }

    /// Whole-GCM known answers for the 2-byte IV, 1-byte AAD and 10-byte
    /// payload shape, one per key length. Expected values come from an
    /// independent implementation (PyCryptodome `AES.MODE_GCM` with a 2-byte
    /// nonce), so J0, GHASH, CTR and the tag are pinned to an external
    /// reference and not only to a seal/open round-trip.
    #[test]
    fn gcm_short_iv_known_answers() {
        let iv = [0x13u8, 0x37];
        let aad = [0x08u8];
        let plaintext = b"clipboard!";
        for (len, ct_hex, tag_hex) in [
            (
                16usize,
                "6b65dc989f527c6a32ff",
                "b8040c394e628aff2c2af656daca2b02",
            ),
            (
                24,
                "7fececf8584770360bd2",
                "1d6571935dc6d955a0466365d007c02d",
            ),
            (
                32,
                "49422145a746e8324ae6",
                "b46ae9e3e05f9bc6d46684ad8b7c7fbe",
            ),
        ] {
            let key: Vec<u8> = (0..len as u8).collect();
            let (ct, tag) = seal_truncated(&key, &iv, &aad, plaintext, 16).expect("seal");
            assert_eq!(hex::encode(&ct), ct_hex, "ciphertext, key length {len}");
            assert_eq!(hex::encode(&tag), tag_hex, "tag, key length {len}");

            let tag = hex::decode(tag_hex).unwrap();
            let out = open_truncated(&key, &iv, &aad, &ct, &tag[..1])
                .expect("valid key")
                .expect("1-byte tag verifies");
            assert_eq!(out, plaintext, "key length {len}");
        }
    }

    /// AES-192 and AES-256 keys must round-trip exactly like AES-128.
    #[test]
    fn seal_then_open_aes192_and_aes256() {
        let iv = [0x13u8, 0x37];
        let aad = [0x08u8];
        let plaintext = b"clipboard!";
        for len in [24usize, 32] {
            let key: Vec<u8> = (0..len as u8).collect();
            let (ct, tag) = seal_truncated(&key, &iv, &aad, plaintext, 1).expect("seal");
            assert_eq!(tag.len(), 1);
            let out = open_truncated(&key, &iv, &aad, &ct, &tag)
                .expect("valid key")
                .expect("open");
            assert_eq!(out, plaintext, "key length {len}");
            assert_eq!(
                open_truncated(&key, &iv, &aad, &ct, &[tag[0] ^ 0xff]),
                Ok(None),
                "wrong tag must be rejected for key length {len}"
            );
        }
    }

    /// A 32-byte key is AES-256, not a 16-byte key with 16 ignored bytes.
    #[test]
    fn aes256_key_is_not_truncated_to_aes128() {
        let key: Vec<u8> = (0..32u8).collect();
        let iv = [0x00u8, 0x01];
        let aad = [0x08u8];
        let (ct, tag) = seal_truncated(&key, &iv, &aad, b"clipboard!", 16).expect("seal");
        assert_eq!(open_truncated(&key[..16], &iv, &aad, &ct, &tag), Ok(None));
    }

    #[test]
    fn invalid_key_length_is_an_error() {
        let iv = [0x00u8, 0x01];
        let aad = [0x08u8];
        for len in [0usize, 15, 20, 33] {
            let key = vec![0u8; len];
            assert_eq!(
                open_truncated(&key, &iv, &aad, &[0u8; 10], &[0]),
                Err(GcmError::InvalidKeyLength(len))
            );
            assert_eq!(
                seal_truncated(&key, &iv, &aad, &[0u8; 10], 1),
                Err(GcmError::InvalidKeyLength(len))
            );
            assert_eq!(validate_key(&key), Err(GcmError::InvalidKeyLength(len)));
        }
        for len in [16usize, 24, 32] {
            assert_eq!(validate_key(&vec![0u8; len]), Ok(()));
        }
    }

    #[test]
    fn invalid_tag_length_is_an_error() {
        let key = [0u8; 16];
        assert_eq!(
            open_truncated(&key, &[0, 1], &[8], &[0u8; 10], &[]),
            Err(GcmError::InvalidTagLength(0))
        );
        assert_eq!(
            seal_truncated(&key, &[0, 1], &[8], &[0u8; 10], 17),
            Err(GcmError::InvalidTagLength(17))
        );
    }
}
