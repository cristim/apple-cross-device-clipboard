//! Milestone 3 (reverse direction): build our own Handoff / Universal Clipboard
//! BLE advertisement so Apple devices see that *Linux* has a copy available.
//!
//! This module builds the advert BYTES (encrypting the 10-byte payload with the
//! same truncated-tag AES-GCM the receive path uses). Actually broadcasting them
//! is a documented stub: it needs a real key, correct IV-counter management, and
//! BlueZ LE advertising registration. See `broadcast_stub`.
//!
//! ⚠️ Unvalidated: the seal path shares the (unverified) GCM framing of the
//! receive path, and whether Apple accepts a third-party advert at all is
//! untested.

#![allow(dead_code)] // M2/M3 scaffolding: exercised by unit tests; wired into the runtime once macOS keys exist.

use crate::gcm;

/// Flag bits in the decrypted Handoff payload (mirror of `advert::HandoffFlags`).
pub const FLAG_CLIPBOARD_AVAILABLE: u8 = 0x08;

pub struct HandoffAdvertBuilder {
    /// BLE key (same `keyData` used to decrypt): 16, 24 or 32 bytes.
    key: Vec<u8>,
    /// Monotonic advertisement counter, used as the GCM IV.
    counter: u16,
}

impl HandoffAdvertBuilder {
    pub fn new(key: Vec<u8>) -> Self {
        HandoffAdvertBuilder { key, counter: 0 }
    }

    /// Build one advert's Apple manufacturer-data TLV: `0c len status iv tag ct`.
    /// `activity_hash` is the 7-byte truncated SHA-512 of the activity string;
    /// `flags` is the payload flag byte (set `FLAG_CLIPBOARD_AVAILABLE`).
    ///
    /// Fails only on a bad key length.
    pub fn build(&mut self, activity_hash: [u8; 7], flags: u8) -> Result<Vec<u8>, gcm::GcmError> {
        let status = 0x08u8; // "data copied" plaintext status (status A convention)
        let iv = self.counter.to_le_bytes();

        // 10-byte plaintext: status | activity_hash(7) | flags | unused
        let mut plaintext = Vec::with_capacity(10);
        plaintext.push(status);
        plaintext.extend_from_slice(&activity_hash);
        plaintext.push(flags);
        plaintext.push(0x00);

        let (ct, tag) = gcm::seal_truncated(&self.key, &iv, &[status], &plaintext, 1)?;

        let mut tlv = Vec::with_capacity(4 + ct.len());
        tlv.push(0x0c);
        tlv.push((1 + 2 + 1 + ct.len()) as u8); // status + iv + tag + ct
        tlv.push(status);
        tlv.extend_from_slice(&iv);
        tlv.extend_from_slice(&tag);
        tlv.extend_from_slice(&ct);

        self.counter = self.counter.wrapping_add(1);
        Ok(tlv)
    }

    /// The Apple company id (0x004c) our manufacturer data must be registered
    /// under when advertising via BlueZ.
    pub const APPLE_COMPANY_ID: u16 = 0x004c;
}

/// TODO(M3): actually broadcast. Requires bluer's `Advertisement` with
/// `manufacturer_data` = { 0x004c: build(...) }, registered on the adapter, and
/// re-issued on every new clipboard event with an incremented counter. Also
/// needs the exported BLE key. Left unimplemented until keys exist and the
/// receive path is validated, so we don't ship an untested transmitter.
pub fn broadcast_stub() {
    unimplemented!("M3 BLE broadcast — see module docs");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advert::{HandoffBle, HandoffFlags};

    #[test]
    fn build_parses_and_decrypts_back() {
        // 16-, 24- and 32-byte keys (macOS 26.1 exports 32-byte keys).
        for len in [16usize, 24, 32] {
            let key = vec![0x5Au8; len];
            let mut b = HandoffAdvertBuilder::new(key.clone());
            let hash = [1, 2, 3, 4, 5, 6, 7];
            let tlv = b.build(hash, FLAG_CLIPBOARD_AVAILABLE).expect("build");

            // Our own receive-path parser must accept it...
            let ble = HandoffBle::parse(&tlv).expect("parse");
            // ...and the truncated tag must verify, yielding the payload we put in.
            let plain = gcm::open_truncated(
                &key,
                &ble.counter_iv,
                &[ble.status],
                &ble.ciphertext,
                &ble.tag,
            )
            .expect("valid key")
            .expect("decrypt");
            assert_eq!(&plain[1..8], &hash, "key length {len}");
            assert!(HandoffFlags::from_byte(plain[8]).clipboard_available());
        }
    }

    #[test]
    fn build_rejects_unsupported_key_length() {
        let mut b = HandoffAdvertBuilder::new(vec![0u8; 20]);
        assert_eq!(b.build([0; 7], 0), Err(gcm::GcmError::InvalidKeyLength(20)));
    }

    #[test]
    fn counter_increments_across_adverts() {
        let mut b = HandoffAdvertBuilder::new(vec![0u8; 16]);
        let a1 = b.build([0; 7], 0).unwrap();
        let a2 = b.build([0; 7], 0).unwrap();
        // IV bytes (indices 3..5 of the TLV) must differ.
        assert_ne!(&a1[3..5], &a2[3..5]);
    }
}
