//! QR-bound proof for the device key a host pins during `thumbdesk pair`.
//!
//! The host puts a fresh random secret in the QR it prints. The phone reads
//! it optically and sends back, through the backend, an HMAC under that
//! secret over the claim it is making. The backend never sees the secret, so
//! it cannot produce a proof for a device id or key of its own choosing.
//!
//! MUST match `mobile/src/services/pairingProof.ts`; both sides assert the
//! same known-answer vector.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain-separation label, the first transcript field.
/// Shared with the app; keeps its pre-rename name like every signing tag.
pub const PAIR_PROOF_LABEL: &str = "pocketshell-pair-v1";
pub const PAIR_MODE_NEW_HOST: &str = "new_host";
pub const PAIR_MODE_DEVICE_ADD: &str = "device_add";

const PAIRING_SECRET_LEN: usize = 32;

/// The per-pairing secret shown in the QR (`ps`). Lives only in memory for
/// one `pair` command: never sent to the backend, logged, or written to
/// disk, hence no `Debug`/`Serialize`. Wiped on drop.
pub struct PairingSecret(Zeroizing<[u8; PAIRING_SECRET_LEN]>);

impl PairingSecret {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; PAIRING_SECRET_LEN]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; PAIRING_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// base64url, no padding: the value of the QR's `ps` field.
    pub fn to_qr_field(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_ref())
    }
}

/// What the proof binds. Every value is the exact string the host is about
/// to act on: the claim token and host key it printed in the QR, and the
/// device id and key it is about to pin from the backend's response.
pub struct PairingTranscript<'a> {
    /// `PAIR_MODE_NEW_HOST` or `PAIR_MODE_DEVICE_ADD` (QR carries `host_id`).
    pub mode: &'a str,
    pub claim_token: &'a str,
    pub mobile_device_id: &'a str,
    pub device_public_key: &'a str,
    pub host_public_key: &'a str,
}

impl PairingTranscript<'_> {
    /// Canonical encoding: the six fields in fixed order (label, mode,
    /// claim_token, mobile_device_id, device_public_key, host_public_key),
    /// each as a 4-byte big-endian byte length followed by its UTF-8 bytes.
    /// `mobile_device_id` is ASCII-lowercased first, since the backend
    /// relays UUIDs in lowercase whatever case the phone sent.
    fn encode(&self) -> Vec<u8> {
        let mobile_device_id = self.mobile_device_id.to_ascii_lowercase();
        let fields = [
            PAIR_PROOF_LABEL,
            self.mode,
            self.claim_token,
            &mobile_device_id,
            self.device_public_key,
            self.host_public_key,
        ];
        let mut out = Vec::new();
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }
}

fn transcript_mac(secret: &PairingSecret, transcript: &PairingTranscript<'_>) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.0.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(&transcript.encode());
    mac
}

/// `HMAC-SHA256(secret, transcript)` as base64url without padding.
pub fn compute_device_proof(secret: &PairingSecret, transcript: &PairingTranscript<'_>) -> String {
    URL_SAFE_NO_PAD.encode(transcript_mac(secret, transcript).finalize().into_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProofCheck {
    /// The proof matches: the device id and key came from whoever scanned
    /// the QR.
    Verified,
    /// No proof in the response: an older app that does not know `ps`, or a
    /// backend that dropped it. What that means for the pairing is the
    /// caller's policy.
    Absent,
    /// A proof was sent and does not match. Never pin.
    Mismatch,
}

/// Check the proof relayed by the backend against the values the host is
/// about to pin. The comparison is constant-time.
pub fn check_device_proof(
    secret: &PairingSecret,
    transcript: &PairingTranscript<'_>,
    device_proof: Option<&str>,
) -> DeviceProofCheck {
    let Some(device_proof) = device_proof else {
        return DeviceProofCheck::Absent;
    };
    let Ok(tag) = URL_SAFE_NO_PAD.decode(device_proof) else {
        return DeviceProofCheck::Mismatch;
    };
    match transcript_mac(secret, transcript).verify_slice(&tag) {
        Ok(()) => DeviceProofCheck::Verified,
        Err(_) => DeviceProofCheck::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared known-answer vector. The same inputs and expected output are
    // asserted in `mobile/src/services/__tests__/pairingProof.test.ts`.
    const KAT_CLAIM_TOKEN: &str = "kat-claim-token-0123456789abcdef";
    const KAT_MOBILE_DEVICE_ID: &str = "3f2b8c1e-5d4a-4f6b-9a7c-0e1d2c3b4a59";
    const KAT_DEVICE_PUBLIC_KEY: &str = "ZGV2aWNlLXB1YmxpYy1rZXktMzItYnl0ZXMtISEhISE=";
    const KAT_HOST_PUBLIC_KEY: &str = "aG9zdC1wdWJsaWMta2V5LTMyLWJ5dGVzLSEhISEhISE=";
    const KAT_QR_FIELD: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const KAT_PROOF_NEW_HOST: &str = "MicXH0bU0ABYNPq_lHTNbyLuqgylhLF7WsiNSuu5ob8";
    const KAT_PROOF_DEVICE_ADD: &str = "o2NFwP82sB9xfwfFrVWXntL8KA6VdeSgxprRyaRFMaI";

    fn kat_secret() -> PairingSecret {
        // Bytes 0x00..=0x1f.
        PairingSecret::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn kat_transcript(mode: &str) -> PairingTranscript<'_> {
        PairingTranscript {
            mode,
            claim_token: KAT_CLAIM_TOKEN,
            mobile_device_id: KAT_MOBILE_DEVICE_ID,
            device_public_key: KAT_DEVICE_PUBLIC_KEY,
            host_public_key: KAT_HOST_PUBLIC_KEY,
        }
    }

    #[test]
    fn known_answer_vector_matches_mobile() {
        let secret = kat_secret();
        assert_eq!(secret.to_qr_field(), KAT_QR_FIELD);
        assert_eq!(
            compute_device_proof(&secret, &kat_transcript(PAIR_MODE_NEW_HOST)),
            KAT_PROOF_NEW_HOST
        );
        assert_eq!(
            compute_device_proof(&secret, &kat_transcript(PAIR_MODE_DEVICE_ADD)),
            KAT_PROOF_DEVICE_ADD
        );
    }

    #[test]
    fn transcript_is_length_prefixed_in_fixed_order() {
        let encoded = PairingTranscript {
            mode: "m",
            claim_token: "ct",
            mobile_device_id: "ID",
            device_public_key: "",
            host_public_key: "hpk",
        }
        .encode();
        let mut expected = Vec::new();
        for field in [PAIR_PROOF_LABEL, "m", "ct", "id", "", "hpk"] {
            expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expected.extend_from_slice(field.as_bytes());
        }
        assert_eq!(encoded, expected);
    }

    #[test]
    fn valid_proof_is_verified() {
        let secret = kat_secret();
        assert_eq!(
            check_device_proof(
                &secret,
                &kat_transcript(PAIR_MODE_NEW_HOST),
                Some(KAT_PROOF_NEW_HOST)
            ),
            DeviceProofCheck::Verified
        );
        // The backend relays the id lowercased whatever the phone sent.
        let upper = KAT_MOBILE_DEVICE_ID.to_ascii_uppercase();
        let transcript = PairingTranscript {
            mobile_device_id: &upper,
            ..kat_transcript(PAIR_MODE_NEW_HOST)
        };
        assert_eq!(
            check_device_proof(&secret, &transcript, Some(KAT_PROOF_NEW_HOST)),
            DeviceProofCheck::Verified
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let other = PairingSecret::from_bytes([7u8; 32]);
        assert_eq!(
            check_device_proof(
                &other,
                &kat_transcript(PAIR_MODE_NEW_HOST),
                Some(KAT_PROOF_NEW_HOST)
            ),
            DeviceProofCheck::Mismatch
        );
    }

    #[test]
    fn substituted_values_are_rejected() {
        let secret = kat_secret();
        let base = || kat_transcript(PAIR_MODE_NEW_HOST);
        let altered = [
            PairingTranscript {
                device_public_key: "YXR0YWNrZXIta2V5LTMyLWJ5dGVzLSEhISEhISEhISE=",
                ..base()
            },
            PairingTranscript {
                mobile_device_id: "3f2b8c1e-5d4a-4f6b-9a7c-0e1d2c3b4a58",
                ..base()
            },
            PairingTranscript {
                claim_token: "another-claim-token",
                ..base()
            },
            PairingTranscript {
                host_public_key: "b3RoZXItaG9zdC1rZXktMzItYnl0ZXMtISEhISEhISE=",
                ..base()
            },
            PairingTranscript {
                mode: PAIR_MODE_DEVICE_ADD,
                ..base()
            },
        ];
        for transcript in &altered {
            assert_eq!(
                check_device_proof(&secret, transcript, Some(KAT_PROOF_NEW_HOST)),
                DeviceProofCheck::Mismatch
            );
        }
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let secret = kat_secret();
        let transcript = kat_transcript(PAIR_MODE_NEW_HOST);
        let truncated = &KAT_PROOF_NEW_HOST[..KAT_PROOF_NEW_HOST.len() - 4];
        for proof in ["", "not base64url!", truncated] {
            assert_eq!(
                check_device_proof(&secret, &transcript, Some(proof)),
                DeviceProofCheck::Mismatch,
                "{proof:?}"
            );
        }
    }

    #[test]
    fn absent_proof_is_reported_not_accepted() {
        assert_eq!(
            check_device_proof(&kat_secret(), &kat_transcript(PAIR_MODE_NEW_HOST), None),
            DeviceProofCheck::Absent
        );
    }

    #[test]
    fn generated_secrets_are_32_random_bytes() {
        let a = PairingSecret::generate().to_qr_field();
        let b = PairingSecret::generate().to_qr_field();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }
}
