use anyhow::{anyhow, Result};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub(crate) const PROTOCOL_INFO_PREFIX: &[u8] = b"pocketshell-files-v1";

/// Shared signing-context prefix for signed SDP envelopes. MUST match the
/// mobile-side constant in `mobile/src/services/sdpSignature.ts`.
pub const SDP_SIGNING_PREFIX: &str = "pocketshell-sdp-v1";
/// Shared signing-context prefix for X25519 key exchange transcripts. MUST
/// match `X25519_SIGNING_PREFIX` in `mobile/src/services/signalingService.ts`.
pub const X25519_SIGNING_PREFIX: &str = "pocketshell-x25519-v1";
/// Shared signing-context prefix for Strategy A pair-attestations. MUST match
/// the constant in `mobile/src/services/pairAttestation.ts`.
pub const PAIR_ATTEST_SIGNING_PREFIX: &str = "pocketshell-pair-attest-v1";
/// Shared signing-context prefix for mobile-signed host-to-host transfer
/// attestations. MUST match the constant in `mobile/src/services/fileService.ts`.
pub const HOST_TRANSFER_SIGNING_PREFIX: &str = "pocketshell-host-transfer-v1";
/// Domain separator for the host-capability signature in an
/// `x25519_key_response`. MUST match `HOST_CAPS_SIGNING_PREFIX` in
/// `mobile/src/services/hostAgentCaps.ts`.
pub const HOST_CAPS_SIGNING_PREFIX: &str = "pocketshell-host-caps-v1";

const HOST_TRANSFER_MAX_LIFETIME_SECS: i64 = 5 * 60;

/// Direction flag for nonce construction — prevents nonce collision between sides.
const DIRECTION_HOST_TO_MOBILE: u32 = 0x00000001;
const DIRECTION_MOBILE_TO_HOST: u32 = 0x00000000;

/// Ephemeral X25519 keypair for a single session.
pub struct EphemeralKeypair {
    secret: Option<EphemeralSecret>,
    pub public_key: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public_key,
        }
    }

    /// Consume the private key to compute the shared secret.
    /// After this call, the ephemeral private key no longer exists.
    pub fn diffie_hellman(mut self, their_public: &PublicKey) -> SharedSecret {
        let secret = self
            .secret
            .take()
            .expect("ephemeral secret already consumed");
        secret.diffie_hellman(their_public)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_key.as_bytes())
    }
}

/// Derives a 256-bit session content key from X25519 shared secret.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    auth_nonce: &[u8],
    mobile_x25519_pub: &[u8; 32],
    host_x25519_pub: &[u8; 32],
    session_id: &str,
) -> Result<[u8; 32]> {
    // info = protocol_prefix || mobile_pub || host_pub || session_id
    let mut info = Vec::with_capacity(PROTOCOL_INFO_PREFIX.len() + 32 + 32 + session_id.len());
    info.extend_from_slice(PROTOCOL_INFO_PREFIX);
    info.extend_from_slice(mobile_x25519_pub);
    info.extend_from_slice(host_x25519_pub);
    info.extend_from_slice(session_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(auth_nonce), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    Ok(key)
}

/// Per-session encryption/decryption state.
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    /// Counter for outbound messages (host→mobile).
    send_counter: u64,
    /// Counter for inbound messages (mobile→host) — for replay detection.
    recv_counter: u64,
    is_host: bool,
}

impl SessionCipher {
    pub fn new_host(session_key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&session_key)
                .expect("session key is 32 bytes"),
            send_counter: 0,
            recv_counter: 0,
            is_host: true,
        }
    }

    pub fn new_mobile(session_key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&session_key)
                .expect("session key is 32 bytes"),
            send_counter: 0,
            recv_counter: 0,
            is_host: false,
        }
    }

    /// Build a 96-bit nonce: 4 bytes direction + 8 bytes counter.
    fn build_nonce(direction: u32, counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&direction.to_be_bytes());
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypt a plaintext payload. Returns (nonce_bytes, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let direction = if self.is_host {
            DIRECTION_HOST_TO_MOBILE
        } else {
            DIRECTION_MOBILE_TO_HOST
        };

        let nonce = Self::build_nonce(direction, self.send_counter);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {}", e))?;

        self.send_counter += 1;

        Ok((nonce.as_slice().to_vec(), ciphertext))
    }

    /// Decrypt a ciphertext payload. Validates nonce counter for replay protection.
    pub fn decrypt(&mut self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce_bytes.len() != 12 {
            return Err(anyhow!("invalid nonce length: {}", nonce_bytes.len()));
        }

        let nonce = Nonce::from_slice(nonce_bytes);

        // Validate direction: incoming messages should be from the other side
        let expected_direction = if self.is_host {
            DIRECTION_MOBILE_TO_HOST
        } else {
            DIRECTION_HOST_TO_MOBILE
        };

        let msg_direction = u32::from_be_bytes([
            nonce_bytes[0],
            nonce_bytes[1],
            nonce_bytes[2],
            nonce_bytes[3],
        ]);
        if msg_direction != expected_direction {
            return Err(anyhow!(
                "unexpected nonce direction: expected {}, got {}",
                expected_direction,
                msg_direction
            ));
        }

        // Extract counter and check for replay
        let msg_counter = u64::from_be_bytes([
            nonce_bytes[4],
            nonce_bytes[5],
            nonce_bytes[6],
            nonce_bytes[7],
            nonce_bytes[8],
            nonce_bytes[9],
            nonce_bytes[10],
            nonce_bytes[11],
        ]);
        if msg_counter < self.recv_counter {
            return Err(anyhow!(
                "replay detected: counter {} < expected {}",
                msg_counter,
                self.recv_counter
            ));
        }

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("decryption failed: {}", e))?;

        // Advance counter past the received message
        self.recv_counter = msg_counter + 1;

        Ok(plaintext)
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// Parse a base64-encoded X25519 public key.
pub fn parse_x25519_public_key(b64: &str) -> Result<PublicKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("invalid base64 for X25519 public key: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "X25519 public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

/// Signed-SDP envelope fields, produced by `sign_sdp` and emitted alongside
/// the raw SDP in the signaling payload.
#[derive(Debug, Clone)]
pub struct SignedSdp {
    pub sig_b64: String,
    pub nonce_b64: String,
    pub ts: i64,
}

#[derive(Debug, Clone)]
pub struct SignedX25519KeyResponse {
    pub sig_b64: String,
    pub nonce_b64: String,
    pub ts: i64,
}

/// The capability-signature fields of an `x25519_key_response`, produced by
/// [`sign_host_caps`].
#[derive(Debug, Clone)]
pub struct SignedHostCaps {
    pub sig_b64: String,
    pub nonce_b64: String,
    pub ts: i64,
}

/// The exact byte string covered by an SDP signature. Both the signing path
/// (`sign_sdp`) and the verifying path (`daemon::auth::verify_signed_sdp_payload`)
/// MUST go through this function — if the two ever spell the format out
/// separately they can silently drift and every signature check becomes a no-op
/// against a differently-framed payload.
pub(crate) fn canonical_signing_payload(
    sdp_type: &str,
    nonce_b64: &str,
    ts: i64,
    sdp: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        SDP_SIGNING_PREFIX, sdp_type, nonce_b64, ts, sdp
    )
}

fn canonical_pair_attest_payload(
    code: &str,
    host_pub_b64: &str,
    nonce_b64: &str,
    ts: i64,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        PAIR_ATTEST_SIGNING_PREFIX, code, host_pub_b64, nonce_b64, ts
    )
}

/// The message the phone signs. v2 appends the source path, the destination
/// path (each as a JSON string, so a `|` in a path cannot shift a field) and
/// the size: `…|<nonce>|"<src_path>"|"<dst_path>"|<size>`. The phone builds
/// the same string in `mobile/src/services/fileService.ts`.
fn canonical_host_transfer_attestation_payload(
    attestation: &crate::models::HostTransferAttestation,
) -> String {
    let mut canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        HOST_TRANSFER_SIGNING_PREFIX,
        attestation.v,
        attestation.mobile_device_id,
        attestation.transfer_id,
        attestation.src_host_id,
        attestation.src_host_public_key,
        attestation.dst_host_id,
        attestation.dst_host_public_key,
        attestation.expires_at,
        attestation.nonce
    );
    if attestation.v >= 2 {
        let json = |path: &Option<String>| {
            serde_json::to_string(path.as_deref().unwrap_or_default()).unwrap_or_default()
        };
        canonical.push_str(&format!(
            "|{}|{}|{}",
            json(&attestation.src_path),
            json(&attestation.dst_path),
            attestation.size.unwrap_or_default()
        ));
    }
    canonical
}

/// The string the host-capability signature covers. Bound to the exchange's
/// session and host ephemeral key, so a capability cannot be lifted from one
/// response into another, and domain-separated from the key-exchange signature.
fn canonical_host_caps_payload(
    host_id: &str,
    mobile_device_id: &str,
    session_id: &str,
    host_pub_b64: &str,
    caps: &[&str],
    nonce_b64: &str,
    ts: i64,
) -> String {
    format!(
        "{HOST_CAPS_SIGNING_PREFIX}|{host_id}|{mobile_device_id}|{session_id}|{host_pub_b64}|{}|{nonce_b64}|{ts}",
        caps.join(",")
    )
}

fn canonical_x25519_response_payload(
    host_id: &str,
    mobile_device_id: &str,
    session_id: &str,
    mobile_pub_b64: &str,
    host_pub_b64: &str,
    salt_b64: &str,
    nonce_b64: &str,
    ts: i64,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        X25519_SIGNING_PREFIX,
        host_id,
        mobile_device_id,
        session_id,
        mobile_pub_b64,
        host_pub_b64,
        salt_b64,
        nonce_b64,
        ts
    )
}

/// Verify a mobile-signed direct host-to-host transfer attestation against the
/// mobile device public key pinned on this host.
pub fn verify_host_transfer_attestation(
    attestation: &crate::models::HostTransferAttestation,
    mobile_public_key_b64: &str,
) -> Result<()> {
    match attestation.v {
        1 => {}
        2 => {
            if attestation.src_path.as_deref().is_none_or(str::is_empty)
                || attestation.dst_path.as_deref().is_none_or(str::is_empty)
                || attestation.size.is_none()
            {
                return Err(anyhow!(
                    "host transfer attestation v2 is missing its paths or size"
                ));
            }
        }
        _ => return Err(anyhow!("unsupported host transfer attestation version")),
    }
    if attestation.mobile_device_id.is_empty()
        || attestation.transfer_id.is_empty()
        || attestation.src_host_id.is_empty()
        || attestation.src_host_public_key.is_empty()
        || attestation.dst_host_id.is_empty()
        || attestation.dst_host_public_key.is_empty()
        || attestation.nonce.is_empty()
        || attestation.sig.is_empty()
    {
        return Err(anyhow!(
            "host transfer attestation is missing required fields"
        ));
    }

    let now = chrono::Utc::now().timestamp();
    if attestation.expires_at < now {
        return Err(anyhow!("host transfer attestation expired"));
    }
    if attestation.expires_at - now > HOST_TRANSFER_MAX_LIFETIME_SECS {
        return Err(anyhow!("host transfer attestation lifetime is too long"));
    }

    let nonce = base64::engine::general_purpose::STANDARD
        .decode(&attestation.nonce)
        .map_err(|e| anyhow!("invalid host transfer attestation nonce base64: {}", e))?;
    if nonce.len() != 16 {
        return Err(anyhow!("host transfer attestation nonce must be 16 bytes"));
    }

    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(mobile_public_key_b64)
        .map_err(|e| anyhow!("invalid mobile public key base64: {}", e))?;
    let verify_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("mobile public key must be 32 bytes"))?,
    )
    .map_err(|e| anyhow!("invalid mobile public key: {}", e))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&attestation.sig)
        .map_err(|e| anyhow!("invalid host transfer attestation signature base64: {}", e))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("invalid host transfer attestation signature: {}", e))?;
    let canonical = canonical_host_transfer_attestation_payload(attestation);
    verify_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| anyhow!("host transfer attestation signature did not verify: {}", e))
}

/// Decode a base64-encoded 32-byte Ed25519 seed into a `SigningKey`. The seed
/// is moved through a `Zeroizing` buffer so it doesn't linger on the stack
/// after construction. Used by every signing path (SDP, X25519 handshake,
/// host reauth) so seed-handling stays consistent.
pub(crate) fn parse_ed25519_signing_key(private_key_b64: &str) -> Result<SigningKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(private_key_b64)
        .map_err(|e| anyhow!("invalid base64 for ed25519 private key: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "ed25519 private key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

/// Sign an outgoing SDP offer/answer with the host's ED25519 identity key.
///
/// `private_key_b64` is the base64-encoded 32-byte ED25519 secret (the `private_key`
/// field stored on `HostIdentity`). `sdp_type` MUST be `"offer"` or `"answer"`.
///
/// Returns the signature, a fresh 16-byte nonce, and a Unix timestamp — all of
/// which are echoed in the signaling envelope alongside the SDP so the mobile
/// client can verify.
pub fn sign_sdp(private_key_b64: &str, sdp: &str, sdp_type: &str) -> Result<SignedSdp> {
    let signing_key = parse_ed25519_signing_key(private_key_b64)?;
    let (nonce_b64, ts) = fresh_nonce_and_ts();
    let payload = canonical_signing_payload(sdp_type, &nonce_b64, ts, sdp);
    Ok(SignedSdp {
        sig_b64: sign_b64(&signing_key, &payload),
        nonce_b64,
        ts,
    })
}

/// Sign a host X25519 key-exchange response with the host identity key.
///
/// The signed transcript binds both ephemeral public keys, the salt, session,
/// host, and mobile device id so a signaling relay cannot substitute keys.
pub fn sign_x25519_key_response(
    signing_key: &SigningKey,
    host_id: &str,
    mobile_device_id: &str,
    session_id: &str,
    mobile_pub_b64: &str,
    host_pub_b64: &str,
    salt_b64: &str,
) -> SignedX25519KeyResponse {
    let (nonce_b64, ts) = fresh_nonce_and_ts();
    let payload = canonical_x25519_response_payload(
        host_id,
        mobile_device_id,
        session_id,
        mobile_pub_b64,
        host_pub_b64,
        salt_b64,
        &nonce_b64,
        ts,
    );
    SignedX25519KeyResponse {
        sig_b64: sign_b64(signing_key, &payload),
        nonce_b64,
        ts,
    }
}

/// Sign the capabilities a host advertises in its `x25519_key_response`
/// (`caps`, `caps_sig`, `caps_nonce`, `caps_ts`), so the phone can take its
/// agent-wire v1/v2 decision from the host's own key rather than from the
/// backend-reported version. Bound to this exchange's session and host
/// ephemeral key.
pub fn sign_host_caps(
    signing_key: &SigningKey,
    host_id: &str,
    mobile_device_id: &str,
    session_id: &str,
    host_pub_b64: &str,
    caps: &[&str],
) -> SignedHostCaps {
    let (nonce_b64, ts) = fresh_nonce_and_ts();
    let payload = canonical_host_caps_payload(
        host_id,
        mobile_device_id,
        session_id,
        host_pub_b64,
        caps,
        &nonce_b64,
        ts,
    );
    SignedHostCaps {
        sig_b64: sign_b64(signing_key, &payload),
        nonce_b64,
        ts,
    }
}

/// A fresh 16-byte signature nonce (base64) and the current Unix time.
fn fresh_nonce_and_ts() -> (String, i64) {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    (
        base64::engine::general_purpose::STANDARD.encode(nonce),
        chrono::Utc::now().timestamp(),
    )
}

/// Ed25519-sign `payload`, base64-encoded.
fn sign_b64(signing_key: &SigningKey, payload: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(signing_key.sign(payload.as_bytes()).to_bytes())
}

/// Strategy A: sign a pair-attestation binding the host's ED25519 public key
/// to the pairing code the user typed in the mobile app. The mobile verifies
/// against the host-reported pubkey and, on success, upgrades the local pin
/// source from "backend" to "qr".
///
/// Code-slot value for the QR (host-initiated) flow, which has no pairing
/// code when the host opens its claim. MUST match
/// `app/services/pair_attestation.py::HOST_INIT_ATTEST_CONTEXT`.
pub const HOST_INIT_ATTEST_CONTEXT: &str = "host-initiated-create";

/// Returns the wire-shape `PairAttestation` directly so the agent can drop it
/// into `PairingValidateRequest.pair_attestation` (or
/// `HostInitiatedCreateRequest.pair_attestation`) without remapping fields.
pub fn sign_pair_attestation(
    private_key_b64: &str,
    code: &str,
    host_pub_b64: &str,
) -> Result<crate::models::PairAttestation> {
    let signing_key = parse_ed25519_signing_key(private_key_b64)?;
    let (nonce_b64, ts) = fresh_nonce_and_ts();
    let payload = canonical_pair_attest_payload(code, host_pub_b64, &nonce_b64, ts);
    Ok(crate::models::PairAttestation {
        sig: sign_b64(&signing_key, &payload),
        nonce: nonce_b64,
        ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn test_sign_sdp_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk: VerifyingKey = sk.verifying_key();

        let sk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let sdp =
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 AA:BB\r\n";

        let signed = sign_sdp(&sk_b64, sdp, "answer").unwrap();

        // Verify using the same canonical payload construction.
        let canon = canonical_signing_payload("answer", &signed.nonce_b64, signed.ts, sdp);
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.sig_b64)
            .unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(canon.as_bytes(), &sig).unwrap();

        // Tampering the sdp must break the signature.
        let bad = canonical_signing_payload("answer", &signed.nonce_b64, signed.ts, "different");
        assert!(vk.verify(bad.as_bytes(), &sig).is_err());

        // Nonce is 16 bytes = 24 base64 chars (with '=' padding).
        let n = base64::engine::general_purpose::STANDARD
            .decode(&signed.nonce_b64)
            .unwrap();
        assert_eq!(n.len(), 16);
    }

    /// Pinned literally so the phone's copy (`hostAgentCaps.ts`) can be
    /// checked against the same string.
    #[test]
    fn the_host_caps_canonical_string_is_stable() {
        assert_eq!(
            canonical_host_caps_payload(
                "host-1",
                "mobile-1",
                "agent:host-1:mobile-1",
                "SFBVQg==",
                &["agent_wire_v2"],
                "Tk9OQ0U=",
                1_700_000_000,
            ),
            "pocketshell-host-caps-v1|host-1|mobile-1|agent:host-1:mobile-1|SFBVQg==|agent_wire_v2|Tk9OQ0U=|1700000000",
        );
    }

    /// Ed25519 is deterministic, so this signature over the pinned string is a
    /// cross-language vector: `hostAgentCaps.test.ts` verifies the same bytes.
    #[test]
    fn the_host_caps_signature_matches_the_phone_vector() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let message = canonical_host_caps_payload(
            "host-1",
            "mobile-1",
            "agent:host-1:mobile-1",
            "SFBVQg==",
            &["agent_wire_v2"],
            "Tk9OQ0U=",
            1_700_000_000,
        );
        assert_eq!(
            b64.encode(sk.verifying_key().to_bytes()),
            "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg="
        );
        assert_eq!(
            sign_b64(&sk, &message),
            "2WB/PCgzlT0iywk6I5cZ00n0kuqixWzHmMQV9PHhTa7xLsEXtJclSnk5F3Vb5kniDYnzdSa10n1XnpLkVnJKBA=="
        );
    }

    #[test]
    fn the_host_caps_are_signed_by_the_host_identity_key() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let signed = sign_host_caps(
            &sk,
            "host-1",
            "mobile-1",
            "agent:host-1:mobile-1",
            "SFBVQg==",
            &["agent_wire_v2"],
        );
        let message = canonical_host_caps_payload(
            "host-1",
            "mobile-1",
            "agent:host-1:mobile-1",
            "SFBVQg==",
            &["agent_wire_v2"],
            &signed.nonce_b64,
            signed.ts,
        );
        let sig = Signature::from_slice(&b64.decode(&signed.sig_b64).unwrap()).unwrap();
        vk.verify(message.as_bytes(), &sig)
            .expect("verifies under the host key");
        // Bound to this exchange: another session's response cannot carry it.
        let lifted = message.replace("agent:host-1:mobile-1", "agent:host-1:mobile-2");
        assert!(vk.verify(lifted.as_bytes(), &sig).is_err());
    }

    #[test]
    fn test_sign_x25519_key_response_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk: VerifyingKey = sk.verifying_key();
        let signed = sign_x25519_key_response(
            &sk,
            "host-1",
            "mobile-1",
            "session-1",
            "mobile-pub",
            "host-pub",
            "salt",
        );

        let canon = canonical_x25519_response_payload(
            "host-1",
            "mobile-1",
            "session-1",
            "mobile-pub",
            "host-pub",
            "salt",
            &signed.nonce_b64,
            signed.ts,
        );
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.sig_b64)
            .unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(canon.as_bytes(), &sig).unwrap();

        let tampered = canonical_x25519_response_payload(
            "host-1",
            "mobile-1",
            "session-1",
            "mobile-pub",
            "attacker-host-pub",
            "salt",
            &signed.nonce_b64,
            signed.ts,
        );
        assert!(vk.verify(tampered.as_bytes(), &sig).is_err());
    }

    #[test]
    fn test_sign_pair_attestation_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk: VerifyingKey = sk.verifying_key();
        let sk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let host_pub_b64 = base64::engine::general_purpose::STANDARD.encode(vk.to_bytes());

        let signed = sign_pair_attestation(&sk_b64, "ABC123", &host_pub_b64).unwrap();

        let canon =
            canonical_pair_attest_payload("ABC123", &host_pub_b64, &signed.nonce, signed.ts);
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.sig)
            .unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(canon.as_bytes(), &sig).unwrap();

        // Binding to the user's pairing event: a different code must not verify.
        let bad = canonical_pair_attest_payload("WRONG", &host_pub_b64, &signed.nonce, signed.ts);
        assert!(vk.verify(bad.as_bytes(), &sig).is_err());

        // The attacker scenario this attestation defends against: a substituted
        // pubkey under the same code must not verify.
        let bad_pub = canonical_pair_attest_payload("ABC123", "evil-pub", &signed.nonce, signed.ts);
        assert!(vk.verify(bad_pub.as_bytes(), &sig).is_err());
    }

    #[test]
    fn test_verify_host_transfer_attestation_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk: VerifyingKey = sk.verifying_key();
        let mobile_pub_b64 = base64::engine::general_purpose::STANDARD.encode(vk.to_bytes());
        let mut att = crate::models::HostTransferAttestation {
            v: 1,
            mobile_device_id: "mobile-1".into(),
            transfer_id: "transfer-1".into(),
            src_host_id: "src-host".into(),
            src_host_public_key: "src-pub".into(),
            dst_host_id: "dst-host".into(),
            dst_host_public_key: "dst-pub".into(),
            expires_at: chrono::Utc::now().timestamp() + 60,
            nonce: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            ..Default::default()
        };
        let canonical = canonical_host_transfer_attestation_payload(&att);
        let sig = sk.sign(canonical.as_bytes());
        att.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        verify_host_transfer_attestation(&att, &mobile_pub_b64).unwrap();

        let mut tampered = att.clone();
        tampered.dst_host_public_key = "evil-dst-pub".into();
        assert!(verify_host_transfer_attestation(&tampered, &mobile_pub_b64).is_err());
    }

    fn signed_v2_attestation(sk: &SigningKey) -> crate::models::HostTransferAttestation {
        let mut att = crate::models::HostTransferAttestation {
            v: 2,
            mobile_device_id: "mobile-1".into(),
            transfer_id: "transfer-1".into(),
            src_host_id: "src-host".into(),
            src_host_public_key: "src-pub".into(),
            dst_host_id: "dst-host".into(),
            dst_host_public_key: "dst-pub".into(),
            expires_at: chrono::Utc::now().timestamp() + 60,
            nonce: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            sig: String::new(),
            src_path: Some("/home/me/report|v1.pdf".into()),
            dst_path: Some("/srv/in/report.pdf".into()),
            size: Some(4096),
        };
        let canonical = canonical_host_transfer_attestation_payload(&att);
        att.sig = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(canonical.as_bytes()).to_bytes());
        att
    }

    #[test]
    fn a_v2_attestation_binds_its_paths_and_size() {
        let sk = SigningKey::generate(&mut OsRng);
        let mobile_pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        let att = signed_v2_attestation(&sk);
        verify_host_transfer_attestation(&att, &mobile_pub_b64).unwrap();
        let paths = att.attested_paths().unwrap();
        assert_eq!(paths.dst_path, "/srv/in/report.pdf");
        assert_eq!(paths.size, 4096);

        let mut other_dst = att.clone();
        other_dst.dst_path = Some("/home/me/.bashrc".into());
        assert!(verify_host_transfer_attestation(&other_dst, &mobile_pub_b64).is_err());
        let mut other_src = att.clone();
        other_src.src_path = Some("/home/me/.ssh/id_ed25519".into());
        assert!(verify_host_transfer_attestation(&other_src, &mobile_pub_b64).is_err());
        let mut bigger = att.clone();
        bigger.size = Some(1 << 30);
        assert!(verify_host_transfer_attestation(&bigger, &mobile_pub_b64).is_err());
        // A `|` moved between the two paths changes the signed string.
        let mut shifted = att.clone();
        shifted.src_path = Some("/home/me/report".into());
        shifted.dst_path = Some("v1.pdf|/srv/in/report.pdf".into());
        assert!(verify_host_transfer_attestation(&shifted, &mobile_pub_b64).is_err());
        // Downgraded to v1 with the same signature: the canonical string differs.
        let mut downgraded = att.clone();
        downgraded.v = 1;
        assert!(verify_host_transfer_attestation(&downgraded, &mobile_pub_b64).is_err());
    }

    #[test]
    fn a_v2_attestation_without_its_paths_or_size_is_refused() {
        let sk = SigningKey::generate(&mut OsRng);
        let mobile_pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        for strip in 0..3 {
            let mut att = signed_v2_attestation(&sk);
            match strip {
                0 => att.src_path = None,
                1 => att.dst_path = Some(String::new()),
                _ => att.size = None,
            }
            let canonical = canonical_host_transfer_attestation_payload(&att);
            att.sig = base64::engine::general_purpose::STANDARD
                .encode(sk.sign(canonical.as_bytes()).to_bytes());
            assert!(verify_host_transfer_attestation(&att, &mobile_pub_b64).is_err());
        }
        let mut v3 = signed_v2_attestation(&sk);
        v3.v = 3;
        assert!(verify_host_transfer_attestation(&v3, &mobile_pub_b64).is_err());
    }

    #[test]
    fn a_v1_attestations_path_fields_are_not_trusted() {
        let sk = SigningKey::generate(&mut OsRng);
        let mobile_pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        let mut att = signed_v2_attestation(&sk);
        att.v = 1;
        let canonical = canonical_host_transfer_attestation_payload(&att);
        att.sig = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(canonical.as_bytes()).to_bytes());
        // The v1 signature does not cover the paths, so they bind nothing.
        verify_host_transfer_attestation(&att, &mobile_pub_b64).unwrap();
        assert_eq!(att.attested_paths(), None);
    }

    /// The same string `mobile/src/services/__tests__/hostTransferAttestation.test.ts`
    /// expects the phone to sign.
    #[test]
    fn the_v2_canonical_string_matches_the_phones() {
        let att = crate::models::HostTransferAttestation {
            v: 2,
            mobile_device_id: "mdi-1".into(),
            transfer_id: "h2h_1_1700000000000".into(),
            src_host_id: "src".into(),
            src_host_public_key: "c3JjLXB1Yg==".into(),
            dst_host_id: "dst".into(),
            dst_host_public_key: "ZHN0LXB1Yg==".into(),
            expires_at: 1_700_000_120,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            sig: String::new(),
            src_path: Some("C:\\Users\\me\\a \"b\"|c.txt".into()),
            dst_path: Some("/home/me/naïve\tfile".into()),
            size: Some(1234),
        };
        assert_eq!(
            canonical_host_transfer_attestation_payload(&att),
            "pocketshell-host-transfer-v1|2|mdi-1|h2h_1_1700000000000|src|c3JjLXB1Yg==|dst|\
             ZHN0LXB1Yg==|1700000120|AAAAAAAAAAAAAAAAAAAAAA==|\
             \"C:\\\\Users\\\\me\\\\a \\\"b\\\"|c.txt\"|\"/home/me/naïve\\tfile\"|1234"
        );
    }

    #[test]
    fn test_verify_host_transfer_attestation_rejects_expired() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk: VerifyingKey = sk.verifying_key();
        let mobile_pub_b64 = base64::engine::general_purpose::STANDARD.encode(vk.to_bytes());
        let mut att = crate::models::HostTransferAttestation {
            v: 1,
            mobile_device_id: "mobile-1".into(),
            transfer_id: "transfer-1".into(),
            src_host_id: "src-host".into(),
            src_host_public_key: "src-pub".into(),
            dst_host_id: "dst-host".into(),
            dst_host_public_key: "dst-pub".into(),
            expires_at: chrono::Utc::now().timestamp() - 1,
            nonce: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            ..Default::default()
        };
        let canonical = canonical_host_transfer_attestation_payload(&att);
        let sig = sk.sign(canonical.as_bytes());
        att.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        assert!(verify_host_transfer_attestation(&att, &mobile_pub_b64).is_err());
    }

    #[test]
    fn test_sign_sdp_rejects_bad_key() {
        // Not base64
        assert!(sign_sdp("!!not-base64!!", "sdp", "offer").is_err());
        // Wrong length
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(sign_sdp(&short, "sdp", "offer").is_err());
    }

    #[test]
    fn test_key_exchange_and_encrypt_decrypt() {
        // Simulate both sides
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        // Both sides compute shared secret
        let host_shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let mobile_shared = mobile_kp.diffie_hellman(&PublicKey::from(host_pub));

        assert_eq!(host_shared.as_bytes(), mobile_shared.as_bytes());

        let auth_nonce = b"test-auth-nonce-32-bytes-padding!";
        let session_id = "test-session-123";

        // Derive session keys
        let host_key = derive_session_key(
            host_shared.as_bytes(),
            auth_nonce,
            &mobile_pub,
            &host_pub,
            session_id,
        )
        .unwrap();
        let mobile_key = derive_session_key(
            mobile_shared.as_bytes(),
            auth_nonce,
            &mobile_pub,
            &host_pub,
            session_id,
        )
        .unwrap();

        assert_eq!(host_key, mobile_key);

        // Create ciphers
        let mut host_cipher = SessionCipher::new_host(host_key);
        let mut mobile_cipher = SessionCipher::new_mobile(mobile_key);

        // Host encrypts, mobile decrypts
        let plaintext = b"hello from host";
        let (nonce, ciphertext) = host_cipher.encrypt(plaintext).unwrap();
        let decrypted = mobile_cipher.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Mobile encrypts, host decrypts
        let plaintext2 = b"hello from mobile";
        let (nonce2, ciphertext2) = mobile_cipher.encrypt(plaintext2).unwrap();
        let decrypted2 = host_cipher.decrypt(&nonce2, &ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_replay_protection() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"replay-test-nonce-32-bytes-pad!!";

        let key = derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s1")
            .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut mobile_cipher = SessionCipher::new_mobile(key);

        // Host sends two messages
        let (nonce1, ct1) = host_cipher.encrypt(b"msg1").unwrap();
        let (nonce2, ct2) = host_cipher.encrypt(b"msg2").unwrap();

        // Mobile receives both in order
        mobile_cipher.decrypt(&nonce1, &ct1).unwrap();
        mobile_cipher.decrypt(&nonce2, &ct2).unwrap();

        // Replaying nonce1 should fail
        let result = mobile_cipher.decrypt(&nonce1, &ct1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn test_wrong_direction_rejected() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"direction-test-nonce-32-pad!!!!!";

        let key = derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s2")
            .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut host_cipher2 = SessionCipher::new_host(key);

        // Host encrypts (direction = host→mobile)
        let (nonce, ct) = host_cipher.encrypt(b"msg").unwrap();

        // Another host instance tries to decrypt as if it were inbound — wrong direction
        let result = host_cipher2.decrypt(&nonce, &ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("direction"));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"tamper-test-nonce-32-bytes-pad!!";

        let key = derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s3")
            .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut mobile_cipher = SessionCipher::new_mobile(key);

        let (nonce, mut ct) = host_cipher.encrypt(b"sensitive data").unwrap();

        // Flip a byte
        ct[0] ^= 0xff;

        let result = mobile_cipher.decrypt(&nonce, &ct);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn test_parse_x25519_public_key() {
        let kp = EphemeralKeypair::generate();
        let b64 = kp.public_key_base64();
        let parsed = parse_x25519_public_key(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), kp.public_key.as_bytes());
    }

    #[test]
    fn test_different_sessions_produce_different_keys() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();
        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();
        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let salt = b"same-salt-for-both-sessions!!!!!";

        let key1 = derive_session_key(shared.as_bytes(), salt, &mobile_pub, &host_pub, "session-A")
            .unwrap();
        let key2 = derive_session_key(shared.as_bytes(), salt, &mobile_pub, &host_pub, "session-B")
            .unwrap();

        assert_ne!(
            key1, key2,
            "different session_ids must produce different keys"
        );
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();
        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();
        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));

        let key1 = derive_session_key(
            shared.as_bytes(),
            b"salt-one-32-bytes-pad!!!!!!!!!",
            &mobile_pub,
            &host_pub,
            "s",
        )
        .unwrap();
        let key2 = derive_session_key(
            shared.as_bytes(),
            b"salt-two-32-bytes-pad!!!!!!!!!",
            &mobile_pub,
            &host_pub,
            "s",
        )
        .unwrap();

        assert_ne!(key1, key2, "different salts must produce different keys");
    }

    #[test]
    fn test_nonce_never_reused_within_session() {
        let key = [0x42u8; 32];
        let mut cipher = SessionCipher::new_host(key);

        let (nonce1, _) = cipher.encrypt(b"msg1").unwrap();
        let (nonce2, _) = cipher.encrypt(b"msg2").unwrap();
        let (nonce3, _) = cipher.encrypt(b"msg3").unwrap();

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_counter_monotonically_increases() {
        let key = [0x42u8; 32];
        let mut cipher = SessionCipher::new_host(key);

        assert_eq!(cipher.send_counter(), 0);
        cipher.encrypt(b"a").unwrap();
        assert_eq!(cipher.send_counter(), 1);
        cipher.encrypt(b"b").unwrap();
        assert_eq!(cipher.send_counter(), 2);
    }

    #[test]
    fn test_out_of_order_allowed_but_replay_rejected() {
        let key = [0x42u8; 32];
        let mut host = SessionCipher::new_host(key);
        let mut mobile = SessionCipher::new_mobile(key);

        let (n1, c1) = host.encrypt(b"msg1").unwrap();
        let (n2, c2) = host.encrypt(b"msg2").unwrap();
        let (n3, c3) = host.encrypt(b"msg3").unwrap();

        // Receive out of order: 3, then 1 skipped, then replay 3
        mobile.decrypt(&n3, &c3).unwrap(); // counter jumps to 3
                                           // n1 has counter 0 which is < recv_counter (3), so rejected
        assert!(mobile.decrypt(&n1, &c1).is_err());
        // n2 has counter 1 which is also < recv_counter (3)
        assert!(mobile.decrypt(&n2, &c2).is_err());
        // replaying n3 again: counter 2 < recv_counter (3)
        assert!(mobile.decrypt(&n3, &c3).is_err());
    }

    #[test]
    fn test_large_payload_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let mut host = SessionCipher::new_host(key);
        let mut mobile = SessionCipher::new_mobile(key);

        // 200 KB payload (at the signaling limit)
        let payload = vec![0xABu8; 200 * 1024];
        let (nonce, ct) = host.encrypt(&payload).unwrap();
        let decrypted = mobile.decrypt(&nonce, &ct).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_ephemeral_key_consumed_after_dh() {
        let kp = EphemeralKeypair::generate();
        let other_pub = EphemeralKeypair::generate().public_key;

        // After diffie_hellman, the private key is consumed
        let _shared = kp.diffie_hellman(&other_pub);
        // kp is moved — cannot be used again (enforced by Rust ownership)
    }

    #[test]
    fn test_cross_session_cipher_isolation() {
        // Two sessions with different keys cannot decrypt each other's messages
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let mut host1 = SessionCipher::new_host(key1);
        let mut mobile2 = SessionCipher::new_mobile(key2);

        let (nonce, ct) = host1.encrypt(b"secret").unwrap();
        let result = mobile2.decrypt(&nonce, &ct);
        assert!(result.is_err(), "different session keys must not decrypt");
    }

    #[test]
    fn test_invalid_public_key_rejected() {
        // Too short
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(parse_x25519_public_key(&short).is_err());

        // Too long
        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(parse_x25519_public_key(&long).is_err());

        // Invalid base64
        assert!(parse_x25519_public_key("not-valid-base64!!!").is_err());
    }
}
