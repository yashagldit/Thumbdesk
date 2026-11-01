# Published host agent source

These files are the part of the Thumbdesk host agent a developer reads to decide whether to trust it. They are the same files that go into the shipped builds, mirrored from the private repository commit by commit, so `git log` on any of them shows what changed and when, in the author's own words. Each mirror merge names the private commit it was taken from.

| File | What it is |
|---|---|
| `src/pairing_proof.rs` | The QR-bound proof: the phone proves to the host that it scanned the QR, so the backend cannot pair a device key of its own choosing. Known-answer vector shared with the app. |
| `src/signaling_crypto.rs` | Signed SDP transcripts (the DTLS fingerprint bound to the pinned Ed25519 key), the X25519/HKDF key agreement and ChaCha20-Poly1305 envelope for sealed signaling, and the host-to-host transfer attestation. |
| `src/api.rs` | Every HTTPS call the agent makes to the backend. |
| `src/transport.rs` | The WebSocket signaling client. |
| `src/models.rs` | Every payload on the wire, in both directions. |
| `src/auth.rs` | Token refresh, safe across the daemon and short-lived CLI commands. |
| `src/secret_store.rs` | Where the host key and refresh token live: the OS keychain, or an owner-only file where there is none. |
| `src/state_dir.rs`, `src/config.rs` | What is kept on disk and which settings and environment variables the agent reads. |
| `src/audit.rs` | The local audit log: what is recorded, and that terminal contents never are. |
| `src/update.rs` | Self-update: the SHA-256, Sigstore cosign and Apple Developer ID checks a release must pass before it replaces the binary. |

This is a source mirror, not a crate that builds on its own: the files import private modules (`error`, `platform`, `store`, `service`, among others) that are not published. The rest of the agent, the mobile app and the backend are proprietary; see [`../../LICENSE.md`](../../LICENSE.md). Constants marked `MUST match` mirror a value in the app or the backend, and the tests pin them.

The files in this directory are licensed under the [Apache License, Version 2.0](./LICENSE). Found something? Email support@thumbdesk.com with "Security" in the subject.
