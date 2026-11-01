# Thumbdesk protocol: pairing, sessions and sealed signaling

This document describes how a phone running the Thumbdesk app and a machine running the Thumbdesk host agent establish trust and open connections, and what each party can and cannot do along the way. It matches host agent 2.0.0 and the 2.0 apps. The host-side implementation of everything here is published in [`../crates/host-core/src/`](../crates/host-core/src/) (`pairing_proof.rs`, `signaling_crypto.rs`, `api.rs`, `transport.rs`, `models.rs`, `auth.rs`); where this document and that code disagree, the code is right and the document has a bug.

Conventions: byte strings are base64 (standard alphabet, padded) unless stated; timestamps are Unix seconds; signatures are Ed25519 over the UTF-8 bytes of the string shown; `|` is a literal pipe in a joined string. Every signed string starts with a domain tag so a signature made for one purpose cannot be presented for another. The tags keep their original `pocketshell-` names because they are shared with apps already installed.

| Tag | Signed by | Purpose |
|---|---|---|
| `pocketshell-pair-v1` | pairing secret (HMAC) | the phone proves it scanned the QR |
| `pocketshell-pair-attest-v1` | host key | the host proves it holds the key it registers |
| `pocketshell-reauth-v1` | host key | the host re-authenticates to the backend without a refresh token |
| `pocketshell-ws-v1` | device key | every phone-originated signaling message that acts on the host |
| `pocketshell-session-open-v1` | device key | the request to open a terminal session |
| `pocketshell-sdp-v1` | host key | the host's WebRTC answers and offers |
| `pocketshell-x25519-v1` | host key | the host's half of the sealed-signaling key exchange |
| `pocketshell-host-caps-v1` | host key | the capabilities the host advertises in that exchange |
| `pocketshell-host-transfer-v1` | device key | the phone's attestation for a host-to-host transfer |
| `pocketshell-files-v1` | (HKDF info) | key derivation for sealed signaling |

## 1. Parties and keys

**Host.** Generates an Ed25519 key pair the first time `thumbdesk pair` runs. The private key lives in the OS keychain (an owner-only file where there is none). The backend assigns a `host_id`. The host keeps its own list of trusted phones, with each phone's public key and permissions.

**Phone.** Holds an Ed25519 device key pair in the platform secure store and a `mobile_device_id` (a UUID). It keeps a pinned public key per host, with a record of where the key came from.

**Backend.** Holds accounts, host and device records, public keys, and the signaling relay. It never holds a private key. Both other parties reach it over TLS only.

The design goal is that the backend is needed to introduce the two devices and to relay their handshake, but cannot impersonate either of them to the other. Sections 2 and 5 are where that is enforced.

## 2. Pairing

Pairing happens over a QR code shown on the host's screen. There are two modes: `new_host` (first phone) and `device_add` (another phone for a host that is already paired). The steps are the same; the differences are noted.

### 2.1 The host asks for a claim

```
POST /api/v1/pairing/host-initiated
{ "hostname", "platform", "public_key", "app_version",
  "pair_attestation": { "sig", "nonce", "ts" } }
```

`pair_attestation.sig` signs `pocketshell-pair-attest-v1|host-initiated-create|<public_key>|<nonce>|<ts>` with the host's private key. A public key is not a secret, so this is what lets the backend reattach an existing host record to a reinstalled agent that recovered its key from the keychain; without a valid attestation the backend creates a new record instead. The response is `{ "claim_token", "expires_at" }`. The claim lives five minutes, is single-use, and only its SHA-256 is stored.

For `device_add` the host is already authenticated and calls `POST /api/v1/pairing/host-initiated/device-add` with `{ "existing_host_id" }` instead.

### 2.2 The host shows the QR

```json
{ "v": 1, "mode": "host_init", "token": "<claim_token>", "pubkey": "<host public key>",
  "hostname": "...", "platform": "...", "bu": "<backend base URL>", "ps": "<pairing secret>" }
```

`ps` is 32 fresh random bytes (base64url, unpadded) that exist only in the memory of this one `pair` command. They are never sent to the backend, logged or written to disk. `pubkey` is how the phone learns the host's key: from something displayed on the machine, not from the backend.

### 2.3 The phone claims it

The phone scans the QR, stores the host's public key with source `qr`, and computes a proof that it did:

```
transcript = len("pocketshell-pair-v1") "pocketshell-pair-v1"
           | len(mode)               mode               # "new_host" or "device_add"
           | len(claim_token)        claim_token
           | len(mobile_device_id)   mobile_device_id   # ASCII-lowercased
           | len(device_public_key)  device_public_key
           | len(host_public_key)    host_public_key
device_proof = base64url_nopad( HMAC-SHA256(ps, transcript) )
```

Each `len` is a 4-byte big-endian length. Then, with its own account's bearer token:

```
POST /api/v1/pairing/host-initiated/claim
{ "claim_token", "mobile_device_id", "device_public_key", "device_proof",
  "device_name"?, "platform"? }
```

The backend checks the claim is unexpired and unused, that a `device_add` claim comes from the account that owns the host, creates the host and trusted-device records, issues host tokens, and stores `device_proof` verbatim. It cannot check the proof: it never had `ps`.

### 2.4 The host verifies and pins

The host polls `POST /api/v1/pairing/host-initiated/status { "claim_token" }` every two seconds until it is `claimed`. The response carries the host record, `access_token`, `refresh_token`, `mobile_device_id`, `device_public_key` and `device_proof`.

Before saving anything, the host recomputes the HMAC over the exact `mobile_device_id` and `device_public_key` it is about to pin, together with the `claim_token` and `host_public_key` it printed, and compares in constant time.

- **Match**: the host saves its identity and tokens and pins the device key. If a daemon was running it is stopped first, so a dying daemon cannot overwrite the new identity.
- **Mismatch**: nothing is saved and `pair` fails. A backend that substituted a device id or key gets exactly this.
- **Absent**: accepted, for apps that predate the proof. This is a deliberate compatibility choice in 2.0.0 (`ACCEPT_PAIRING_WITHOUT_PROOF` in the agent); a mismatching proof is never accepted.

Result: the phone pins the host's key from the QR, and the host pins the phone's key from a value the phone bound to the QR's secret. Neither pin came from the backend alone.

## 3. The host and the backend

**Tokens.** Hosts get a 15-minute access token and a 365-day refresh token. Refresh rotates: each refresh token's id is marked used atomically when redeemed, and presenting a used one is detected as reuse. The refresh token lives in the keychain; the access token in `state.json` (owner-only). Because the daemon and short-lived CLI commands share these, refresh is serialised with a file lock (`auth.rs`).

**Re-authentication.** If the refresh token is lost, the host can prove its identity with its signing key:

```
POST /api/v1/auth/host/reauth { "host_id", "issued_at", "signature" }
signature = Ed25519( "pocketshell-reauth-v1\n" + host_id + "\n" + issued_at )
```

The backend accepts `issued_at` within 30 seconds of its clock and remembers each `(host_id, issued_at)` for that window, so a captured request cannot be replayed.

**Signaling socket.** The daemon connects to `wss://<backend>/ws/host` with `Authorization: Bearer <access token>` and keeps it open. Every signaling message is a JSON envelope:

```json
{ "type": "...", "session_id": "...", "payload": { ... }, "state": "...",
  "host_id": "...", "mobile_device_id": "...", "target_mobile_device_id": "..." }
```

**Presence.** A heartbeat every 20 seconds carries the active session count, the number of devices awaiting approval, the agent version and a capability list (which coding-agent CLIs are installed, whether screen capture is available, what the OS supports). Summary metrics go as separate messages on the same socket; what they contain is listed in the README.

**Trusted devices.** The host refreshes its copy of the trusted-device list from `GET /api/v1/hosts/{host_id}/trusted-devices` every 300 seconds (`THUMBDESK_TRUSTED_DEVICES_SECS`). Every authorization decision below is made against that local copy: a device must be approved and not revoked, and must hold the permission the operation needs. `permissions_json` keys are `shell` (older records say `terminal`, which is honoured as an alias) and `stats`; a record with no permissions object at all, as minted by early apps, grants everything. A revocation is refused by the backend relay immediately and takes effect on an already-open direct channel at the host's next sync.

## 4. Signed signaling messages

Any message from a phone that makes the host do something carries a `ws_auth` block the host verifies against the phone's pinned key before acting:

```json
"ws_auth": { "v": 1, "nonce": "<16 random bytes>", "ts": <unix seconds>,
             "payload_hash": "<base64 SHA-256 of canonical payload>", "signature": "..." }
signature = Ed25519( "pocketshell-ws-v1|host_id|mobile_device_id|type|session_id|state|nonce|ts|payload_hash" )
```

Canonical JSON has object keys sorted and no whitespace. The host rejects a message if the device is not trusted, `ts` is more than 60 seconds from its clock, the payload hash does not match the payload it received, `host_id` names another host, the signature fails, or the nonce was seen from that device in the last 120 seconds.

The types that require it, and the permission each needs:

| Permission | Types |
|---|---|
| `stats` | `stats_offer`, `stats_ice_candidate` |
| `shell` | `session_offer`, `ice_candidate`, `signal`, `session_join`, `session_event`, `files_offer`, `files_ice_candidate`, `screen_offer`, `screen_ice_candidate`, `agent_offer`, `agent_ice_candidate`, `agent_init`, `agent_input`, `agent_close`, `agent_alive_probe`, `x25519_public_key`, `encrypted_file_payload`, `host_transfer_request`, `host_transfer_cancel` |

Because the payload hash covers the SDP inside an offer, and an SDP contains the `a=fingerprint` of the DTLS certificate the phone will present, the phone's WebRTC identity is bound to its pinned Ed25519 key by this signature.

Messages the backend itself sends to the host (`session_request`, `host_control`) are not signed by a device. They are gated on device trust and permissions, and their consequences are limited: for example the backend cannot trigger a self-update through `host_control`; that command is only accepted over an authenticated channel from a paired phone.

## 5. Opening a terminal session

```
Phone                          Backend                         Host
  |  POST /api/v1/sessions         |                              |
  |  {host_id, purpose,            |                              |
  |   attach_target?, open_auth}   |                              |
  |------------------------------->|  session_request             |
  |                                |----------------------------->|  trusted? shell? open_auth ok?
  |                                |  session_ack {accepted}      |  spawn or attach PTY
  |<-------------------------------|<-----------------------------|
  |  session_offer {sdp} + ws_auth |                              |
  |------------------------------->|----------------------------->|  ws_auth ok?
  |                                |  session_answer {sdp,        |  sign answer
  |  verify sdp_sig with QR pin    |   sdp_sig, _nonce, _ts}      |
  |<-------------------------------|<-----------------------------|
  |  ice_candidate (+ ws_auth)  <----- both directions ----->     |
  |                                                               |
  |=============== DTLS handshake, direct or via TURN ============|
  |  \0PSAU auth_challenge {nonce}                                |
  |<--------------------------------------------------------------|
  |  \0PSAU auth_response {signature}                             |
  |-------------------------------------------------------------->|  verify, check permission
  |  \0PSAU auth_result {ok}                                      |
  |<--------------------------------------------------------------|
  |  terminal bytes                                               |
```

1. **Open request.** `open_auth` is `{ "v": 1, "nonce", "ts", "signature" }` where the signature covers `pocketshell-session-open-v1|host_id|mobile_device_id|purpose|<hash of attach_target>|nonce|ts`. The backend relays it inside `session_request`, so a backend that altered the purpose or the attach target after the phone signed fails verification at the host, which also applies the 60-second window and the nonce cache. The host answers `session_ack` with `accepted`, and a `reason` when refused, such as `permission_denied:shell`, `open_auth_invalid` or `pty_failed`.
2. **Offer.** The phone sends `session_offer` with `payload.sdp`, signed as in section 4.
3. **Answer.** The host replies `session_answer` with `payload = { "sdp", "type": "answer", "sdp_sig", "sdp_sig_nonce", "sdp_sig_ts" }`, where `sdp_sig` signs `pocketshell-sdp-v1|answer|<nonce>|<ts>|<sdp>` with the host key. The phone verifies it against the key it pinned from the QR, within 60 seconds. If the host's key did not come from a QR, the phone refuses to open a terminal, stats or screen channel at all: keys reported by the backend are not accepted as WebRTC identity.
4. **ICE.** Candidates travel both ways through the relay; the phone's are signed.
5. **DTLS.** WebRTC's own handshake, whose certificates match the fingerprints inside the two signed SDPs. Through TURN, the relay forwards this ciphertext.
6. **Channel authentication.** Before a data channel is used, the host sends a challenge framed with the sentinel `\0PSAU`: `{ "type": "auth_challenge", "nonce": "<32 random bytes>" }`. The phone replies `{ "type": "auth_response", "signature" }`, signing the raw nonce bytes followed by the channel key and its `mobile_device_id`. The channel key is `<kind>:<mobile_device_id>` (`terminal:…`, `stats:…`, `files:…`, `screen:…`); for dev-server forwarding it is per channel instance and the challenge names it in `channel_key`. The host verifies with the pinned key, checks the permission for that kind (`stats` for stats, `shell` for everything else), and answers `auth_result`. Only an authenticated channel carries bytes. Opening a new channel of the same kind supersedes the old one's authentication.

Stats, screen and files channels follow the same offer, answer, ICE and `\0PSAU` steps with their own `*_offer` types. A revoked device's channels are closed at the host's next trusted-device sync.

**Relay mode.** While WebRTC is connecting or cannot connect, keystrokes travel as `signal` messages (`payload.channel = "terminal"`), each signed per section 4, and output returns over the same socket. These frames are protected by TLS to and from the backend but are readable by it in transit; the app shows a SIGNALING badge while this is the path. Screen sharing never uses the relay.

## 6. Sealed signaling

File operations that go through the relay, and agent chat, are encrypted end to end on top of TLS, so the backend forwards ciphertext. The key comes from an exchange the host signs:

1. Phone → host: `x25519_public_key { "session_id", "public_key" }` (32-byte X25519 key, signed per section 4).
2. Host → phone:
   ```json
   { "session_id", "public_key": "<host X25519 key>", "salt": "<32 random bytes>",
     "sig", "sig_nonce", "sig_ts",
     "caps": ["..."], "caps_sig", "caps_nonce", "caps_ts" }
   ```
   `sig` covers `pocketshell-x25519-v1|host_id|mobile_device_id|session_id|<phone key>|<host key>|<salt>|<nonce>|<ts>`; `caps_sig` covers `pocketshell-host-caps-v1|host_id|mobile_device_id|session_id|<host key>|<caps joined by ","> |<nonce>|<ts>`. Both are Ed25519 by the host's long-term key; the phone verifies them against its QR pin within 60 seconds. The capability list currently advertises the agent-chat wire version, so a relay cannot downgrade the phone to an older, unsealed agent protocol by editing it.
3. Both sides derive the same 32-byte key:
   ```
   key = HKDF-SHA256( ikm = X25519(my private, their public), salt = salt,
                      info = "pocketshell-files-v1" || phone key || host key || session_id )
   ```
4. Each sealed message is `encrypted_file_payload { "session_id", "nonce", "ciphertext" }`, ChaCha20-Poly1305 under that key. The 12-byte nonce is a 4-byte direction (`0` phone to host, `1` host to phone) followed by an 8-byte counter. The receiver rejects a nonce in the wrong direction and any counter lower than the next one it expects, so a frame cannot be replayed or reordered within a session. Agent-chat frames use the same cipher with the same rule, sealed in send order at the single socket writer.

If the exchange fails, the app can fall back to TLS-only frames for small file operations, and the app labels the connection accordingly. Large transfers need a WebRTC channel regardless.

## 7. Host-to-host transfers

A file can move directly between two hosts the same account has paired. Neither host has pinned the other's key, so the phone, which both trust, introduces them with an attestation:

```json
{ "v": 2, "mobile_device_id", "transfer_id", "src_host_id", "src_host_public_key",
  "dst_host_id", "dst_host_public_key", "expires_at", "nonce": "<16 bytes>", "sig",
  "src_path", "dst_path", "size" }
sig = Ed25519( "pocketshell-host-transfer-v1|v|mobile_device_id|transfer_id|src_host_id|src_host_public_key|dst_host_id|dst_host_public_key|expires_at|nonce|<json src_path>|<json dst_path>|size" )
```

Each host verifies the signature with the phone key it pinned at pairing, requires `expires_at` to be in the future and at most five minutes away, and checks that its own `host_id` and public key appear in the attested slot it is playing. The WebRTC offer and answer between the hosts are then signed with the host keys named in the attestation (`sdp_sig`, as in section 5), so the backend can relay the handshake but cannot substitute a peer. Version 1 attestations omit the paths and size.

## 8. Windows and replay protection, in one place

| Check | Where | Window |
|---|---|---|
| Pairing claim | backend | 5 minutes, single use |
| Host re-authentication | backend | 30 seconds, `(host_id, issued_at)` remembered |
| Signed signaling message (`ws_auth`) | host | 60 seconds, nonce remembered 120 seconds per device |
| Session open request (`open_auth`) | host | 60 seconds, nonce remembered |
| Host's signed SDP, key exchange, capabilities | phone | 60 seconds |
| Host-to-host attestation | both hosts | at most 5 minutes ahead |
| Sealed frame | receiver | strictly increasing counter per direction |
| Data-channel challenge | host | one fresh 32-byte nonce per channel |

## 9. What the backend can and cannot do

It can: see who is talking to whom and when; refuse to relay; read terminal frames that pass through the relay path in section 5; read unsealed file operations if the exchange in section 6 fails.

It cannot: pair a phone of its own choosing to a host (section 2.4); make a phone accept a key for a host other than the one on the QR (section 2.3, 5.3); open a session, send a keystroke or start a share as a trusted phone (sections 4 and 5); read sealed file operations or agent chat (section 6); read anything that crosses a direct or TURN WebRTC path; or trigger a self-update of the agent (section 4).

## 10. Test vectors

The pairing proof has a known-answer vector asserted by both the host (`pairing_proof.rs`, `known_answer_vector_matches_mobile`) and the app:

```
secret            = bytes 0x00 … 0x1f
ps (QR field)     = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
claim_token       = kat-claim-token-0123456789abcdef
mobile_device_id  = 3f2b8c1e-5d4a-4f6b-9a7c-0e1d2c3b4a59
device_public_key = ZGV2aWNlLXB1YmxpYy1rZXktMzItYnl0ZXMtISEhISE=
host_public_key   = aG9zdC1wdWJsaWMta2V5LTMyLWJ5dGVzLSEhISEhISE=
proof, new_host   = MicXH0bU0ABYNPq_lHTNbyLuqgylhLF7WsiNSuu5ob8
proof, device_add = o2NFwP82sB9xfwfFrVWXntL8KA6VdeSgxprRyaRFMaI
```

The reauth payload is pinned by `build_reauth_payload_format_is_stable` in `api.rs`: `pocketshell-reauth-v1\nh-123\n2026-05-04T03:40:00+00:00`.

Questions and reports: support@thumbdesk.com, or see [SECURITY.md](../SECURITY.md).
