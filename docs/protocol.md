# Tablefolk Wire & Storage Protocol Profile

Status: **draft implementation profile.** This document specifies the byte-level
wire formats, cryptographic framing, transport bindings, and local persistence
invariants that [spec.md](spec.md) leaves implicit. Any change that alters
encoded bytes requires a new protocol version once version 1 transcripts exist
outside development fixtures.

For the candidate 36-card Bayer–Groth shuffle proof format, see
[shuffle.md](shuffle.md). For the active Sasku match profile
(`sasku-match-candidate@4`), see [sasku.md](sasku.md).

---

## 1. Deterministic CBOR

All protocol values use **RFC 8949 §4.2.1 Core Deterministic Encoding**.

- **Allowed:** `null`, booleans, valid UTF-8 text strings (no unpaired
  surrogates), byte strings (`Uint8Array`), integers in JavaScript's safe range
  (`Number.MIN_SAFE_INTEGER`..`Number.MAX_SAFE_INTEGER`), definite-length arrays,
  and definite-length maps with unique text-string keys.
- **Forbidden:** floats (including `-0`), `bigint` / bignum tags, any CBOR tags,
  indefinite-length collections/strings, `undefined`, non-standard simple values,
  and non-text map keys.
- **Decoder requirements:** reject unless input is exactly one complete CBOR
  item, every integer/length uses minimal encoding, map keys are unique and in
  canonical order, nesting depth is `<= 32`, and re-encoding produces the exact
  received bytes. Decoded maps use null prototypes and detached byte buffers.

---

## 2. Cryptographic Primitives & Framing

### Fixed-length byte fields

| Field | Bytes | Validation |
| --- | ---: | --- |
| Game identifier (`game_id`) | 16 | Exact length |
| Ed25519 identity public key (`pk_id`) | 32 | Strict RFC 8032 prime-subgroup point (no small-order points) |
| SHA-256 digest / DTLS fingerprint | 32 | Exact length |
| Ristretto255 point | 32 | RFC 9496 canonical encoding (opaque; no Edwards coordinates) |
| Ristretto255 scalar | 32 | Little-endian canonical integer `0 <= s < q` |
| Beacon / random secret | 32 | Exact length (raw bytes; not reduced mod `q`) |
| Ed25519 signature | 64 | Strict RFC 8032 / FIPS 186-5 verification (ZIP-215 disabled) |

Group order: `q = 2^252 + 27742317777372353535851937790883648493`.

- **Human identity fingerprints:** RFC 4648 uppercase unpadded base32 of the
  first 16 bytes of `SHA-256(pk_id)`, grouped in 4-character blocks (final
  group of 2).
- **Randomness:** exclusively from `crypto.getRandomValues` via an injectable
  boundary. Uniform integers in `[0, n)` (`1 <= n <= 2^32`) use 32-bit
  little-endian rejection sampling (`limit = 2^32 - (2^32 mod n)`). Random
  permutations use descending Fisher–Yates. Fresh secret scalars mask 253 bits
  and reject `0` and values `>= q`.

### Domain separators & hash inputs

Domain separators are exact ASCII bytes with no terminator:

| Purpose | ASCII domain separator |
| --- | --- |
| Signaling room | `p2pcards/v1/room` |
| Channel auth (`HELLO`) | `p2pcards/v1/chan` |
| Envelope signature | `p2pcards/v1/msg` |
| Card derivation | `p2pcards/v1/card` |
| Key proof of possession | `p2pcards/v1/pop` |
| Decryption-share DLEQ | `p2pcards/v1/dleq` |
| Shuffle proof challenges | `p2pcards/v1/shuffle` |
| Randomness beacon | `p2pcards/v1/beacon` |

Exact hash/signing layouts (every `cbor(...)` item is self-delimiting Core
Deterministic CBOR):

```text
room_id           = SHA-256(room_ds || game_id[16])
channel_input     = chan_ds || game_id[16] || local_fp[32] || remote_fp[32]
message_input     = msg_ds || cbor(unsigned_envelope)
envelope_hash     = SHA-256(cbor(signed_envelope))

card_hash         = SHA-512(card_ds || cbor(deck_spec_id) || cbor(card_id))
card_point        = ristretto255_from_uniform_bytes(card_hash)

beacon_commitment = SHA-256(
  beacon_ds || game_id[16] || cbor(round) || cbor(seat) || secret[32]
)

proof_challenge   = LE512_TO_INT(SHA-512(
  proof_ds || game_id[16] || cbor(round) || cbor(phase) || cbor(statement)
)) mod q
```

---

## 3. Signed Envelopes & Sender Chains

Every protocol message after `HELLO` is a deterministic CBOR map with **exactly**
ten fields (no extensions):

| Field | Constraint |
| --- | --- |
| `v` | Integer `1` |
| `game` | 16-byte `game_id` |
| `from` | 32-byte Ed25519 `pk_id` |
| `seq` | Unsigned safe integer (starts at `0`) |
| `prev` | 32-byte `envelope_hash` of `seq - 1` (32 zero bytes for `seq = 0`) |
| `round` | Unsigned safe integer |
| `phase` | Non-empty text string |
| `type` | Closed v1 envelope type catalogue (`HELLO` is not an envelope) |
| `body` | Valid deterministic CBOR value matching `type` |
| `sig` | 64-byte Ed25519 signature over `message_input` |

### Per-sender chains & canonical order

- Each roster identity maintains one hash chain starting at `seq = 0`,
  `prev = 0x00 * 32`.
- Ingestion classifies each artifact without mutating state first: `accepted`,
  `duplicate` (byte-identical at an existing `seq`), `equivocation` (different
  validly signed envelope at an existing `seq`), `gap`, `broken_prev`, or
  `wrong_sender`.
- **Canonical signed-envelope order** (for deterministic inspection/export,
  independent of local arrival order): group by sender, validate each chain
  from `0`, sort sender groups by ascending lexicographic `pk_id` bytes, and
  emit each chain by ascending `seq`. This is serialization order, not semantic
  replay order.

---

## 4. Message Bodies

### Lobby (`round: 0`, `phase: "lobby"`)

- **`JOIN`:** `{pk_id, rules_hash, client_version}`. Must be the joiner's
  `seq = 0` genesis with `pk_id == from` and matching `rules_hash`. Accepted
  only by explicit host admission (for the host) or when the current valid host
  `ROSTER` names the sender (for peers).
- **`ROSTER`:** `{game_id, rules_hash, ice_config_hash, seats}`. Signed only by
  the invitation host; `seats` has 1–8 unique valid Ed25519 keys including the
  host (finalized sessions require 3–8 seats). `ice_config_hash` mismatch is a
  diagnostic warning, not a security failure.
  ```text
  roster_hash = SHA-256(cbor(ROSTER body))
  ```
- **`READY`:** `{roster_hash}`. Requires `>= 3` seats in the current roster and
  a bootstrapped sender chain. Votes are tracked per `(roster_hash, sender)`.
  Once every seat in the current roster is ready for the same `roster_hash`, all
  complete lobby chains replay in seat order into the established session
  registry (continuing the same `seq`/`prev` chains) and host authority ends.

### Setup & deck cryptography

- **Deck specs:** non-empty ID and 2–128 unique non-empty card IDs; initial
  public deck is `[(O, M_0), ..., (O, M_{D-1})]`.
- **ElGamal masking:** `(A, B) = (r*G, M + r*H)`; remasking adds `(r'*G, r'*H)`.
  Fresh randomizers, individual keys, and aggregate key `H = sum(H_i)` must be
  non-zero / non-identity. An identity aggregate key terminates setup as a
  collective failure (no single seat is blamed).
- **`KEY_SHARE`** (`phase: "setup.keys"`): `{H_i, pop: {R, z}}`. Schnorr PoP
  statement `{H, R}` under `p2pcards/v1/pop`; verifies `z*G = R + c*H`.
- **`RAND_COMMIT`** (`phase: "setup.rand"`): `{cm}` (32-byte `beacon_commitment`).
  Accepted only after aggregate-key completion.
- **`RAND_REVEAL`** (`phase: "setup.rand"`): `{s}` (32-byte preimage). Accepted
  only after all seats commit; `seed = SHA-256(s_0 || ... || s_{N-1})`.
  *(Note: `sasku-match-candidate@4` uses key-only setup and omits `setup.rand`.)*
- **`SHUFFLE`** (`phase: "round.<r>.shuffle.<i>"`): `{outputDeck, proof}`.
  `outputDeck` is one byte string of `m*n` ordered 64-byte `A || B` point pairs.
  `proof` is a v2 Bayer–Groth proof for the agreed matrix. The prover and
  verifier reconstruct the statement from the envelope scope, finalized
  roster, setup key, and preceding verified deck. Sasku uses 4×9.
  See [shuffle.md](shuffle.md).
- **`SHARES`** (`phase: "round.<r>.deal.<k>"`): `{to, items}` where `to` is
  `0..7` and `items` contains 1–128 unique-position `{pos, S, R1, R2, z}` items
  (`pos` in `0..127`). Each item's Chaum–Pedersen DLEQ statement is
  `{pos, H, A, S, R1, R2}` under `p2pcards/v1/dleq` bound to the carrying
  `{gameId, round, phase}`, verifying `z*G = R1 + c*H` and `z*A = R2 + c*S`.
  In `sasku-match-candidate@4`, `to: 4` denotes the four-seat all-other-positions
  donor batch in `round.<r>.deal.0` (27 ascending positions).
- **`ACTION`** (`phase: "round.<r>.play.<t>"`): `{kind, data, reveal, shares}`.
  `kind` is non-empty text (`<= 64` bytes); `reveal` has 0–128 unique positions
  matching `shares` in exact order. Proofs use the carrying action phase;
  `t` is the zero-based accepted action counter (not `seq`).
- **`AUDIT_DISCLOSE`** (`phase: "round.<r>.audit"`): `{items}` (0–128 unique
  positions). Empty `{items: []}` is valid when all dealt cards were already
  opened publicly.

### Authenticated channel control

After reciprocal `HELLO`, a control payload is prefixed with byte `0x03` and
encoded as a canonical CBOR map with `type` and `body`. Sync requests and
responses also carry a channel-local unsigned integer `id`. The DTLS channel
authenticates the sending peer. Control payloads allocate no sequence numbers
and are omitted from the transcript.

- **`HEADS`** carries `{heads}` or `{heads, state_hash}`. Up to eight unique
  `{from, seq, hash}` entries advertise signed history held by that peer,
  including history from other roster members. The browser sends heads on
  authentication, on roster changes by the host, and every five seconds.
- **`SYNC_REQ`** carries `{from, from_seq, to_seq}` with inclusive bounds.
  The browser requests one original at a time per author and serving peer.
- **`SYNC_RESP`** echoes the request ID and carries `{envelopes}`, with complete
  nested signed envelope maps. A null body means the requested original is
  unavailable. The receiver matches the response to an outstanding request,
  verifies the original author's signature, game, sequence, and any advertised
  hash, then validates the original chain and semantics before admitting it.
  Any connected roster peer holding the original can serve it.
- **`ABORT_VOTE`** carries `{missing, ended}`, a four-seat bitmask of disconnected
  players. At least two players must be connected. The table ends without a
  new score when every connected player explicitly votes for the same
  nonempty missing-seat mask. A topology change clears pending votes locally.
  Observers save a completed vote outcome locally. A returning seat learns the
  outcome when every voter independently confirms it with `ended: true`.

Initial catch-up gates the local driver on the authenticated channel generation.
Subsequent live envelopes travel over ordered, reliable SCTP without per-envelope
acknowledgements. Everyone at a table must use a browser build that supports
these channel messages. Periodic heads can expose a missing or conflicting original
without pausing live play.

### Equivocation certificate

A conflicting head is a hint to request the signed original at that sequence.
If the advertised branch is ahead and its first missing original does not
extend the local head, the receiver requests that original's predecessor at
the known sequence to confirm the conflicting history.

**`VIOLATION`** is a signed envelope in round `0`, phase
`"control.equivocation"`. Its body is
`{seat, reason: "equivocation", evidence: [env1, env2]}`. Both items are complete
nested signed envelopes for the same `(game, from, seq)` with different hashes,
sorted in ascending lexicographic hash order. The seat must match the original
author in the finalized roster. Verified evidence ends the table and identifies
the equivocating player. Other game faults are checked directly against the
offending signed envelope.

---

## 5. Invitations, Signaling & WebRTC Transport

### Invitation URLs

Invitations encode four fragment parameters in order (`<= 4,096` chars, no URL
credentials):

```text
https://<host>/<path>#g=<game_id_hex32>&h=<host_pk_hex64>&r=<rules_id>@<ver>&s=trystero-nostr
```

The current browser profile requires `r=sasku-match-candidate@4` and
`s=trystero-nostr`. Fragment parameters never leave the browser in HTTP requests.

### Signaling messages & Nostr adapter

Signaling carries Core Deterministic CBOR (`<= 257 KiB` per message):

- SDP description: `{kind: "description", description_type: "offer" | "answer", sdp}` (`sdp <= 256 KiB`)
- ICE candidate: `{kind: "candidate", candidate, sdp_mid, sdp_mline_index, username_fragment}` (`candidate <= 4 KiB`, nullable fields; all-null = end-of-candidates)

`TrysteroNostrSignalingAdapter` uses pinned Trystero `0.25.4` (`createEvent` and
default relay list only—never `joinRoom`/`makeAction`, so `FullMeshTransport`
keeps full ownership of peer connections and `HELLO`):

```text
context = cbor({app_id, room_id})                  // default app_id: "p2pcards/v1"
topic   = lowerhex(SHA-256("p2pcards/v1/nostr-signal/topic" || context))
key     = SHA-256("p2pcards/v1/nostr-signal/key" || context)
aad     = SHA-256("p2pcards/v1/nostr-signal/aad" || cbor({app_id, room_id, topic}))
```

- Plaintext of each fragment is `cbor({from, to, frame})` using the 16 KiB
  frame schema below.
- Nostr event `content` is unpadded base64url of
  `0x01 || nonce[12] || AES-256-GCM(key, nonce, plaintext, aad) || tag[16]`.
- Ephemeral event kind is `20000 + (sum(ASCII(topic)) mod 10000)` with tag
  `["x", topic]`. Subscription ID is the first 32 hex chars of
  `SHA-256("p2pcards/v1/nostr-signal/subscription" || cbor({topic, self}))`.
- Relay URLs require `wss://` (except loopback `ws://`), no credentials/query/fragment,
  `<= 2,048` bytes each. Up to 5 relays are selected deterministically by
  sorting ascending on `lowerhex(SHA-256("p2pcards/v1/nostr-signal/relay" || cbor({topic, url})))`.
- Operational defaults: 10 s EOSE startup deadline, 5,333 ms publish ACK
  timeout, 30 s recent-event replay window (128-event cap), 32 KiB max WS frame,
  24 KiB max content, 16 concurrent sends, 30 s reassembly expiry.
- Room-key encryption is signaling hygiene only; relay `OK`s are not peer
  receipts and do not authenticate identities.

### Full mesh, framing & `HELLO` authentication

- One `RTCPeerConnection` per peer pair (`iceTransportPolicy: "all"`,
  `bundlePolicy: "max-bundle"`, STUN required, TURN optional). Lexicographically
  smaller `pk_id` is impolite; larger is polite (perfect negotiation).
- One externally negotiated `RTCDataChannel`: label `p2pcards`, `id: 0`,
  `ordered: true`, fully reliable.
- **Frames:** deterministic CBOR `{id: uint32, index: uint16, count: uint16, bytes: bstr(<= 16 KiB)}`
  (`count >= 1`, `index < count`, non-empty chunks when `count > 1`). Defaults:
  8 MiB / 512 frames per message, 64 pending groups, 16 MiB pending bytes, 30 s
  expiry from first chunk; outbound backpressure pauses above 4 MiB and resumes
  at 2 MiB.
- **`HELLO`** (not an envelope, `<= 256` bytes, reserved **frame ID `0`**,
  `index: 0`, `count: 1`):
  ```text
  {pk_id, local_fp, remote_fp, sig}
  ```
  where `sig` signs `channel_input` from the sender's viewpoint (`local_fp` =
  sender's SDP `sha-256` DTLS fingerprint, `remote_fp` = peer's observed
  fingerprint). Application frame IDs start at `1`. Any pre-auth payload,
  fingerprint mismatch, wrong identity/game, or 30 s auth timeout closes the
  channel.
- **Per-peer lifecycle & readiness gate:**
  `connecting -> authenticating -> synchronizing -> ready` (local generation
  counter isolates reconnects/restarts; stale callbacks cannot unlock a
  replacement). `AuthenticatedMeshTransport` requires an explicit session
  `synchronizePeer(context)` barrier (default 30 s timeout, 64 messages / 8 MiB
  queue) before unlocking ordinary application send/receive.
- **ICE path diagnostics:** `connectionPath(remote)` reports `direct`,
  `relayed`, or `unknown` from `getStats()` without exposing addresses or TURN
  credentials.

---

## 6. Local Storage & Recovery Invariants

IndexedDB database **`p2pcards`** (schema version 1):

| Object store | Key / index | Contents & invariants |
| --- | --- | --- |
| `identity` | `"self"` | `{version: 1, secretKey[32], publicKey[32]}`. Raw 32-byte Ed25519 seed protected by strict CSP (non-extractable WebCrypto key storage is not required; see [decisions.md](decisions.md#d7--keep-raw-ed25519-identity-seeds-in-indexeddb-with-strict-csp)). Atomic get-or-create; corrupt records fail closed and are never silently regenerated. |
| `games` | `game_id` | Per-game ElGamal secret scalar (`32` canonical LE bytes, persisted before `KEY_SHARE`), monotonic `lobbyRoster` snapshot, and optional `setupBeaconSecret` (`{version: 1, round, sender, roster, secret}`). No plaintext hands are stored. |
| `transcripts` | auto-inc arrival key; unique `(game, sender, seq)` | Canonical signed envelope bytes + `authored` flag. Exact duplicates are idempotent; equal-sequence conflicts preserve the first record and surface both for equivocation. Arrival order is diagnostic only. |
| `authored_heads` | `(game, sender)` | Atomic sequence-allocation checkpoint updated in the same transaction as appending to `transcripts`. Verified against the sender's last indexed row and count before signing. |

### Core durability rules

1. **Persist before broadcast:** authored envelopes and private secrets (game
   key, beacon preimage) commit to IndexedDB before becoming visible to the
   network.
2. **Never re-sign on retry or failure:** uncertain appends or disconnects
   require recovering and replaying original signed bytes (e.g., via
   `replayAuthoredHistory`), never generating a replacement signature at the
   same sequence.
3. **Validate before commit, commit before memory mutation:** incoming messages
   pass signature, chain, proof, and public-rule checks before persistence;
   in-memory state advances only after durable receipt succeeds.
4. **Reload recovery (current `main` vs. target `#3`):** On `main`, recovery
   re-checks signatures, sender chains, setup, and shuffle proofs from original
   stored bytes rather than trusting cached flags or arrival order. Web Locks
   prevent concurrent tabs with the same identity from writing the same table.
5. **Trusted local reload checkpoints (planned in `#3`):** `games` does not yet
   store a phase snapshot on `main`; `#3` adds a derived local reload checkpoint
   keyed by the four `(seat, seq, hash)` transcript heads so page reloads
   restore immediately while retaining the full signed transcript in
   `transcripts` for peer sync and on-demand full re-verification. Exported
   offline transcripts (`#8`) omit transport-layer `HELLO` messages and contain
   `{version, rules_hash, roster, envelopes}` in canonical order.
