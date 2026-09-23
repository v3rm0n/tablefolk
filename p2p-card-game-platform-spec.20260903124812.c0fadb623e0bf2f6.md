# Peer-to-Peer Card Game Platform — Technical Specification

Version 0.1 (draft) · 2026-09-03

---

## 1. Purpose and scope

This document specifies a browser-based platform for multiplayer card games (3–8 players) that runs without a game server. Peers connect directly over WebRTC; the deck is shuffled and dealt with a cryptographic protocol so that no coalition of fewer than all players can learn a hidden card or bias the shuffle; every game action is signed and independently validated by every peer; and the whole game is captured in a transcript that any third party can verify offline.

The platform is game-agnostic. Concrete games (trick-taking, draw-and-discard, poker variants, etc.) are supplied as *rules modules* that plug into a common engine.

Key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in RFC 2119.

### 1.1 Goals

- **G1 — No trusted party.** No server, dealer, or player is trusted with the deck, the game state, or the rules.
- **G2 — Hidden-information secrecy.** No card is learned by anyone other than its intended recipient until it is deliberately revealed, even if all other players collude.
- **G3 — Fair shuffle.** The deck order is uniformly random and unknown to everyone as long as at least one player is honest.
- **G4 — Rule enforcement.** Every action is checked by every peer against the same deterministic rules; illegal actions are rejected and attributed to their author.
- **G5 — Verifiability.** A complete signed transcript allows any party to re-verify the game after the fact.
- **G6 — Connectivity.** Peers behind NAT connect using STUN, falling back to TURN when direct paths fail.
- **G7 — No backend.** The application is served as static files. The only third-party dependencies are signaling channels (which carry no game data) and optional TURN relays (which carry only DTLS-encrypted traffic).

### 1.2 Non-goals

- Collusion through side channels (voice call, chat). Players who share their hands out of band are indistinguishable from a single player.
- Abort resistance. A player can always disconnect. Aborts are detected, attributed and treated as forfeit; they are not prevented.
- Remote client integrity. The protocol is designed so that a modified client gains no advantage; it does not attempt to attest remote software.
- Availability of third-party signaling or TURN infrastructure.
- Matchmaking, ranking, spectators, cross-device persistence.

### 1.3 Threat model

The adversary:

- controls up to N−1 of the N players, including their clients and secret keys;
- fully controls the signaling channel and any TURN relay (read, modify, drop, replay, inject);
- may drop, delay or reorder messages on any link;
- is computationally bounded (DDH is assumed hard in the chosen group).

The honest player runs an unmodified client in a browser with a functioning CSPRNG on a device the adversary does not control.

---

## 2. Architecture

```
+-----------------------------------------------------------+
| Rules module      pure, deterministic game logic          |
+-----------------------------------------------------------+
| Game engine       phases, turn discipline, validation,    |
|                   deal scheduling, audit, results         |
+-----------------------------------------------------------+
| Deck protocol     ElGamal masking, verifiable shuffle,    |
|                   distributed reveal, randomness beacon   |
+-----------------------------------------------------------+
| Session layer     identity, signed envelopes, hash chain, |
|                   witness/equivocation, sync, transcript  |
+-----------------------------------------------------------+
| Transport         WebRTC full mesh, ICE (STUN/TURN),      |
|                   signaling adapters, channel auth,       |
|                   framing/chunking                        |
+-----------------------------------------------------------+
```

All layers run in the browser. Heavy cryptography SHOULD run in a Web Worker. The static bundle MAY be served from any static host (object storage, GitHub Pages, IPFS).

Design principle: **everything is public except secret keys.** All protocol messages, including decryption shares, are broadcast to every peer. There are no private channels in the protocol. Secrecy comes exclusively from the fact that revealing a card requires the recipient's own key.

---

## 3. Cryptographic primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Group 𝔾 | ristretto255 | Prime order q, generator G. Points encode to 32 bytes; invalid encodings MUST be rejected. |
| Hash-to-group | ristretto255 one-way map from 64 bytes | Used for card encodings; no party knows discrete logs of card points. |
| Hash | SHA-512 (challenges), SHA-256 (identifiers, commitments) | |
| Signatures | Ed25519 | Identity and message authentication. |
| Encryption of cards | Exponential ElGamal over 𝔾 under an aggregated key | Section 7. |
| Proofs | Schnorr PoK, Chaum–Pedersen DLEQ, ZK argument of correct shuffle | Non-interactive via Fiat–Shamir. |
| Commitments | SHA-256(nonce ‖ value) | Randomness beacon. Pedersen commitments inside shuffle proofs. |
| Randomness | `crypto.getRandomValues` | The only permitted source of randomness. |
| Encoding | CBOR, deterministic (RFC 8949 §4.2.1) | Canonical bytes for hashing and signing. |

Recommended implementation: `@noble/curves` (ristretto255, Ed25519) and `@noble/hashes`. WebCrypto Ed25519 MAY be used for the identity key where available.

**Scalars** are 32-byte little-endian integers reduced mod q. **Fiat–Shamir challenges** are computed as `c = SHA-512(DS ‖ game_id ‖ round ‖ phase ‖ statement) mod q`, where `DS` is one of the domain-separation strings below and `statement` is the canonical CBOR of all public inputs of the proof.

| Domain string | Used for |
|---|---|
| `p2pcards/v1/room` | Signaling room id |
| `p2pcards/v1/chan` | Channel authentication |
| `p2pcards/v1/msg` | Envelope signatures |
| `p2pcards/v1/card` | Card point derivation |
| `p2pcards/v1/pop` | Key proof of possession |
| `p2pcards/v1/dleq` | Decryption share proofs |
| `p2pcards/v1/shuffle` | Shuffle proof challenges |
| `p2pcards/v1/beacon` | Randomness beacon commitments |

---

## 4. Identity, invitations and lobby

### 4.1 Identity

Each client holds a long-lived Ed25519 identity keypair `(sk_id, pk_id)` in IndexedDB. `pk_id` is the player's identity throughout the protocol. The human-readable fingerprint is the first 16 bytes of `SHA-256(pk_id)` in base32.

### 4.2 Game identifier and invitation

The host generates `game_id` = 16 random bytes and shares an invitation out of band:

```
https://<static-host>/#g=<game_id>&h=<host pk_id>&r=<rules id>@<rules version>&s=<signaling strategy>
```

Possession of the link is the admission credential. The signaling room name is `hex(SHA-256("p2pcards/v1/room" ‖ game_id))`, so the room name reveals nothing about the game.

### 4.3 Lobby

1. Joiners connect to the host (Section 5) and send `JOIN {pk_id, rules_hash, client_version}`.
2. The host maintains a roster and broadcasts `ROSTER` on every change: `{game_id, rules_hash, ice_config_hash, seats: [pk_id, ...]}`. Seat index = position in `seats`.
3. Joiners establish connections to every other roster member (full mesh).
4. When the roster is complete, each player sends `READY {roster_hash}` where `roster_hash = SHA-256(canonical(ROSTER))`.
5. The game starts when every seat has sent `READY` for the same `roster_hash`.

The host's authority ends here. From `READY` onward the host is an ordinary seat. `rules_hash` is the SHA-256 of the rules module bundle; peers MUST refuse to start if it differs from their own.

---

## 5. Transport

### 5.1 Peer connections

One `RTCPeerConnection` per pair of players. For each pair, the peer with the lexicographically smaller `pk_id` is the impolite peer in the perfect-negotiation pattern; the other is polite. Trickle ICE MUST be used.

### 5.2 ICE configuration

```json
{
  "iceServers": [
    { "urls": ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"] },
    { "urls": ["turn:turn.example.net:3478?transport=udp",
               "turns:turn.example.net:5349?transport=tcp"],
      "username": "...", "credential": "..." }
  ],
  "iceTransportPolicy": "all",
  "bundlePolicy": "max-bundle"
}
```

- STUN servers MUST be configured. TURN servers SHOULD be configured; without TURN, peers behind symmetric NATs may fail to connect.
- TURN configuration ships in the static bundle. Because TURN relays only ever see DTLS-encrypted SCTP, a compromised or malicious relay cannot read or alter game traffic; the credential protects the operator's bandwidth, not the game. Operators MAY use a TURN provider with ephemeral credentials (RFC 8489/8656 with time-limited HMAC credentials) minted by a serverless function; this function is outside the trust boundary.
- The UI SHOULD show when a connection is relayed (`RTCIceCandidatePairStats.localCandidateId` → `candidateType == "relay"`).
- `ice_config_hash` in the roster lets peers detect mismatched configurations; it does not affect security.

### 5.3 Signaling adapters

Signaling carries only SDP and ICE candidates. It is untrusted. The adapter interface:

```ts
interface SignalingAdapter {
  join(roomId: string, self: Uint8Array): Promise<void>
  send(to: Uint8Array, payload: Uint8Array): Promise<void>
  onMessage(cb: (from: Uint8Array, payload: Uint8Array) => void): void
  leave(): Promise<void>
}
```

Required adapters:

| Adapter | Mechanism | Dependency |
|---|---|---|
| `trystero-nostr` (default) | Public Nostr relays via Trystero | Public infrastructure |
| `trystero-torrent` | BitTorrent trackers via Trystero | Public infrastructure |
| `trystero-mqtt` | Public MQTT brokers via Trystero | Public infrastructure |
| `manual` | Copy/paste or QR code exchange of compressed SDP | None |

Signaling payloads SHOULD be encrypted with a key derived from `game_id` so that room contents are opaque to the relay; this is hygiene, not a security requirement, because Section 5.4 defeats an active signaling adversary.

### 5.4 Channel authentication

WebRTC secures the channel with DTLS, but an attacker on the signaling path can substitute certificate fingerprints and sit in the middle. To bind the DTLS session to the identity key, the first message on every data channel MUST be:

```
HELLO {
  pk_id,
  local_fp:  SHA-256 fingerprint of own DTLS certificate,
  remote_fp: SHA-256 fingerprint observed for the peer,
  sig: Ed25519(sk_id, "p2pcards/v1/chan" ‖ game_id ‖ local_fp ‖ remote_fp)
}
```

The receiver MUST verify that `sig` is valid for `pk_id`, that `remote_fp` equals the fingerprint of its own certificate, and that `local_fp` equals the fingerprint it observed for the remote (from the remote SDP `a=fingerprint` or `RTCPeerConnection.getStats()`). Any mismatch MUST close the connection. No other message is accepted before a valid `HELLO`.

### 5.5 Data channels and framing

One `RTCDataChannel` per pair, label `p2pcards`, `ordered: true`, no `maxRetransmits`/`maxPacketLifeTime` (fully reliable). Each channel message is a frame:

```
Frame { id: uint32, index: uint16, count: uint16, bytes: bstr }
```

Payloads are split into frames of at most 16 KiB. Receivers reassemble by `id` and discard incomplete groups after 30 s.

### 5.6 Reconnection

The transcript is deterministic and locally persisted (Section 12), so a dropped peer can rejoin by re-entering the signaling room with the same `pk_id`, completing `HELLO` and running `SYNC_REQ` (Section 6.6). Peers MUST accept a reconnecting `pk_id` that appears in the roster. Reconnection must complete within the active timeout (Section 8.5), otherwise the seat forfeits.

---

## 6. Session layer: envelopes and transcript

### 6.1 Envelope

Every protocol message after `HELLO` is an envelope:

```
Envelope {
  v:     1,
  game:  bstr(16)   game_id,
  from:  bstr(32)   sender pk_id,
  seq:   uint       per-sender counter starting at 0,
  prev:  bstr(32)   hash of the sender's previous envelope (32 zero bytes for seq 0),
  round: uint,
  phase: tstr,
  type:  tstr       message type (Section 10),
  body:  any,
  sig:   bstr(64)
}
```

### 6.2 Canonical encoding and signing

`sig = Ed25519(sk_id, "p2pcards/v1/msg" ‖ canonical_cbor(envelope without sig))`.
`hash(envelope) = SHA-256(canonical_cbor(envelope with sig))`.

Receivers MUST reject envelopes with invalid signatures, an unknown `from`, a `game` mismatch, or a non-canonical encoding.

### 6.3 Per-sender hash chain

Each sender's envelopes form a chain via `(seq, prev)`. Receivers MUST reject an envelope whose `seq` is not exactly one greater than the last accepted envelope from that sender, or whose `prev` does not match the hash of that envelope. Out-of-order arrival is impossible on a reliable ordered channel; a gap therefore indicates equivocation or a bug and is treated as a protocol violation.

### 6.4 Broadcast

Every envelope is sent by its author to all N−1 peers. There is no relaying of envelopes in normal operation.

### 6.5 Witnesses and equivocation detection

A sender could send different envelopes with the same `seq` to different peers. To detect this, every peer broadcasts `WITNESS { heads: [{from, seq, hash}] }` listing the latest accepted envelope from every sender, after each of its own envelopes and at least every 5 s while idle.

On receiving a `WITNESS` whose `(from, seq, hash)` conflicts with its own view for the same `(from, seq)`, a peer sends `SYNC_REQ` for that envelope. If it obtains two validly signed envelopes with equal `(from, seq)` and different hashes, it broadcasts `VIOLATION { seat, reason: "equivocation", evidence: [env1, env2] }`. Equivocation evidence is self-certifying and ends the game with the equivocating seat forfeiting.

### 6.6 Sync

`SYNC_REQ { from, from_seq, to_seq }` requests a range of one sender's envelopes; `SYNC_RESP { envelopes }` returns them. Responses are verified by signature and chain, so any peer may serve them. Used for reconnection and equivocation resolution.

### 6.7 Transcript

The transcript is the set of all accepted envelopes plus `HELLO` and `ROSTER`. It is sufficient to re-run every verification in this specification offline. Clients MUST persist it locally and SHOULD offer export as a single CBOR file.

---

## 7. Deck protocol

The deck protocol follows the Barnett–Smart construction: cards are ElGamal-masked under a key jointly controlled by all players, shuffled in turn with zero-knowledge proofs, and revealed by combining per-player decryption shares.

### 7.1 Notation

- 𝔾, q, G as in Section 3. O is the identity point.
- N players, seats 0..N−1. Player i has game secret `x_i` and public `H_i = x_i·G`.
- Aggregate key `H = Σ H_i`.
- A masked card is a pair `(A, B)` ∈ 𝔾².
- The deck has D positions 0..D−1.

### 7.2 Game keys

In phase `setup.keys`, each seat generates a fresh `x_i` and broadcasts

```
KEY_SHARE { H_i, pop: { R, z } }
```

where `k ← Z_q`, `R = k·G`, `c = FS("p2pcards/v1/pop", H_i, R)`, `z = k + c·x_i`. Verifiers check `z·G = R + c·H_i`. The proof of possession prevents rogue-key attacks on the aggregate. `x_i` MUST be generated fresh per game and MUST be persisted locally until the game ends.

### 7.3 Card encoding

The rules module's `DeckSpec` lists D card identifiers `id_0..id_{D−1}` (e.g. `"S:A"`, `"H:10"`, `"JOKER:1"`). The card point is

```
M_c = HashToGroup(SHA-512("p2pcards/v1/card" ‖ deck_spec_id ‖ id_c))
```

Every peer computes the lookup table `M_c → id_c`. Because card points come from a hash, no party knows their discrete logarithms, which is required for the shuffle proof's soundness against forged cards.

### 7.4 Masked cards and the initial deck

An ElGamal masking of `M` with randomness `r` is `(A, B) = (r·G, M + r·H)`. Re-masking with `r'` maps `(A, B) → (A + r'·G, B + r'·H)` and preserves the plaintext.

The initial deck is the public list `[(O, M_0), (O, M_1), …, (O, M_{D−1})]`. It requires no proof.

### 7.5 Shuffle

Seats shuffle sequentially in seat order, phases `round.<r>.shuffle.<i>`. Seat i takes the current deck `[(A_j, B_j)]`, picks a uniformly random permutation π and fresh randomizers `r_j`, and outputs

```
(A'_j, B'_j) = (A_{π(j)} + r_j·G,  B_{π(j)} + r_j·H)
```

broadcast as `SHUFFLE { deck: [(A', B')], proof }`. Every peer verifies `proof` against `(H, deck_in, deck_out)` before accepting. After all N shuffles the deck is fixed for the round.

A shuffle whose proof fails is a violation by that seat.

### 7.6 Shuffle proof

The proof is a non-interactive zero-knowledge argument that `deck_out` is a permutation and re-masking of `deck_in` under `H`.

**Normative proof system:** Bayer–Groth (Eurocrypt 2012) argument of correct shuffle for ElGamal ciphertexts, instantiated with Pedersen commitments over 𝔾 and Fiat–Shamir challenges under `p2pcards/v1/shuffle`. It requires `D = m·n` with `m, n ≥ 2`; all standard decks satisfy this (24 = 4·6, 32 = 4·8, 36 = 4·9, 52 = 4·13, 54 = 6·9, 104 = 8·13). Proof size is O(√D) group elements; proving and verification are O(D) scalar multiplications.

**Permitted alternative:** a cut-and-choose Σ-protocol with λ repetitions. The prover generates λ independent random shuffles `E_k` of `deck_in`; the challenge bits `b_k = FS(...)` select, for each k, whether to open `deck_in → E_k` or `E_k → deck_out` (permutation and randomizers). Soundness error is 2^−λ; λ MUST be ≥ 40. Proof size is about `λ·D·97` bytes (≈ 200 KB for D = 52), verification costs `2·λ·D` scalar multiplications. This variant exists to make a correct first implementation feasible; implementations SHOULD migrate to Bayer–Groth.

Both systems are zero-knowledge, so a shuffle proof reveals nothing about π or the `r_j`.

### 7.7 Reveal to one seat (deal and draw)

To reveal position j to seat p, every seat i ≠ p broadcasts a decryption share with a Chaum–Pedersen proof:

```
S_{i,j} = x_i·A_j
proof: k ← Z_q, R1 = k·G, R2 = k·A_j,
       c = FS("p2pcards/v1/dleq", round, j, H_i, A_j, S_{i,j}, R1, R2),
       z = k + c·x_i
```

Verifiers check `z·G = R1 + c·H_i` and `z·A_j = R2 + c·S_{i,j}`. Shares for all positions due in a phase are batched into a single `SHARES { to: p, items: [{pos, S, R1, R2, z}] }` envelope per sender. All peers verify all shares, not just the recipient.

Seat p then computes `M = B_j − Σ_{i≠p} S_{i,j} − x_p·A_j` and looks up `id_c`. Because every input was verified, the lookup cannot fail for an honest p; a failure indicates a bug, not an attack.

Which positions are revealed to whom is fixed by the engine's deterministic deal schedule (Section 8.4). A seat that publishes shares for a position not scheduled to it, or fails to publish scheduled shares within the timeout, commits a violation.

### 7.8 Reveal to all (playing a card)

Seat p plays the card at position j by including j in `ACTION.reveal` and attaching its own share `S_{p,j}` with proof. Every peer now has all N shares and computes `M = B_j − Σ_i S_{i,j}`, obtaining `id_c`. The engine passes `{j: id_c}` to the rules module for validation.

Peers MUST check that j was scheduled to p and has not been revealed before. This guarantees that a player can only play cards actually dealt to them.

A position never dealt to anyone (e.g. turning the top of the stock face up) is revealed to all by the engine scheduling `{to: "all", count}`: every seat publishes its share for that position.

### 7.9 Re-shuffling a subset

Rules that return cards to the deck (discards reshuffled into the stock) are handled by the engine building a sub-deck from the affected positions: for still-masked positions the current `(A, B)` is used; for publicly revealed cards the fresh public masking `(O, M_c)` is used. The sub-deck is shuffled by all seats as in 7.5 and appended as new positions. Old positions become dead.

### 7.10 Randomness beacon

For randomness other than the deck order (initial dealer, seat rotation, dice), the engine runs a commit–reveal beacon:

1. `RAND_COMMIT { cm = SHA-256("p2pcards/v1/beacon" ‖ game_id ‖ round ‖ seat ‖ s) }`, with `s` = 32 random bytes, from every seat.
2. After all commitments are received, `RAND_REVEAL { s }` from every seat.
3. `seed = SHA-256(s_0 ‖ s_1 ‖ … ‖ s_{N−1})`.

A reveal that does not match its commitment, or a missing reveal, is a violation by that seat. The seed is unpredictable and unbiasable if at least one seat is honest, because the last revealer can only choose to abort, not to alter the outcome.

### 7.11 Cost estimates

Per-operation costs, with `mul` = one scalar multiplication in 𝔾 (≈ 0.3–1 ms in JavaScript on current desktop hardware; to be measured):

| Operation | Prover | Each verifier |
|---|---|---|
| Re-mask deck (D cards) | 2·D mul | — |
| Bayer–Groth proof | ~10·D mul | ~6·D mul |
| Cut-and-choose proof, λ = 40 | 2·λ·D mul | 2·λ·D mul |
| Deal share (per position, per sender) | 2 mul | 4 mul |
| Deal of full 52-card deck, N = 4 | 156 mul per sender | 624 mul |

A complete round setup (N shuffles with proofs plus a full deal) for N = 4 and D = 52 is expected to take 5–20 s of wall time depending on the proof system. All of this MUST run off the main thread.

---

## 8. Game engine

### 8.1 Phases and expected senders

The engine is a state machine whose phases have a fixed set of expected senders. An envelope whose `type` is a game message and whose `from` is not an expected sender for the current phase, or whose `round`/`phase` do not match, is a violation. Housekeeping types (`WITNESS`, `SYNC_*`, `TIMEOUT_VOTE`, `VIOLATION`) are accepted in any phase.

| Phase | Expected senders | Messages |
|---|---|---|
| `setup.keys` | all | `KEY_SHARE` |
| `setup.rand` | all, then all | `RAND_COMMIT`, `RAND_REVEAL` |
| `round.r.shuffle.i` | seat i | `SHUFFLE` |
| `round.r.deal.k` | all seats except recipient(s) | `SHARES` |
| `round.r.play.t` | rules-defined (one seat or all) | `ACTION` |
| `round.r.audit` | all | `AUDIT_DISCLOSE` |
| `end` | — | — |

When `expected()` returns `"all"` (simultaneous actions such as bids or passes), the phase completes when one `ACTION` from every listed seat has been accepted; order within the phase is irrelevant.

### 8.2 Deterministic reducer

Public game state is a value produced by `rules.apply(state, action, revealed)`. All peers hold identical state after each accepted envelope. Rules modules MUST be pure and deterministic: integer arithmetic only, no `Math.random`, no `Date`, no dependence on object key order, no floating point. The engine MAY compute `SHA-256(canonical(state))` after each transition and include it in `WITNESS` to detect divergence early.

### 8.3 Public and audit constraints

Rules split into two classes:

- **Public constraints** depend only on public state and the cards being revealed in this action (turn order, legal bid, a played card being of the right type). The engine enforces them immediately via `rules.validate`; a failing action is a violation.
- **Audit constraints** depend on the actor's hidden hand ("must follow suit if able", "must not have held a joker while claiming none"). These are enforced at round end by `rules.audit` after mandatory disclosure (8.4 step 5).

The rules module declares audit constraints by implementing `audit`. Games whose legality is entirely public (most poker variants) return an empty `audit` and skip disclosure of unrevealed hands.

### 8.4 Round lifecycle

1. **Shuffle** — N sequential `SHUFFLE` phases (7.5).
2. **Initial deal** — the engine calls `rules.schedule(state)` and assigns stock positions in ascending order to the returned deal steps; peers publish `SHARES` (7.7). Stock = positions not yet assigned.
3. **Play** — repeat: `rules.expected(state)` names the acting seat(s); accepted `ACTION`s are applied; after each action `rules.schedule(state)` may return further deal steps (draws, community cards), which the engine executes before the next action.
4. **End** — when `rules.finished(state)` is true, the engine enters `round.r.audit`.
5. **Audit disclosure** — if the rules module defines `audit`, every seat publishes `AUDIT_DISCLOSE { items }` containing its shares for every position dealt to it and not yet revealed. All hands become public. Every peer runs `rules.audit(transcript, hands)`. Any violation ends the game with the offending seat forfeiting.
6. **Score** — `rules.score(state)` is recorded; the engine proceeds to the next round or `end`.

Mandatory disclosure means that in games with audit constraints, unplayed cards become public at round end. Rules authors MUST be aware of this trade-off; for trick-taking games where all cards are played it is moot.

### 8.5 Timeouts and forfeit

Each phase has a deadline: `T_crypto` (default 120 s) for `SHUFFLE`, `SHARES`, `AUDIT_DISCLOSE`; `T_action` (default 60 s, overridable by the rules module) for `ACTION`, `RAND_*`. When a peer's deadline for seat p expires, it broadcasts `TIMEOUT_VOTE { seat: p, phase }`. When a peer has accepted `TIMEOUT_VOTE` for the same `(p, phase)` from every seat other than p, seat p forfeits and the game ends. A message from p accepted before the vote completes cancels pending votes.

Timeouts are not synchronized across peers; the unanimity requirement among the other N−1 seats prevents a single peer from ejecting a slow but live player.

### 8.6 Violations and blame

A violation is any of: invalid proof, unscheduled or missing share, failed public constraint, failed audit constraint, equivocation, chain break, message from an unexpected sender, malformed envelope. All violation checks are deterministic over public data, so all honest peers reach the same verdict. On detecting one, a peer broadcasts `VIOLATION { seat, reason, evidence }` and stops accepting game messages. The game result is "forfeit by seat p". The transcript, including the evidence, is retained.

### 8.7 Results

At `end`, each client produces a `Result { roster_hash, rounds: [scores], outcome, transcript_hash }` and SHOULD offer the signed transcript for export. Because the transcript is self-verifying, any party can recompute the result.

---

## 9. Rules module interface

```ts
type Seat = number
type Position = number
type CardId = string

interface DeckSpec {
  id: string
  cards: CardId[]
}

interface Action {
  seat: Seat
  kind: string
  data: unknown
  reveal?: Position[]
}

interface DealStep {
  to: Seat | "all"
  count: number
}

interface Violation {
  seat: Seat
  rule: string
  at: number
}

interface RulesModule<S> {
  id: string
  version: string
  deck: DeckSpec
  seats: { min: number; max: number }
  timeouts?: { actionMs?: number }

  init(seatCount: number, seed: Uint8Array): S
  expected(state: S): { seats: Seat[] | "all"; phase: string } | null
  schedule(state: S): DealStep[]
  validate(state: S, action: Action, revealed: Record<Position, CardId>): boolean
  apply(state: S, action: Action, revealed: Record<Position, CardId>): S
  finished(state: S): boolean
  audit?(transcript: Transcript, hands: Record<Seat, Record<Position, CardId>>): Violation[]
  score(state: S): Record<Seat, number>
}
```

Contract:

- The engine owns all cryptography. Rules see card identifiers, never points or shares.
- `revealed` contains exactly the positions in `action.reveal`, already verified to belong to `action.seat` (or to be `"all"`-scheduled positions).
- `expected` returning `null` is equivalent to `finished` being true.
- `schedule` MUST be a pure function of state; the engine calls it after every transition.
- The rules bundle is content-addressed by `rules_hash`; any change to the module is a different game.

---

## 10. Message catalogue

| Type | Phase | Sender | Body |
|---|---|---|---|
| `HELLO` | connection | each side | Section 5.4 (not an envelope) |
| `JOIN` | lobby | joiner | `pk_id, rules_hash, client_version` |
| `ROSTER` | lobby | host | `game_id, rules_hash, ice_config_hash, seats[]` |
| `READY` | lobby | all | `roster_hash` |
| `KEY_SHARE` | `setup.keys` | all | `H_i, pop{R,z}` |
| `RAND_COMMIT` | `setup.rand`, rules-defined | all | `cm` |
| `RAND_REVEAL` | `setup.rand`, rules-defined | all | `s` |
| `SHUFFLE` | `round.r.shuffle.i` | seat i | `deck[], proof` |
| `SHARES` | `round.r.deal.k` | all except recipient | `to, items[{pos,S,R1,R2,z}]` |
| `ACTION` | `round.r.play.t` | expected seats | `kind, data, reveal[], shares[]` |
| `AUDIT_DISCLOSE` | `round.r.audit` | all | `items[{pos,S,R1,R2,z}]` |
| `WITNESS` | any | any | `heads[{from,seq,hash}], state_hash?` |
| `SYNC_REQ` | any | any | `from, from_seq, to_seq` |
| `SYNC_RESP` | any | any | `envelopes[]` |
| `TIMEOUT_VOTE` | any | any | `seat, phase` |
| `VIOLATION` | any | any | `seat, reason, evidence` |

All types except `HELLO` are carried in the envelope of Section 6.1.

---

## 11. Security properties

| Property | Mechanism | Holds against |
|---|---|---|
| Card secrecy: an unrevealed card is unknown to everyone but its recipient | ElGamal under aggregate key; decryption requires every seat's share, including the recipient's own | Any coalition not including the recipient (up to N−1 players), under DDH |
| Deck secrecy: the order of undealt positions is unknown | Same as above; stock positions have no shares published | Any coalition of up to N−1 |
| Shuffle fairness: final order is uniform | Each seat applies its own uniform permutation; ZK proof shows the output is a permutation | Any coalition of up to N−1, as long as one honest seat shuffles |
| Deal integrity: a seat learns only scheduled positions | Shares are published only per deterministic schedule; unscheduled shares are violations | Any coalition |
| Card authenticity: a played card is the card at the claimed dealt position | DLEQ proofs on all shares; hash lookup; position-ownership check | Any coalition |
| No forged cards | Card points are hash-derived; shuffle proof is sound | Computationally bounded adversary |
| Rule compliance | Deterministic validation by every peer; audit after disclosure | Any coalition |
| Non-repudiation and offline verifiability | Signed envelopes, per-sender hash chain, public shares and proofs | Any party |
| Equivocation detection | Witness heads and self-certifying evidence | Any sender |
| Signaling MITM resistance | DTLS fingerprints signed by identity keys | Active network adversary |

Explicitly not provided: prevention of aborts (only attribution), secrecy against a coalition that includes the recipient, protection against out-of-band collusion, resistance to traffic analysis or timing side channels.

---

## 12. Local storage

IndexedDB database `p2pcards`, stores:

| Store | Key | Value |
|---|---|---|
| `identity` | `"self"` | Ed25519 keypair (WebCrypto non-extractable where supported, else raw bytes) |
| `games` | `game_id` | `x_i`, roster, ICE config, phase snapshot, latest public state |
| `transcripts` | `game_id` | Accepted envelopes in arrival order |

`x_i` is the only secret whose loss is unrecoverable mid-game (the player could no longer decrypt their hand). Clients MUST write it before broadcasting `KEY_SHARE` and MAY delete it after `end`.

---

## 13. Compatibility and limits

- Browsers: current Chrome/Edge, Firefox, Safari (desktop and mobile). Required APIs: `RTCPeerConnection` with data channels, `BigInt`, IndexedDB, Web Workers, `crypto.getRandomValues`.
- Players: 3 ≤ N ≤ 8 (28 peer connections at N = 8). Larger N is out of scope for the full-mesh transport.
- Deck: 2 ≤ D ≤ 128, D composite when using Bayer–Groth.
- Envelope size: no fixed limit; frames are chunked at 16 KiB.
- Mobile browsers may suspend background tabs; clients SHOULD warn that the tab must stay in the foreground during crypto phases.

---

## 14. Verification and test plan

1. **Known-answer tests** for point/scalar encodings, card point derivation, PoP, DLEQ, and both shuffle proof systems, shared across implementations.
2. **Round-trip property tests**: shuffle by k random seats, deal every position to a random seat, reveal all; recovered card set equals the deck spec.
3. **Adversarial peer harness**: a scripted peer that (a) submits a bad shuffle proof, (b) publishes an unscheduled share, (c) plays a position it was not dealt, (d) equivocates, (e) breaks its hash chain, (f) withholds a reveal, (g) violates an audit constraint. Each MUST be detected by every honest peer with identical blame.
4. **Determinism**: replay recorded transcripts in Chrome, Firefox and Safari and compare per-step `state_hash`.
5. **Transport**: connection matrix across NAT types with and without TURN; reconnection mid-round within the timeout.
6. **Offline verifier**: a standalone tool that takes an exported transcript and reproduces the result or the violation, with no network access.

---

## 15. Future work

- Zero-knowledge proofs for audit constraints (e.g. proof that no card in a hidden hand matches a suit), removing mandatory disclosure.
- Threshold (t-of-N) decryption so a dropped player does not block the game, at the cost of weakening secrecy to coalitions of size t−1.
- Verified spectators consuming the public transcript in real time.
- Anchoring transcript hashes to an external timestamping service for cross-game reputation, without adding a trusted server.
