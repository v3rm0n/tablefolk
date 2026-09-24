# P2P Cards Protocol Profile

Status: draft implementation profile

This document makes byte-level choices that the main technical specification
leaves implicit. A profile change that alters encoded bytes is a protocol
version change once version 1 transcripts exist outside development fixtures.

## Deterministic CBOR Values

Protocol values use the Core Deterministic Encoding requirements from RFC 8949
section 4.2.1.

The version 1 implementation accepts only:

- `null` and booleans;
- well-formed Unicode text strings;
- byte strings represented in code as `Uint8Array`;
- integers in JavaScript's safe integer range;
- definite-length arrays containing protocol values; and
- definite-length maps with unique text-string keys and protocol values.

The following are not protocol values:

- floating-point values, including negative zero;
- integers outside `Number.MIN_SAFE_INTEGER` through `Number.MAX_SAFE_INTEGER`;
- CBOR bignum tags or JavaScript `bigint` values;
- CBOR tags of any kind;
- indefinite-length strings, arrays, or maps;
- `undefined` and non-standard CBOR simple values;
- maps with non-text keys;
- malformed Unicode strings containing unpaired surrogates; and
- application objects such as `Date`, class instances, typed arrays other than
  `Uint8Array`, functions, symbols, or cyclic structures.

Protocol schemas impose narrower unsigned ranges and fixed byte lengths on top
of this encoding profile. Cryptographic scalars and identifiers are byte
strings, not CBOR integers.

## Decoder Requirements

A decoder must reject an input unless all of these conditions hold:

1. It contains exactly one complete CBOR item.
2. Every integer and length uses its preferred encoding.
3. Every map is in Core Deterministic Encoding key order.
4. Every map key is unique and is a text string.
5. Every collection has a definite length.
6. Its nesting depth does not exceed 32 levels.
7. Re-encoding the decoded value produces exactly the received bytes.

Decoded maps are materialized as null-prototype JavaScript records. This avoids
prototype-setter behavior for untrusted keys such as `__proto__`. Every decoded
byte string is copied away from the input buffer before the value is returned.

## Fixed-Length Byte Fields

The following protocol fields are CBOR byte strings with exact lengths:

| Field | Bytes | Validation in the current increment |
|---|---:|---|
| Game identifier | 16 | Length |
| Ed25519 identity public key | 32 | Length |
| SHA-256 digest | 32 | Length |
| SHA-256 DTLS fingerprint | 32 | Length |
| Ristretto255 point encoding | 32 | RFC 9496 canonical point decoding |
| Ristretto255 scalar encoding | 32 | Canonical little-endian value below the group order |
| Beacon/random secret | 32 | Length |
| Ed25519 signature | 64 | Length; signature verification is a separate operation |

Field parsers copy accepted input so subsequent mutation of the received CBOR
buffer cannot change a validated value. Semantic brands prevent accidental use
of, for example, a fingerprint where a game identifier is required.

## Domain Separators

Domain separators are the exact ASCII bytes of the strings in specification
section 3. No terminator or implicit length is appended.

| Purpose | ASCII string |
|---|---|
| Signaling room | `p2pcards/v1/room` |
| Channel authentication | `p2pcards/v1/chan` |
| Envelope signature | `p2pcards/v1/msg` |
| Card derivation | `p2pcards/v1/card` |
| Key proof of possession | `p2pcards/v1/pop` |
| Decryption-share proof | `p2pcards/v1/dleq` |
| Shuffle proof | `p2pcards/v1/shuffle` |
| Randomness beacon | `p2pcards/v1/beacon` |

Unframed concatenation is currently exposed only for these unambiguous layouts:

```text
room_id        = SHA-256(room_ds || game_id[16])
channel_input  = chan_ds || game_id[16] || local_fp[32] || remote_fp[32]
message_input  = msg_ds || canonical_cbor(unsigned_envelope)
envelope_hash  = SHA-256(canonical_cbor(signed_envelope))
```

Builders for card derivation, beacon commitments, and Fiat-Shamir challenges
use self-delimiting canonical CBOR segments. After the fixed ASCII domain and
fixed-length game identifier (where applicable), each integer, text value, or
statement is encoded as a separate canonical CBOR item before concatenation.

The resolved layouts are:

```text
card_hash = SHA-512(card_ds || cbor(deck_spec_id) || cbor(card_id))
card_point = ristretto255_from_uniform_bytes(card_hash)

beacon_commitment = SHA-256(
  beacon_ds || game_id[16] || cbor(round) || cbor(seat) || secret[32]
)

proof_challenge = LE512_TO_INTEGER(SHA-512(
  proof_ds || game_id[16] || cbor(round) || cbor(phase) || cbor(statement)
)) mod q
```

Seats in beacon commitments are integers from zero through seven. Proof
statements are exact canonical maps defined by each proof profile.

## Identity Signatures

The raw fallback identity secret is the 32-byte Ed25519 seed defined by RFC
8032. It is never included in a protocol value. The corresponding public key is
a 32-byte compressed Edwards point, and signatures are 64 bytes.

Imported public keys must use strict RFC 8032 decoding, lie in the prime-order
subgroup, and not be a small-order point. Signature verification uses strict
RFC 8032/FIPS 186-5 behavior with ZIP-215 compatibility disabled. Verification
of malformed untrusted input returns failure rather than throwing across the
protocol boundary.

Raw key generation allocates a 32-byte seed and fills it through the injectable
random-source interface. The production source delegates exclusively to
`globalThis.crypto.getRandomValues`, chunking requests at the API's 65,536-byte
limit. A later WebCrypto-backed non-extractable signer must produce signatures
that pass the same verifier and vectors.

The browser connection-check profile stores the exact versioned IndexedDB
identity record `{version: 1, secretKey, publicKey}` at key `self` in `identity`.
Both key fields are 32-byte `Uint8Array` values. Get-or-create is one read/write
transaction, generates only when absent, and resolves only after commit. Reads
validate the version, exact fields, strict public-key encoding, and derivation
from the stored secret; corruption fails closed without generating a new identity.
Returned buffers are independent copies. This is explicitly the raw-seed
fallback, not a non-extractable or hardware-protected WebCrypto key.

Human fingerprints use RFC 4648 uppercase, unpadded base32 of the first 16 bytes
of `SHA-256(pk_id)`, displayed in groups of four characters (the final group has
two). Public fingerprints and key hex may appear in browser snapshots; secret
seeds and keypair objects must not.

## Uniform Random Selection

A uniform integer in `[0, n)` for `1 <= n <= 2^32` is sampled from four random
bytes interpreted as an unsigned little-endian integer `x`. Let
`limit = 2^32 - (2^32 mod n)`. Values `x >= limit` are rejected and redrawn;
accepted values produce `x mod n`. Direct modulo reduction without this
rejection is forbidden.

A random permutation starts with `[0, 1, ..., size - 1]` and runs Fisher-Yates
from `i = size - 1` down through `1`, swapping positions `i` and a fresh uniform
index in `[0, i]`. Random bytes come through the same injectable source used by
keys and scalars.

## Signed Envelope Schema

A version 1 signed envelope is a deterministic CBOR map containing exactly the
following fields and no extensions:

| Field | Profile constraint |
|---|---|
| `v` | Integer exactly equal to `1` |
| `game` | 16-byte game identifier |
| `from` | 32-byte Ed25519 public key |
| `seq` | Unsigned safe integer |
| `prev` | 32-byte SHA-256 envelope hash |
| `round` | Unsigned safe integer |
| `phase` | Non-empty text string |
| `type` | One of the version 1 envelope message types |
| `body` | Any value allowed by the deterministic CBOR profile |
| `sig` | 64-byte Ed25519 signature |

`HELLO` is not an envelope message type. The version 1 envelope type catalogue
is closed; adding a type requires a protocol-profile change.

Signing first validates the unsigned nine-field projection, verifies that
`from` matches the signing secret, and signs `message_ds || canonical(unsigned)`.
Verification reconstructs that same projection from the received canonical
ten-field map. The envelope hash is SHA-256 over the complete canonical signed
map. The generic body is deep-snapshotted through canonical CBOR during both
signing and verification, so neither caller-owned values nor the received byte
buffer can mutate a validated envelope body later.

The envelope codec does not decide whether the game identifier, sender, phase,
round, sequence chain, or message body is valid in the current session. Those
are deterministic session and message-catalogue checks layered after signature
verification.

## Lobby Message Bodies

The `JOIN` body is exactly `{pk_id, rules_hash, client_version}`. `pk_id` is a
32-byte identity public key, `rules_hash` is a 32-byte SHA-256 digest, and
`client_version` is a non-empty text string. Session processing must additionally
require `pk_id` to equal the signed envelope's `from` identity; the body codec
does not make that contextual authority decision.

The `ROSTER` body is exactly
`{game_id, rules_hash, ice_config_hash, seats}`. The first field is a 16-byte game
identifier, both hash fields are 32-byte SHA-256 digests, and `seats` contains
one to eight unique 32-byte identities in seat order. Lobby rosters permit one
or two entries because the host broadcasts changes while players are still
joining. Finalized-session construction separately requires three to eight
seats. Session processing must also require `game_id` to equal the envelope game
and accept `ROSTER` only from the host.

The `READY` body is exactly `{roster_hash}`, with a 32-byte digest calculated as:

```text
roster_hash = SHA-256(canonical_cbor(ROSTER body))
```

The hash covers the exact four-field body, not its signed envelope. Seat order
is significant. Readiness processing must require every finalized roster member
to sign `READY` for the same currently accepted roster hash. All three codecs
copy byte fields at their input and output boundaries.

## Lobby Identity and Chain Bootstrap

The invitation's host identity is the initial lobby trust anchor. Every data
channel still completes `HELLO` authentication before carrying envelopes, and
all values below are canonical, signature-verified envelope artifacts before
they reach the lobby chain registry.

Ordinary chain ingestion never automatically trusts an unknown `from` identity.
The host may make an explicit admission call for a joiner connected with the
invitation credential. An admitted unknown envelope must be `JOIN`, use game
round zero and phase `lobby`, and be the sender's chain genesis with `seq = 0`
and a zero `prev`. Its `pk_id` must equal the signed envelope's `from`, and its
`rules_hash` must equal the host's selected rules. The accepted `JOIN` becomes
sequence zero of that identity's persistent sender chain; exact retransmission
is a duplicate and a different signed sequence-zero envelope is equivocation.

A roster envelope is accepted only from the invitation host, in game round zero
and phase `lobby`. Its body game and rules hash must match local context, every
seat must be a valid Ed25519 public key, and the host must occur in the unique
seat list. A different `ice_config_hash` is reported to connection diagnostics
but does not invalidate the roster because the base specification does not make
matching ICE configuration a security requirement.

A new peer bootstraps without exempting later envelopes from chain checks:

1. It knows the host identity from the invitation and receives the host's own
   envelopes from sequence zero in order after `HELLO`.
2. A valid host roster authorizes the identities it names, but does not create
   chain heads for them.
3. On each newly established direct channel, the roster member retransmits its
   own chain from sequence zero. For a non-host member, sequence zero is the
   signed `JOIN`; peers accept that unknown genesis only when the current valid
   host roster names its sender.
4. Once a sender's genesis is present, ordinary chain ingestion and `SYNC_REQ`
   or `SYNC_RESP` recover any later range without another bootstrap exception.

Receiving only a later host roster or member envelope therefore produces a
normal chain gap; it is not accepted as a synthetic head. Roster removal does
not erase already accepted history. Whether a known sender is authorized to act
under the current roster remains a phase/coordinator check above the chain
registry.

## Roster Readiness and Handoff

A `READY` envelope is accepted only in game round zero and phase `lobby`, after
the current host roster contains at least three seats. Its signer must occupy a
seat in that roster, its sender chain must already be bootstrapped, and its exact
`{roster_hash}` body must match the current canonical roster-body hash.

Readiness contributions may arrive in any network order and are recorded by
identity and roster hash. Exact envelope retransmissions and later valid `READY`
envelopes from an identity that is already ready for that hash are duplicates
rather than additional votes. Changing the roster switches the active
contribution set without deleting prior hash-bound signatures. Returning to
byte-identical roster contents therefore restores those signatures. This is the
only order-independent behavior expressible by the version 1 body; requiring a
new vote after returning would require a roster epoch in both `ROSTER` and
`READY`.

The lobby finalizes exactly when every identity in the current three-to-eight
seat roster has contributed. At that transition, each roster member's complete
contiguous lobby history, including its sequence-zero genesis and accepted
`READY`, is replayed into a new established `SessionChainRegistry` in seat order.
The resulting heads therefore continue the original sender chains rather than
resetting at setup. Lobby mutation is frozen after handoff; subsequent traffic
uses the established registry. This is also the point where the host loses its
special roster authority.

## Ristretto255 Values

Ristretto points are opaque values. The public API exposes only RFC 9496 decode,
encode, element derivation from 64 uniform bytes, equality, identity testing,
addition, subtraction, negation, and scalar multiplication. Edwards coordinates
and internal representatives are not exposed.

Point decoding accepts exactly 32 bytes and checks the canonical round trip.
Scalar decoding accepts exactly 32 little-endian bytes in the range `0 <= s < q`,
where `q = 2^252 + 27742317777372353535851937790883648493`. A 64-byte
little-endian challenge digest is reduced modulo `q`. Fresh secret scalars are
sampled uniformly by masking to 253 random bits, rejecting values outside the
field, and rejecting zero.

The implementation is covered by RFC 9496 generator, invalid-encoding, and
uniform-byte element-derivation vectors.

## Established Sender Chains

After a roster is finalized, one chain is maintained per roster identity. A
chain starts only at sequence zero with a 32-byte zero predecessor. Ingestion
has distinct outcomes for acceptance, an exact duplicate, equivocation at an
existing sequence, a future gap, a broken predecessor, and a wrong sender. A
rejected artifact never advances the chain.

The established-session registry additionally rejects the wrong game and
senders outside the finalized roster. It emits heads in seat order and serves
only inclusive synchronization ranges that are already complete locally. Its
non-mutating classification operation returns the same result that ingestion
would return at that instant without storing the artifact or advancing a head.

## Witness Heads

The `WITNESS` body is exactly `{heads}` or `{heads, state_hash}`, where `heads`
is an array of zero to eight exact `{from, seq, hash}` maps and optional
`state_hash` is a 32-byte public-state hash. `from` is a 32-byte identity, `seq`
is an unsigned safe integer, and `hash` is a 32-byte envelope hash. Senders must
be unique. Empty and partial arrays are valid because a seat can emit its first
periodic witness before every roster sender has a local chain head.

Session processing additionally requires present heads to appear in ascending
finalized-seat order. A locally known `(sender, seq)` with the same hash is
matching or stale; a different hash requests exactly that sequence before any
equivocation verdict. A claimed sequence above the local head requests the
contiguous range from `local_seq + 1` (or zero) through the claim.

Immediate witness emission follows game and lobby envelopes, but not the five
housekeeping types `WITNESS`, `SYNC_REQ`, `SYNC_RESP`, `TIMEOUT_VOTE`, and
`VIOLATION`. The independent idle timer still emits a witness at least every
five seconds and therefore eventually covers housekeeping heads without a
recursive message loop.

## Synchronization Messages

The `SYNC_REQ` body is exactly `{from, from_seq, to_seq}`. `from` is a 32-byte
roster identity, both bounds are unsigned safe integers, and the requested range
is inclusive with `from_seq <= to_seq`.

The `SYNC_RESP` body is exactly `{envelopes}` with a non-empty array of complete
signed-envelope maps. Envelopes are nested CBOR maps, not byte strings. Each map
is canonicalized and its Ed25519 signature is verified while decoding the
response. A peer serves a response only when its local range is complete.

Before applying a response, session processing checks the requested sender is
in the roster, the array length equals the inclusive range, and every nested
envelope has the session game, requested sender, and exact ascending sequence.
All artifacts are reverified from their canonical bytes, ignoring separately
supplied artifact views/hashes. Every adjacent pair must also have the correct
predecessor link. This preflight happens before any chain advances. It does not
establish attachment of the first artifact to the local chain; normal chain
classification still distinguishes acceptance, duplicates, equivocation, gaps,
and broken predecessors. A single requested known-sequence conflict remains
available for self-certifying equivocation assessment.

## Equivocation Violations

The profiled equivocation body is exactly
`{seat, reason: "equivocation", evidence: [env1, env2]}`. `seat` is an integer
from zero through seven. Evidence contains exactly two complete nested signed
envelope maps, not byte strings. Both signatures and canonical envelope
encodings are checked while decoding the body.

The two evidence envelopes must have the same game identifier, sender identity,
and sequence and must have different envelope hashes. Their array order is
ascending lexicographic order of the 32-byte hashes; encoding normalizes either
input order, while decoding rejects descending order. Session validation then
requires the evidence game to equal the active game and `seat` to be the
evidence sender's actual finalized-roster seat. Thus a reporter cannot use valid
equivocation evidence to blame another seat.

Only `reason = "equivocation"` is byte-profiled in this increment. Other
`VIOLATION` reasons and evidence shapes remain unavailable until each has an
exact public-data proof format.

## Durable Envelope Authoring

An authored envelope is not eligible for broadcast until one IndexedDB
read/write transaction has both appended its canonical bytes to `transcripts`
and advanced the durable `(game, sender)` head in `authored_heads`. The
transaction reads the current head, allocates `seq = head.seq + 1` (or zero),
sets `prev` to the current hash (or 32 zero bytes), signs synchronously, and
validates the resulting game, sender, sequence, predecessor, canonical encoding,
and signature before either write.

`transcripts` uses an auto-increment arrival key and a unique
`(game, sender, seq)` index. IndexedDB serializes overlapping read/write
transactions across connections, preventing separate tabs from allocating the
same sequence. Any signing, validation, constraint, or storage error aborts both
writes and consumes no sequence. The authoring promise resolves only from the
transaction's completion event. Message bodies are canonical-encoded and
decoded once before entering the asynchronous queue so caller mutation cannot
alter a delayed envelope.

Before invoking the signer callback, the native authored store also reads the
last indexed transcript row and the indexed row count for the exact game/sender
within the same transaction. A present checkpoint must byte-match that last
locally authored row, its sequence plus one must equal the count, and a
sequence-zero checkpoint must have the zero predecessor. A missing checkpoint
is valid only when that sender has no indexed history. Missing rows, a stale
checkpoint, conflicting tail bytes, or a non-authored tail require recovery;
the store neither guesses a new genesis nor promotes received own-signed history
into authoring authority.

These tail/cardinality checks are not full recovery of every earlier record's
signature or predecessor, and cannot detect rollback to a mutually consistent
old database snapshot. Full chain/semantic recovery remains a prerequisite to
resuming an interrupted session. The authored replay operation below validates
the complete captured prefix before transmitting it.

The signer callback receives a copy of its head, not the private predecessor used
for next-artifact validation. Callback-produced canonical bytes are read once,
bounded to 8 MiB, and those same bytes are verified before persistence. The
author isolates its game/sender inputs and retained result from storage-owned
buffers, permits one creation attempt, and expires the signing callback when the
append operation settles. A recorded callback failure takes precedence even if
the store swallows it and resolves, or substitutes a different rejection. This
includes callbacks that throw `undefined`; a separate failure flag distinguishes
that outcome from success. These guards do not replace the store's atomic commit
contract.

`PersistentEnvelopeAuthor.gameId` and `sender` return defensive copies. The
optional `author(content, beforeSign)` guard runs after the stored head is
reverified and the next sequence is checked, immediately before signing. It
receives a separately decoded head, or `null` for genesis, never the predecessor
buffers used by the signer. It must synchronously return `undefined`; throws or
other return values prevent signing. Promise-returning guards are rejected, not
awaited. The generic author does not interpret game state: a game-specific caller
must provide any lifecycle, freshness, and accepted-head checks through this
boundary.

`PersistentEnvelopeAuthor.readHead()` provides a readonly preflight against the
author's own store. The store must implement `readAuthoredHead`; unsupported
stores fail rather than appending a dummy envelope. Reads and writes share the
author queue, use isolated scope arguments, reverify the returned head's signature
and game/sender binding, and return detached data. Head bytes are bounded to 8 MiB.
An early head read can prevent private preparation against unreconciled history,
but cannot replace the atomic `beforeSign` guard after asynchronous work.

## Durable Accepted Envelopes and Roster

Every accepted incoming envelope is snapshot-decoded and signature-verified
again at the IndexedDB boundary before its canonical bytes are added to
`transcripts`. The unique `(game, sender, seq)` index makes an exact existing
artifact idempotent. A different valid artifact at the same tuple is returned
as a conflict with both signed artifacts; it never replaces the first record.
The second artifact is not classified as accepted and is not inserted into the
unique transcript table. Authored records retain `authored = true` when the
session store encounters them again.

Transcript reads use the per-game index in local arrival-key order. Every stored
row is signature-verified again and its indexed game, sender, and sequence must
match the decoded envelope. This arrival order is recovery metadata only; it is
not the pending canonical transcript order and must not decide simultaneous
protocol messages.

Persisting an accepted `ROSTER` uses one read/write transaction over
`transcripts` and `games`. The operation idempotently inserts the envelope and
updates `games.lobbyRoster` only when the host sequence is newer than the stored
snapshot. A historical roster is retained in the transcript without downgrading
the snapshot. IndexedDB transaction serialization makes concurrent tabs converge
on the greatest persisted host sequence. Equal-sequence conflicts preserve the
first artifact and are surfaced for equivocation handling.

Roster recovery verifies the envelope signature and lobby metadata, body/envelope
game equality, expected host, every identity public key, and host membership,
then recomputes the canonical roster hash. Snapshot updates merge the existing
game record so durable game secrets and future phase fields are preserved.
Direct callers must invoke these operations only after non-mutating chain and
message classification and must suspend further state processing if persistence
fails.

## Durable Lobby Receipt

Live lobby transitions use one serialized classify-persist-commit queue. `JOIN`,
`ROSTER`, and `READY` each have a non-mutating classifier that applies the same
authority, context, body, and sender-chain checks as its mutating operation. A
rejected transition performs no storage operation. Explicit invitation admission
and current-roster admission remain separate `JOIN` entry points; persistence
does not grant either authority by itself.

Accepted joins and readiness artifacts use accepted-envelope storage. Accepted
rosters use the atomic transcript-and-roster-snapshot transaction. In-memory
sender chains, roster state, readiness sets, and finalization change only after
the store reports success for the exact candidate. The last `READY` therefore
cannot expose a finalized registry before its durable write commits. A semantic
readiness duplicate that occupies a new sender sequence is still persisted and
advances that sender chain exactly once.

Storage failure and durable equal-sequence conflict leave lobby state unchanged,
and one failed operation does not poison the queue. A stored roster snapshot
newer than an otherwise chain-acceptable live roster means startup recovery was
skipped or incomplete; live receipt fails closed and requires recovery instead
of regressing the durable roster. Once a persistent receiver owns a lobby, all
mutating lobby operations must pass through that receiver.

## Durable Established-Session Receipt

Live finalized-session receipt is serialized in local invocation order. Each
candidate is first snapshot-decoded and signature-verified, then classified
against the finalized roster and current sender chain without mutation. A chain
rejection performs no storage operation. An artifact classified as accepted or
duplicate is passed to accepted-envelope storage, and the registry is advanced
only after that operation reports a committed exact artifact. A storage failure
rejects the receive promise and leaves the in-memory chain unchanged. A durable
equal-sequence conflict returns both signed artifacts and likewise does not
advance memory.

The storage result is decoded and verified again before use and must be
byte-identical to the candidate. This supports both restart mismatch directions:
an in-memory duplicate missing from storage is repaired durably, while a durable
duplicate missing from freshly recovered memory can still advance the chain.
Failure of one queued receive does not poison later receives.

This receiver is a persistence and sender-chain boundary, not a game-message
validator. The deterministic phase coordinator must classify body, phase,
round, authority, and one-action constraints before submitting an artifact, and
must mutate public game state only after durable receipt succeeds. Once this
boundary owns a registry, no other component may call that registry's mutating
ingestion operation concurrently.

## Lobby Recovery

Lobby recovery is a pure, network-free operation over signature-verified
envelope artifacts plus the invitation context and optional durable roster
snapshot. It does not trust local arrival order. Every artifact is decoded and
signature-verified again, duplicate `(sender, seq)` tuples are rejected, and
records for another game fail recovery.

Artifacts are grouped by sender and sorted by sequence. The invitation host's
chain is replayed first, with every `ROSTER` passing normal host/context
validation. Every other sender must begin at sequence zero with its strict
`JOIN`; a later `JOIN` or any non-host `ROSTER` is invalid. Normal chain checks
then prove each group is contiguous. When supplied, the durable roster snapshot
must equal the latest accepted host roster exactly.

After chain hydration, syntactically valid `READY` artifacts are restored by
roster hash. At most the earliest accepted contribution for each
`(roster_hash, sender)` is needed; later ones are semantic duplicates. Historical
hash contribution sets are restored before the current set, and current
contributions are applied in seat order. If every current seat is ready, normal
lobby handoff builds the established registry from the complete hydrated chains,
including any accepted tail after a seat's first `READY`. Live traffic must not
be processed until this recovery either succeeds or fails closed.

## Established-Session Chain Recovery

Pure established-chain recovery accepts a game identifier, finalized roster,
and the durable artifact slice for those roster senders. It re-decodes and
signature-verifies every artifact, rejects another game, non-roster senders, and
repeated `(sender, sequence)` tuples, then groups by sender and sorts each group
by sequence. Normal chain ingestion proves zero genesis, contiguity, and every
predecessor link. Network arrival order is never consulted, and roster members
without accepted history retain empty chains.

This operation restores authenticated sender-chain state only; it assumes the
input slice previously passed deterministic message semantics and does not
reconstruct game-engine state. A complete transcript that can contain removed
lobby candidates must instead pass through lobby recovery. Its finalized
registry already includes the full accepted tails of current roster members.
Live receipt starts only after the selected recovery path succeeds.

## Canonical Signed-Envelope Order

The signed-envelope component of a transcript is ordered without using local
arrival metadata. Every envelope is canonical-decoded and signature-verified,
must have the selected game identifier, and must have a unique
`(sender, sequence)` tuple. Records are grouped by sender, each complete chain is
validated from zero through its predecessor links, sender groups are ordered by
ascending lexicographic identity-key bytes, and each group is emitted by
ascending sequence.

This order serializes the authenticated envelope set; it is not the semantic
game-replay schedule. Phase reducers continue to process simultaneous messages
in their profiled phase and seat order. IndexedDB can expose records in this
canonical envelope order while retaining each arrival key as diagnostic
metadata. The final exported container, `HELLO` representation, and
`transcript_hash` input remain unprofiled and are not implied by this ordering
function.

## Durable Game Secret

The local per-game ElGamal secret is stored in the `games` record as its
canonical 32-byte little-endian Ristretto scalar encoding. Zero and malformed or
non-canonical encodings are rejected. A read/write transaction performs atomic
get-or-create, so overlapping browser connections either create the secret once
or reuse that committed value.

Local `KEY_SHARE` preparation first awaits that transaction's completion and
only then generates its fresh proof nonce. Consequently no public key share is
available to the broadcast path before the corresponding secret is durable.
After game end, deleting the secret preserves all unrelated fields in the game
record.

## Durable Setup Beacon Secret

The setup randomness commitment needs its private 32-byte preimage to survive a
restart between `RAND_COMMIT` and `RAND_REVEAL`. This refines the base
specification's section 12 claim that the ElGamal key is the only unrecoverable
secret: before an original reveal is durably available, losing the committed
beacon secret is also unrecoverable by regeneration. A different secret cannot
repair the existing commitment.

`SetupBeaconScope` is a local persistence context, not a new wire value. It is
exactly `{gameId, round, roster, sender}`, with an explicit non-negative safe
setup round (excluding negative zero), three through eight distinct valid Ed25519
identities in finalized seat order, and a sender belonging to that roster. The
seat is derived from the sender's position, never accepted as an independent
integer. Scope containers are plain data objects; accessors, extra fields, and
sparse/accessor roster entries are rejected. `snapshotSetupBeaconScope` copies
the public byte fields and freezes the outer value and roster array.

`IndexedDbSetupBeaconSecretStore` owns one optional field in the existing game
record, with no new object store, index, or database-version change:

```text
setupBeaconSecret = {
  version: 1,
  round: unsigned safe integer,
  sender: identity_public_key[32],
  roster: [identity_public_key[32], ...],
  secret: random_secret[32]
}
```

The enclosing game key supplies the game ID. The field has exactly these five
properties. Its round, sender, and full ordered roster are immutable for that
game's local store: a scope mismatch on load or get-or-create fails instead of
creating a replacement. This supports the current single `setup.rand` invocation
per game, not an automatic beacon for each gameplay hand or multiple same-round
purposes. Setup-round selection remains explicit. Changing that policy requires
a separately profiled invocation/storage scope.

`getOrCreateSetupBeaconSecret(scope, create)` snapshots its scope before awaiting
the database. A read/write transaction validates an existing field or invokes
the synchronous creator once only when the field is absent, writes detached
secret bytes while preserving other game fields, and resolves only at transaction
completion. Overlapping connections converge on one committed secret. Corrupt,
unsupported, or explicitly present-but-undefined fields are not overwritten.
Async creators and malformed results abort rather than being awaited in a live
transaction. Recorded request/callback failures prevent success even if an error
was handled and the transaction subsequently completes.

`prepareLocalBeaconContribution(scope, store, source?)` is for initial preparation
before any commitment has been authored. It returns private `{secret, commitment}`
material only after the selected secret is durable. Scope copies passed to the
store cannot change the helper's private commitment context. The creation
capability permits one attempt, expires when storage settles, and preserves
callback failures even if a store swallows or substitutes an error. If creation
ran, the selected result must equal its private generated copy. Reusing an existing
secret consumes no new protocol randomness.

Beacon secrets are raw random bytes, not Ristretto scalars. All-zero and full-ff
32-byte values are valid encodings; no reduction or nonzero rule is added. The
default generator uses the existing CSPRNG. The v1 commitment remains exactly
`SHA-256(beacon_ds || game_id || cbor(round) || cbor(seat) || secret)`; identity
and full-roster persistence checks do not change that hash preimage or wire format.
Fixed-byte field parsing now measures actual typed-array sizes and makes bounded
private copies, rather than trusting caller-supplied `length` or `slice` behavior.

Recovery uses `loadSetupBeaconSecret(scope)`, which is readonly and returns
`null` when the game/field is absent. `restoreLocalBeaconContribution(scope, store,
expectedCommitment)` uses only this load path, recomputes the commitment in the
captured scope, and rejects missing, malformed, or mismatched secrets. The caller
must supply the commitment from authenticated, accepted or correctly recovered
setup history. It must not call the initial get-or-create/preparation path after
a commitment merely because local storage is missing. Neither helper loads or
regenerates the game key, signs an envelope, advances setup state, or grants
permission to reveal. Revealing still requires all roster commitments and the
normal durable, scope-bound setup receipt path.

Already-authored setup messages must be replayed as original signed bytes.
Recomputing the same beacon commitment does not authorize a new sender sequence,
and recreating `KEY_SHARE` from the saved game key generates a different PoP that
can conflict with the original contribution. If an original signed reveal is
already durable, replay it instead of fabricating another reveal or repairing
the private store implicitly.

`deleteSetupBeaconSecret(gameId)` is an explicit cleanup primitive, not an end-game
decision. It removes only its owned field and preserves the game key, lobby
roster, unrelated fields, and transcript; an otherwise empty game row may be
removed. No automatic deletion occurs at reveal, hand completion, or audit.
Before legitimate reveal, the secret must stay out of public snapshots, exports,
diagnostics, and logs. After reveal, deleting the local field cannot erase the
public signed transcript. Storage is raw IndexedDB bytes, not encryption at rest
or a promise of secure physical erasure.

Four independent IndexedDB peers exercise native key/commit originals, restart
after commitments but before reveal, load-only secret restoration, exact original
replay, and identical seat-ordered seeds after all reveals. The guarded setup
owner below now supplies explicit local authoring; automatic phase scheduling,
readiness-aware delivery, and browser setup flow remain separate work. The beacon
is not deck-order randomness or verified shuffle provenance.

The private key/beacon preparation helpers also accept an optional synchronous
guard. It must return `undefined`, not a promise. It is checked before secret
access, inside single-use creation, after asynchronous storage, before returning
material, and before/after each protocol random draw, including rejected scalar
samples. Closing while a key-store operation is pending cannot cause a fresh PoP
to be generated afterward. Already submitted private writes may still commit;
unused private material is safe and is not deleted or published automatically.

## Initial Deck Cryptography

A deck specification contains a non-empty ID and 2 to 128 unique non-empty card
IDs. Each card point is derived with `card_hash` above and RFC 9496 element
derivation. Implementations build a point-to-card lookup and fail on a duplicate
ID or the cryptographically negligible event of a point collision.

An ElGamal masked card is `(A, B) = (r*G, M + r*H)`. Remasking adds
`(r'*G, r'*H)`. Fresh masking randomizers, individual game secrets, individual
public keys, and the aggregate public key must be non-zero. The public initial
deck uses `(O, M)` directly and therefore does not call the fresh-mask API.

`createUnprovenDeckShuffle(inputDeck, aggregateKey, source?)` captures a detached,
validated 2–128-card input and nonidentity key before invoking its random source.
It uses the existing unbiased Fisher-Yates permutation and nonzero scalar sampler.
For each output position `j`, it computes
`output[j] = remask(input[permutation[j]], randomizers[j], aggregateKey)`.
Both permutation and randomizers are indexed by output position. Each invocation
draws fresh private material; the public beacon must not determine these values.

The result contains the captured key, input/output decks, and a **private witness**
(`permutation`, `randomizers`) for a future prover. This witness never belongs in a
wire body, transcript, diagnostic log, or public game snapshot. The helper checks
input shape/group encodings and performs remasking; it does not verify input-deck
provenance or produce/verify a shuffle proof. Initial identity `A` components are
valid. Operation bounds do not select proof matrices. No `SHUFFLE` proof codec or
production verifier is implied; see the [backend assessment](shuffle-backend-assessment.md).

## Key and Share Proofs

The Schnorr proof-of-possession statement is the exact map `{H, R}`. Its
challenge uses the `proofOfPossession` domain, and verification checks
`z*G = R + c*H`. Identity public keys are rejected.

The Chaum-Pedersen statement is the exact map
`{pos, H, A, S, R1, R2}`. Its challenge uses the `decryptionShare` domain, and
verification checks both `z*G = R1 + c*H` and `z*A = R2 + c*S`. Positions are
integers from zero through 127. Both proof generators use fresh non-zero scalar
nonces from the injectable CSPRNG boundary.

The `KEY_SHARE` body is exactly `{H_i, pop: {R, z}}`. A `SHARES` body is exactly
`{to, items}`, where `to` is a seat from zero through seven and each item is
exactly `{pos, S, R1, R2, z}`. A batch contains 1 to 128 unique positions. Point
and scalar fields are decoded canonically before proof verification.

Setup stores at most one valid key share per finalized seat. Each proof is
checked with the exact context `{gameId, round, phase: "setup.keys"}` before the
seat is consumed; a failed proof can therefore be replaced by a valid one.
Exact retransmissions are duplicates and a second distinct share for an already
consumed seat is a conflict. Once every seat has a valid share, public keys are
aggregated in ascending seat order. An identity aggregate terminates setup as a
collective failure and is not blamed on whichever valid share arrived last.
Randomness commitments are not accepted before aggregate-key completion.

The setup envelope coordinator additionally binds `KEY_SHARE` to `setup.keys`
and `RAND_COMMIT`/`RAND_REVEAL` to `setup.rand`, and checks the exact game,
round, finalized-roster sender, and strict body codec before calling setup
cryptography. Both setup and beacon transitions expose non-mutating
classification. The predicted result includes phase completion but does not
consume a seat, construct an aggregate key, reveal a seed, or otherwise alter
state.

## Action and Audit Bodies

An `ACTION` body is exactly `{kind, data, reveal, shares}`. `kind` is a 1 to
64-byte lowercase ASCII identifier: its first character is a letter, and all
remaining characters are letters, digits, or underscores. Its meaning belongs
to the agreed rules module, not the generic codec. `data` is a supported CBOR
value whose canonical encoding occupies at most 4096 bytes, including its CBOR
headers. Existing canonicality, integer, text, and depth restrictions apply.
Neither field is interpreted as executable code.

`reveal` contains zero to 128 distinct positions from zero through 127. `shares`
has exactly the same length, and each item is the existing strict
`{pos, S, R1, R2, z}` share map. Its `pos` must match the corresponding entry in
`reveal`. Array order is preserved, signed, and never silently sorted. Empty
arrays represent an action without card disclosure. Missing, additional,
duplicate, mismatched, or reordered shares are malformed. Points and scalars
are decoded canonically; this does not verify their proof equations.

An `AUDIT_DISCLOSE` body is exactly `{items}` with zero to 128 distinct-position
share items using the same point/scalar codec. Item order is preserved. Unlike
`SHARES`, an empty disclosure is allowed, including when every dealt card has
already been played publicly. An empty body is not evidence that disclosure is
complete: the engine must compare the positions to the actual outstanding audit
schedule for that sender. Both body codecs reject negative-zero positions and
return independent snapshots of input data/encodings.

New action and audit share proofs use the carrying envelope's exact
`{gameId, round, phase}` proof context. Previously accepted deal shares retain
their original proof contexts; they are not reinterpreted under a play phase.
The engine must bind each proof to the sender's accepted game key and the
scheduled ciphertext. Publicly scheduled reveals still belong to the deal/share
scheduler; this profile does not add an implicit public-deal authorization.

`decodeActionEnvelope` is a stateless signature/scope/body boundary, not a game
receiver. It accepts at most 64 KiB of canonical signed-envelope bytes, a game ID,
round, action index, a finalized three-to-eight-seat identity roster, and an
explicit nonempty set of expected roster indices. Configuration rejects duplicate
or invalid identity keys, duplicate/out-of-range expected seats, and invalid
round/index values. The decoder verifies the signature from the canonical bytes,
derives the actor from `from`, and requires the exact game, round, `ACTION` type,
expected sender, and phase `round.<round>.play.<actionIndex>`. Phase components
use the canonical unsigned decimal representation, not aliases with leading
zeroes. The action index is not the sender's envelope sequence.

The returned `DecodedActionEnvelope` contains the verified envelope artifact,
derived seat, and decoded body. Unsupported body kinds can pass this generic
boundary and must still fail the selected rules adapter. Decoding does not
consume an action, deduplicate a retransmission, advance a sender chain, persist
anything, check proof equations or position ownership, or grant game/session
readiness. A live coordinator must still check verified shuffle/deal provenance,
scheduled and unrevealed ownership, decryption proofs, opened-card lookup, and
public rules before durable chain receipt and the single state mutation.

## Initial Private-Round Reveals

`RoundRevealLedger` is the stateful proof/ownership layer for an explicitly
configured initial private-deal schedule and sequential single-actor actions.
Construction requires a completed, trusted `SetupEnvelopeCoordinator`, a round
number no earlier than that setup, a deck specification and same-sized canonical
ciphertext vector, an explicit `{to, count}[]` schedule, and a positive safe-integer
`maxActions` budget. It snapshots the setup's roster/public game keys and the
deck/schedule inputs. It never stores a player's secret scalar or a hidden hand.

The supplied ciphertext vector must come from separately verified shuffle
processing before production use. This constructor checks size and encodings,
not Bayer-Groth proofs, shuffle fairness, or the provenance of the schedule/rules.
It is not a factory for a cryptographically verified deck. The explicit schedule
also does not choose a dealer or establish the missing Sasku dealing policy.

Schedule steps allocate ascending stock positions beginning at zero. Counts
must be positive and cannot overrun the deck; recipients must be roster indices.
Unused positions remain unassigned stock. In `round.<r>.deal.<k>`, every seat
other than the recipient must contribute exactly one signed `SHARES` batch for
that step's exact position set and recipient. Item order is immaterial to the
ledger, but is preserved in signed bytes. The recipient's premature own-share
batch, missing/extra positions, invalid proofs, and additional distinct sender
contributions are rejected. Every item is proof-checked against the sender's
accepted game key, its scheduled ciphertext's `A`, and the carrying game/round/
deal phase before any contribution is committed. The next step begins only after
all other seats' batches have committed.

`classify(artifact, expectedSeat?)` and `commit(artifact, expectedSeat?)` both
reverify the original canonical signed bytes, ignoring mutable decoded artifact
views. Envelopes are capped at 64 KiB. `classify` performs no state mutation;
`commit` repeats validation before applying a whole batch or action atomically.
For a new `ACTION`, all configured private steps must be complete and the caller
must supply the rules-derived expected seat. The exact current play phase,
authority, and body checks use `decodeActionEnvelope`.

Every action reveal must target an assigned, still-unrevealed position owned by
its authenticated author. A valid proof from another seat cannot confer ownership.
The owner's new share is verified in the action phase; the ledger combines it
with the already-verified deal shares in seat order and identifies the plaintext
card point. An unknown card or repeated card ID at a different position raises
`inconsistent_deck`. With valid shares, this indicates a problem with the supplied
deck/context, not proof of misconduct by the revealer. No partial action or action
counter update is committed if any position, proof, or lookup fails.

Classification returns the opened card map for public-rule preview, without
installing those cards into the ledger's public snapshot. The live caller must
serialize classification, rules validation, durable chain receipt, ledger commit,
and rules-state mutation under one mutation owner. The ledger does not itself
write IndexedDB, advance sender chains, validate game-specific action semantics,
or enforce that its caller actually persisted before `commit`. Its `accepted`
classification means crypto/ownership admissibility only, not game acceptance.

Original accepted envelopes are remembered by their canonical hash. Exact
retransmissions are idempotent even after the phase, turn, or action budget has
advanced; they still require valid signatures and matching game/round/roster.
Another signed envelope is not an exact retransmission even if its body is
equivalent. Receipt memory is bounded by at most `(N - 1) * schedule.length`
deal contributions plus `maxActions`, including actions with no reveals. Reaching
that budget is a resource limit, not a hand/match-completion signal.

Snapshots contain committed phase/counters, the current private step's public
positions and pending senders, and publicly opened cards only. `ownerAt` reports
scheduled ownership, including `null` for stock. Historical envelopes can rebuild
the same ledger given the same trusted round context; this is not standalone game
recovery because shuffle/deal provenance and rules replay must also be restored.
Wrong-phase or incomplete-deal errors do not by themselves prove sender fault:
cross-sender delivery ordering and retry/buffering remain the live coordinator's
responsibility. No timeout or violation certificate is emitted by this ledger.

Dynamic draws, public deals, reshuffle/dead-position tracking, simultaneous game
actions, audit-phase receipt, and automatic recovery orchestration remain outside
this ledger. The game-specific durable receiver below now owns its live mutation
boundary. IndexedDB integration tests use that receiver with explicit ciphertext
fixtures; they do not establish a verified shuffle or open browser gameplay.

## Local Private-Hand Reads

`RoundRevealLedger.readPrivateHand(seat, secretKey)` derives a local hand from
committed initial-deal contributions. The seat must belong to the round roster,
and the supplied canonical scalar must satisfy `secretKey * G == H[seat]` for
that seat's accepted setup key. Invalid or mismatched keys produce
`invalid_local_key` without including the secret in the error or its cause.
The ledger does not retain the supplied secret.

The result is `null` until the entire explicit initial-deal schedule is committed,
even if that seat's own batches finished earlier. A classified contribution or a
missing/rejected batch cannot make a hand available. Once complete, the reader
opens only positions assigned to that seat using their already verified,
committed non-owner shares and the private calculation `secretKey * A[pos]`:

```text
M[pos] = B[pos] - sum(other seats' accepted shares[pos]) - secretKey * A[pos]
```

The card-point table identifies each result; ciphertext positions are not
plaintext card indices. No owner-share proof is generated or disclosed, no
randomness is consumed, and no ledger state or public reveal is added. Existing
deal proofs retain their original verified contexts. Raw ledger users remain
responsible for persisting before `commit`; the durable Sasku wrapper enforces
that boundary rather than trusting arbitrary caller-supplied shares.

The frozen result contains two position-to-card maps: `dealt` preserves the
original assigned cards, and `remaining` excludes positions already publicly
opened by committed actions. Stock and other seats' hidden positions are not
opened. Unknown card points, duplicate local card identities, or a collision
with a different already-public position are `inconsistent_deck` context errors,
not proof of sender fault. This local check cannot establish uniqueness among
opponents' still-hidden cards or replace shuffle verification.

`PersistentSaskuRoundReceiver.readPrivateHand(identity, secretKey)` resolves the
seat from its bound session roster and returns Sasku card IDs through the same
primitive. Reads are explicit and separate from `snapshot` and receive results;
they do not cache the private hand, load/store keys, author messages, or write
plaintext cards. During an awaited write, reads still reflect the last semantic
commit. An owned card disappears from `remaining` only after its reveal commits.
Previously returned immutable hand values remain unchanged.

Closed or failed receivers reject private access, including when an internal
commit failed after advancing only part of the ledger. A private read that
discovers an inconsistent supplied deck stops the receiver with
`recovery_required`; queued work fails, and an active durable write may settle
but cannot publish another semantic transition. A wrong local key is not such
a terminal failure. These errors do not publish the privately discovered cards.

Restart callers use the existing `loadGameSecret(gameId)`, not get-or-create,
then restore verified sender chains, setup, and semantic round history before
reading the same hand. Missing/corrupt keys must stop private recovery rather
than trigger replacement; a canonical but mismatched key fails the setup-key
check. The saved game key and original signed transcript remain the durable
source of truth. No new database field, plaintext hand record, or key-deletion
policy is introduced. The existing key store is raw scalar storage, not at-rest
encryption, and JavaScript memory erasure is not guaranteed. Callers must keep
returned cards out of public snapshots, witnesses, transcript exports, React
state snapshots, and diagnostic logs. Browser hand/input handling and automatic
game recovery remain separate work.

## Durable Sasku Receipt

`PersistentSaskuRoundReceiver` lives in the `game-sasku` composition workspace so
the shared engine remains game-agnostic. It privately constructs and owns both
a `RoundRevealLedger` and a `SaskuPublicHandController`; callers receive no mutable
controller references. Construction requires trusted completed four-seat setup,
the active round, a supplied 36-card ciphertext deck, an explicit private schedule
dealing exactly nine positions per seat, and an explicit dealer. It fixes the
Sasku deck specification and 64-action budget rather than accepting substitutes.
Setup/deck/rules/dealer provenance remains an external prerequisite; constructor
checks do not establish a shuffle proof or select missing game policies.

The supplied `PersistentSessionReceiver` must be bound to the supplied
`SessionChainRegistry`, and that registry must match setup's game ID and exact
seat order. Setup and the relevant sender chains must already have been durably
received or correctly restored. All round `SHARES`/`ACTION`/`AUDIT_DISCLOSE`
traffic must pass through this one semantic receiver; validated housekeeping
may use the same durable session receiver through its own dispatcher.

Admission bounds pending envelope count and original wire-byte totals, including
active work, before copying or verifying another envelope. Defaults are 32
envelopes and 1 MiB of pending wire bytes, with the ledger's 64 KiB per-envelope
ceiling. Local action operations use the same counters and conservatively reserve
one slot and the full 64 KiB ceiling rather than a not-yet-created envelope's size.
Limits are positive safe integers. Admitted canonical bytes are privately
copied and signature-verified; later caller mutation cannot change queued work.
Invalid admission releases its reservation. A FIFO serializes the entire
semantic/durable transition, not merely storage calls.

For each queued message, the receiver derives the expected actor from its owned
public hand, classifies the ledger transition, maps verified card openings to a
Sasku action, and previews the public rules without mutation. Only then does it
invoke durable session receipt with a separate artifact copy. Proof, ownership,
turn, phase, and public-rule failures never reach accepted-envelope persistence.
An ordinary storage error or chain rejection leaves both game states unchanged;
the queue remains usable and the original signed message may be retried without
resigning. A rejection returns its chain reason and a detached input artifact;
full chain/conflict evidence remains in the session/storage layer.

A successful durable receipt must name the exact original canonical bytes and
report a recognized receipt/persistence status. Its bound registry must both
classify the original artifact as an exact duplicate and retain those same
canonical bytes at the sender sequence. This catches corrupted chain hashes as
well as mismatched or unrecorded receipts. The dependency never receives the
private validation/commit buffers, and returned artifacts do not expose buffers
retained by the shared session.

After verified durability, the receiver revalidates/commits the ledger and applies
the already-previewed action synchronously, with no intervening await or external
callback. It publishes one cached immutable snapshot containing ledger state,
public hand state, normalized public history, and local audit state only after
the transition succeeds. An exact duplicate does not apply twice or replace the
snapshot. A fresh semantic receiver can consume original historical messages in
protocol order when the durable chain already knows them: its result is `accepted` with
`chainStatus: "duplicate"` as semantic state catches up. This is not automatic
reconnect completion or a substitute for verified recovery inputs.

Invalid/mismatched receipts, durable-receiver invariant failures, inconsistent
supplied decks, or unexpected post-persistence commit failures stop the instance.
`failure` remains non-null, queued work is rejected, and later receives fail
closed. The published snapshot remains the last fully committed state, even if an
internal component failed partway through a commit. Recovery must reconstruct the
receiver and restore any damaged shared session from verified durable history;
there is no reset/retry switch for this terminal condition and no player-forfeit
claim from it.

`close()` rejects queued work immediately and prevents new admission. An already
submitted durable receipt is allowed to settle and, on success, finish both state
updates consistently; its budget remains charged until it settles. Closing does
not close the shared session receiver, database, or transport. Queue capacity is
released on every success, rejection, failure, and queued cancellation.

`whenIdle()` observes when this receiver's admitted count next reaches zero,
including active writes and local authoring. It settles after failures as well
as successes; callers must separately inspect operation results and `failure`.
Closing does not settle it early while submitted work remains active. It is not
an admission lock or a barrier for shared housekeeping, transport, or future
work. The copied construction scope remains available through `round`,
`dealCount`, and exact-registry `isBoundTo(session)` for bounded composition.

The receiver does not reorder or automatically retry future-phase messages,
automatically generate setup/deal/audit contributions, load local keys, or finalize
a match. Explicit guarded local `ACTION`, scheduled `SHARES`, and completed-hand
`AUDIT_DISCLOSE` authoring are defined below.
The optional round inbox below adds bounded incoming prerequisite deferral without
changing this receiver's ordinary classify/persist/commit contract.
Completed public hands still expose provisional scores; new actions cannot extend
them, while exact historical duplicates remain idempotent. The local signed
disclosure/audit boundary is defined below. Browser gameplay, verified shuffle
provenance, round/match progression, and broader synchronization remain separate
integration work.

## Durable Local Sasku Actions

`authorAction(author, secretKey, expectedSnapshot, intent, source?)` queues one
explicit local action in the same FIFO as incoming round traffic. `author` must
be a `PersistentEnvelopeAuthor` for this game and a roster identity; the acting
seat comes from that identity, not from the intent. The supplied game secret must
match that seat's accepted setup key. The native authored store and accepted
session store must refer to the same intended durable history. Their storage
configuration is a trusted composition prerequisite, not inferred by this API.

`expectedSnapshot` must be the actual cached `receiver.snapshot` object captured
when the caller chose the move. An equal clone, another receiver's snapshot, or
an older committed view fails with `stale_action`. The receiver checks this at
admission, queued execution, and signing time. Queued intents are never silently
retargeted to a later turn or phase. Exact historical duplicates do not replace
the cached snapshot and therefore do not invalidate an otherwise current intent.

The local intent is a strict plain data object with exactly one of these shapes:

```text
{type: "pass"}
{type: "diamonds"}
{type: "bid", value: 3..9}
{type: "choose_trump", suit: "clubs" | "spades" | "hearts" | "diamonds"}
{type: "play", position: 0..35}
```

Integers exclude negative zero. Accessors, symbols, non-enumerable fields,
additional actor/card claims, and unsupported prototypes are rejected. Accepted
fields are copied before queueing. Every local operation reserves one pending
slot and 64 KiB before copying, key work, or proof generation; the reservation
lasts through authoring and local receipt. Queue limits still measure bounded
work and wire capacity, not the complete JavaScript heap.

Execution requires the complete committed initial deal. Public rule preview
checks the turn, phase, auction progression, and play shape. Private checks also
require bids no higher than the original-hand strength, scheduled ownership of an unplayed
position, and effective-suit following. Invalid local moves reach neither signing
nor proof randomness. Auction actions contain no reveals/shares. A play generates
exactly one fresh owner DLEQ proof under its current game, round, and action phase,
then encodes the unchanged `ACTION {kind, data, reveal, shares}` body. No plaintext
card or actor is accepted as a wire identity claim.

The generic ledger's `createActionShare(seat, secretKey, position, source?)` is
the proof primitive behind this path. It checks complete deal/key binding, owned
remaining position, local deck consistency, and action budget, and rejects phase
advancement during randomness callbacks. Both the ledger's phase guard and the
receiver's lifecycle guard run after every random draw, including a zero or
out-of-range nonce rejected by the scalar sampler, before sampling can retry.
It neither validates Sasku rules nor
signs, persists, or consumes the position. The default randomness is the existing
CSPRNG; injected sources are trusted test dependencies, never a nonce-reuse or
retry mechanism.

Immediately before signing, the author guard rechecks lifecycle and snapshot
freshness and requires the native authored head to match the current accepted
own-sender head, including its hash. Both heads may have advanced through already
accepted housekeeping without changing the round snapshot. An unapplied authored
tail or another head disagreement requires recovery before any new signature.
All ordinary local game transitions must use this semantic owner; atomic sequence
allocation alone does not provide cross-tab game ownership or synchronization.

After the authored append commits, the receiver verifies the returned canonical
artifact against the exact intended unsigned bytes, including scope, sender,
sequence, predecessor, and body. Intended bytes and dependency arguments do not
alias. The original artifact then passes through the normal proof/rule/durable
receipt path inside the occupied queue, without re-enqueueing behind itself. Only
after local semantic commit does the method return the detached received artifact
and public snapshot. In the native shared database the accepted store sees a
duplicate row and preserves `authored: true`. No network broadcast occurs here;
transport readiness remains a separate prerequisite.

Authoring and local receipt are two commits, not one database transaction. A known
author-store invariant failure, an append rejection after signing was permitted,
a mismatched returned artifact, or failed/rejected local receipt after authored
commit stops the receiver. This is conservative even when an append reports an
abort: recover the verified durable history/checkpoint before trying another
local action. Never re-sign an already stored move; reapply/retransmit its original
bytes. An ordinary store error before its signing callback remains nonterminal,
and a later explicit attempt creates fresh proof randomness.

Closing before signing makes the guard reject and cancels queued work. Once
signing has occurred, the submitted append may settle and its successful original
artifact may finish local receipt even on the closed instance, unless a terminal
failure has intervened. Closing cannot erase a signature or committed row. Game
secrets are held only for the pending local operation, not added to public
snapshots, errors, or plaintext hand storage; memory erasure is not guaranteed.
Browser controls, readiness-aware delivery, outgoing setup coordination,
automatic contribution scheduling, verified shuffle provenance, and round/match
finalization remain separate work.

## Local Round Contributions

`authorDealShares(author, secretKey, expectedSnapshot, source?)` and
`authorAuditDisclose(author, expectedSnapshot)` explicitly author one currently
required local contribution. They share the action author's admission limits,
bounded FIFO, signing-time native/accepted-head check, independent intended bytes,
returned-artifact correlation, durable local receipt, and terminal recovery
behavior. Each reserves one pending slot and 64 KiB through both commits. Neither
method broadcasts, schedules another phase, or accepts a caller-selected body,
recipient, position list, or phase.

Admission still requires the exact current cached snapshot from this receiver;
an older view, clone, or another instance's snapshot is `stale_contribution`.
After admission, contribution freshness is phase-scoped rather than turn-scoped:
other pending donors or disclosers may commit ahead of the queued request while
the same obligation remains active. Execution and the pre-sign guard require
the captured deal/audit phase and the local seat still pending. They never move
a request to the next deal step. A local contribution consumed by receipt of its
original envelope prevents reauthoring, including when that receipt finishes the
audit. Repeated authorship is not retransmission; use the original signed bytes
through receipt/replay instead. `authorAction` retains its stricter whole-snapshot
freshness rule because a player's chosen move is tied to that turn's public state.

For dealing, the author must be a pending nonrecipient of the current private
step, and its supplied game scalar must match the accepted setup public key.
The ledger's `createDealShares(seat, secretKey, source?)` derives `to` and every
position from the retained schedule, in ascending position order. It prepares one
fresh proven share per position under the exact carrying game/round/deal phase,
then returns an immutable `{to, items}` body. It never computes the recipient's
missing share, opens hands, consumes contribution state, signs, or persists.
It works while private-hand reads still return `null`.

Key, eligibility, and exact-step checks precede protocol randomness. Every proof
uses a fresh nonce, and pending-step/member checks run before and after each
random draw as well as before returning the batch. A source exception, consumed
local obligation, phase advancement, closure, or terminal receiver failure
discards preparation without publishing a partial batch. Explicit transitions
performed reentrantly are not rolled back. Another donor's contribution within
the same step does not invalidate preparation while the local seat remains
pending. A later permitted pre-sign retry generates fresh proofs; a stored batch
must never be regenerated as a retry.

This is not an arbitrary-point share oracle or a substitute for deck provenance.
Canonical ciphertexts and correct DLEQ proofs alone do not establish secrecy:
identity or repeated `A` components can expose information even though proof
contexts are position-bound. A verified shuffle and the agreed schedule remain
production prerequisites; the supplied deterministic test decks are not secrecy
or shuffle fixtures.

For the supported completed Sasku hand, all 36 positions are already public.
`authorAuditDisclose` therefore signs exactly `{items: []}` under
`expectedSnapshot.audit.phase`, not the ledger's historical play cursor. It needs
the persistent signing identity, but no game-secret lookup or new decryption-proof
nonce. It is rejected before completed-hand audit begins or after that identity's
contribution is counted. A fourth valid disclosure remains successfully accepted
even if the resulting audit identifies an earlier action's hidden-rule violation.
The disclosures do not sign or establish agreement on that computed result.

Native integration uses four independent peer databases with one local game key
and a genuine authored prefix in each. Explicit delivery of original messages
drives dealing, 36 plays, and the audit to identical public states and canonical
65-envelope sets. Injected failures between authored append and local receipt
for both `SHARES` and `AUDIT_DISCLOSE` are recovered from original stored bytes
without re-signing. These tests now use the read-only round recovery factory below,
not hand-written phase sorting. Delivery is still test-only, not a production
reconnect controller or an enabled transport/gameplay path.

## Durable Sasku Audit

`snapshot.audit` is `null` until the final card play is durably committed. A
completed Sasku hand must have opened all 36 scheduled positions; otherwise the
receiver stops with an internal commit failure rather than blaming a player.
The completion snapshot starts an audit with `phase: "round.<r>.audit"`, all
four seats in `pendingSenders`, and `result: null`. The ledger's play cursor
remains historical bookkeeping, not authorization for another action.

Each seat contributes one signed `AUDIT_DISCLOSE` for that exact game, round,
phase, and finalized roster. The previously defined body codec is unchanged.
Because every scheduled card is already public at this point, each seat's
outstanding disclosure set is empty and the required body is exactly
`{items: []}`. Nonempty disclosures are unscheduled, even if their proofs are
valid. This is specific to completed Sasku hands, not a generic policy for games
with unplayed cards, early termination, stock, or dynamic dealing.

The same bounded FIFO, independent byte copies, durable session receipt checks,
and close/failure rules apply to disclosures. Scope, body, and contribution
checks precede persistence. Premature/wrong-phase messages are rejected without
storage, buffering, automatic retry, or a sender-forfeit claim. Exact signed
retransmissions are idempotent before and after completion; a newly signed
equivalent contribution from an already counted seat is conflicting, not another
vote. Only four additional canonical hashes are retained, keyed by seat.

Contributions may arrive in any order. Committed participation is represented
in ascending seat order, and a seat is removed from `pendingSenders` only after
verified durable receipt. A failed or chain-rejected fourth disclosure leaves
the audit pending with no result. Three disclosures, duplicate messages, or public
hand completion alone never complete the audit.

After the fourth durable contribution, the receiver reconstructs each original
hand by joining every verified position opening to its scheduled owner. It does
not infer ownership from contiguous nine-card ranges or accept a caller-supplied
plaintext hand. `auditSaskuHand` replays the normalized committed action history
with the explicit dealer and those reconstructed hands. The published local
result is either `{status: "valid", score}` or
`{status: "violation", seat, at, rule}`. `at` indexes the full action history,
including bidding and trump choice, not sender sequences or tricks. A violation
names the first earlier offending action; the last disclosure remains accepted
and is not itself blamed. Violations contain no audited score. Unexpected audit
exceptions or incomplete results stop the receiver with `commit_failed`, keeping
the last complete snapshot even though the final disclosure is already durable.

Audit state and results are immutable and published separately from the public
hand's unchanged `provisionalScore`. Restoring a partial disclosure set or a
post-persistence audit failure requires the same trusted round context and
verified original envelopes; replay rebuilds participation and the local result
through this receiver, including when the durable session already knows them.
No authoritative phase snapshot or result-agreement record is added to storage.

Four signed disclosures are not four signatures over the reconstructed history,
score, or violation. This increment adds no `AUDIT_OK` message, result digest,
violation certificate, timeout blame, automatic next round, match end, or game-key
deletion. The audit is valid relative to the supplied round context; verified
shuffle/deal provenance remains a production prerequisite.

## Read-Only Sasku Recovery

`PersistentSaskuRoundReceiver.recover(options, limits?)` synchronously constructs
a fresh receiver from a quiescent, already restored session registry and the same
explicit round context used for live receipt. It accepts the normal constructor
options, including the completed setup, ciphertext deck, schedule, dealer, and
exactly bound persistent session receiver. Options are captured once for both
construction and history validation. No caller-supplied transcript slice, phase
sorter, signing key, game secret, persistence callback, or replay callback is used.

The caller must first stop live processing and wait for submitted authoring and
receipt operations to settle, then load verified durable history and restore the
appropriate lobby/finalized sender chains and setup. The factory cannot discover
newer database or peer history, detect a consistently rolled-back prefix, or
cancel previously submitted writes. It does not create or repair authored
checkpoints, alter provenance flags, or replace the application's exclusive
game/identity ownership and synchronization barriers.

Recovery captures every roster sender's complete sequence-zero-through-head
prefix, not merely the records that look like current-round traffic. All four
chains must exist. Default limits are 1,024 envelopes and 16 MiB of original wire
bytes, configurable by positive safe `maxEnvelopes` and `maxBytes`. Counts are
checked before range allocation, bytes before copying/decoding, and all history
is charged, including ignored control records. A limit failure never yields a
truncated recovered state. The normal 64 KiB ceiling still applies to selected
round messages; these limits do not bound an earlier IndexedDB `getAll()` load or
guarantee a wall-clock execution time.

All original byte views are copied before verification. Recovery reverifies
canonical encoding, signatures, game/sender/sequence identity, zero genesis,
every predecessor link, and the final captured head. Fresh artifacts must also
classify as exact duplicates in the bound registry, detecting contradictory
cached hashes. Private verified artifacts are not handed to cache/classifier
dependencies without separate copies. Heads, source bytes, and cache agreement
are checked again before returning; a detected source change aborts recovery.

The signed setup records are independently replayed using `recoverSetup`, which
must finish and match the supplied setup's per-seat public keys, aggregate key,
and beacon seed. Each selected round envelope must follow its sender's first
setup randomness reveal in sender-sequence order. Matching game/roster fields on
a separately completed but different setup are not sufficient.

This first factory supports one gameplay round in the registry. Every `SHARES`,
`ACTION`, `AUDIT_DISCLOSE`, and `SHUFFLE` record must name the requested round;
preceding or future round traffic is rejected rather than silently omitted.
Setup records are semantically verified as above. Lobby records and housekeeping
(`WITNESS`, `SYNC_REQ`, `SYNC_RESP`, `TIMEOUT_VOTE`, `VIOLATION`) are authenticated
as chain history, but their body semantics and operational effects are not
restored. Nested `SYNC_RESP` artifacts are not imported as separately accepted
originals. Current-round `SHUFFLE` records are also chain-only: the supplied deck's
verified provenance remains an external prerequisite. New message types require
an explicit selection policy; none are silently ignored by a default branch.

Selected round messages retain each sender's authenticated sequence order.
Recovery repeatedly considers only the next unconsumed message from each seat,
choosing the first seat whose type and exact phase match the current deal, action,
or audit state. It applies the same semantic classification, public-rule preview,
proof checks, ledger/hand commit, and audit logic as live receipt. It never sorts
a later same-sender message ahead of an earlier one to repair misleading phase
labels. Every selected message must be consumed; messages left behind a missing
prerequisite, a phase alias, or an impossible ordering cause failure. Exhausting
the selected history can legitimately leave a partial deal, hand, or audit.
This is a deterministic legal merge, not reconstruction of historical cross-peer
arrival order or the canonical export ordering.

Live receipt and recovery share private synchronous semantic operations. Their
arguments are isolated, action content comes from private canonical bytes, and
commit results must match the original type, seat, status, bytes, and previewed
play before a snapshot is published. Recovery never calls either public receive
method, persists even a duplicate, ingests into the bound registry, authors an
envelope, accesses a game secret, or generates new protocol randomness/proofs.
The supplied setup/session/store and an existing receiver remain unchanged by
recovery. If verification or a later replay commit fails, no partial receiver is
returned; history failures use `SaskuRoundRecoveryError` (invalid constructor or
limit arguments may retain their normal type/range errors).

A successful result has restored exact-replay memory, public state/history, and
audit participation/result, and remains bound to the supplied live session
receiver for subsequent ordinary receipt or authoring. Callers separately load
the existing game key for private-hand access or future proof preparation; no
key is regenerated. An open recovered round object is not session readiness or
permission to ignore terminal housekeeping, shuffle verification, match policy,
or peer agreement. Multi-round recovery, complete control-state recovery, and
automatic browser reconnect remain separate work.

## Bounded Round Inbox

`SaskuRoundInbox({receiver, session, self, maxPendingEnvelopes?, maxPendingBytes?})`
is a headless incoming scheduler for one restored Sasku round. The concrete
receiver must be bound to that exact session registry, and `self` must be one of
its four roster identities. Scope, local identity, round, and initial-deal count
are captured at construction. This is not transport authentication or session
synchronization: the caller must use the matching transport/game/roster and
supply an already-authenticated, session-ready direct-peer identity.

`receive(remote, payload)` privately copies and verifies a complete signed
envelope, requiring `from === remote`, the correct game/round, and a non-self
roster peer. Normal-operation relaying is rejected. Only `SHARES`, `ACTION`, and
`AUDIT_DISCLOSE` belong here; setup, witnesses, synchronization, timeouts, and
violations require their own validated dispatchers. Historical relay/range
traffic must not be disguised as a direct peer's original message.

Admission checks exact canonical phase spelling and bounded indices against the
retained round/deal configuration, plus strict wire-body syntax. It does not
verify future share equations, open a card, or advance either chain or game state.
Defaults allow 32 pending envelopes and 1 MiB of original wire bytes, including
both active and deferred work; every frame is at most 64 KiB. Reservations precede
copying, signature verification, and body decoding. Exact duplicate calls each
retain their own charged entry and promise, avoiding unbounded coalesced waiters.
Different signed bytes for the same pending sender/sequence are rejected without
replacing the original entry. Admission failures release their reservation.

Pending queues are ordered by signed sender sequence, preserving admission order
for equal-sequence duplicates. The scheduler considers only each seat's head and
rotates fairly among eligible seats. A sender-chain gap or a future deal/action/
audit phase is held without invoking durable round receipt. Other senders'
prerequisites can proceed; an earlier future message from one sender is never
skipped to process its later, conveniently phased message. This addresses legal
cross-sender reordering, not just ordering within a single RTCDataChannel.

Eligible current/past messages go through normal round receipt for authoritative
proof/rule validation, persistence, and exact replay. Broken predecessors or
equivocation can be reported directly as chain rejections. Ordinary semantic or
storage exceptions reject the attempted call without automatically retrying it;
fulfilled rejected receipt statuses are likewise reported and removed. Later
sequence numbers remain blocked if their predecessor was not accepted. Missing
history, impossible sender ordering, stalled peers, or resource exhaustion may
require the external coordinator to stop and recover; no timeout blame or forfeit
certificate is inferred from deferral.

New admissions and completed inbox receipts drive further scheduling. After
external **local authoring or durable housekeeping** changes prerequisites, the
lifecycle owner must call `processPending()`. Progress requests made during a
drain are retained, including requests or admissions made by observation callbacks;
redundant wakes without observable progress do not poll the queue. There are no
timers, network retries, new signatures, or proof generation in this scheduler.

The scheduler waits for `receiver.whenIdle()` before choosing work and rechecks
receiver activity and the selected queue head before submission. Its own
`whenIdle()` and `processPending()` promises mean **drain quiescence only**: they
can resolve while future/gapped envelopes remain buffered. Each `receive()` promise
settles only when its own attempt completes or is cancelled/rejected. Observe
both rejected promises and fulfilled `{status: "rejected"}` outcomes. In particular,
the mesh's ordinary synchronous `onMessage` callback does not await returned
promises; a dispatcher must explicitly attach outcome/error handling rather than
leave asynchronous errors unobserved. Neither idle API proves peer catch-up,
transport readiness, or an empty network.

Receipt artifacts and dependency arguments are isolated from retained wire bytes.
Successful receipts must be reflected in the bound registry with matching original
bytes and hashes. Receipt and registry byte views are copied using intrinsic
typed-array sizes before comparison, so dependency-controlled `length` accessors
cannot bypass correlation. Unexpected receipts or underlying terminal receiver
failure stop the inbox and reject remaining work; no peer connection is closed or
replaced by the inbox itself.

`close()` cancels and releases all unsubmitted entries, including deferred work.
It unblocks an inbox drain waiting only on unrelated receiver activity, without
cancelling that activity. An already submitted round receipt keeps its budget
until it settles and may commit/resolve after close. Closing the inbox does not
close its receiver, session, database, or transport. The lifecycle owner must
explicitly close it to promptly retire dormant work on shutdown/disconnect and
must fence stale connection callbacks/results appropriately. Buffered messages
are volatile and not a durable delivery acknowledgement; original-author history
and verified synchronization remain the recovery source.

Four independent IndexedDB peers exercise a next deal step arriving before another
sender's prior-step share, a later play arriving before the prior actor's play,
and audit disclosure arriving before another actor's final card. Deferred originals
cause no writes or public-state changes until prerequisites commit; the peers
then converge on the same 65 envelopes and audit. Those tests directly invoke the
inboxes with fixture-authenticated identities. They do not implement a live mesh
dispatcher, outbound fan-out, synchronization completion, verified shuffling,
or browser gameplay.

## Randomness Beacon

The `RAND_COMMIT` body is exactly `{cm}`, where `cm` is a 32-byte SHA-256 digest.
The `RAND_REVEAL` body is exactly `{s}`, where `s` is a 32-byte random secret.
Neither map permits extension fields.

For a fixed game, round, and finalized three-to-eight-seat roster, commitments
may arrive in any order. Reveals are rejected until exactly one commitment from
every seat has been accepted. A reveal is accepted only when recomputing
`beacon_commitment` for its seat matches the stored commitment. Once every
reveal is accepted, the output is:

```text
seed = SHA-256(secret[0] || secret[1] || ... || secret[N - 1])
```

The concatenation order is always ascending seat order, independent of network
arrival order. Exact retransmissions are classified as duplicates; conflicting
commitments, conflicting reveals, phase-inappropriate messages, and commitment
mismatches are distinct deterministic rejection outcomes. Timeout processing
will separately turn a missing commitment or reveal into violation evidence.

## Durable Setup Receipt and Recovery

`PersistentSetupReceiver` privately owns its `SetupEnvelopeCoordinator`. Its
constructor takes `{round, self, session, sessionReceiver, maxPendingEnvelopes?,
maxPendingBytes?, historyLimits?}` rather than accepting an externally mutable
coordinator and structural persistence callback. The concrete durable receiver
must be bound to that exact finalized session registry, and the explicit local
identity must belong to its three-to-eight-seat roster. Game and ordered roster
come from that registry; no seat or setup-round policy is guessed. The private
workspace callers have been migrated; signed wire formats and persisted originals
are unchanged by this API change.

Construction is readonly: `captureSessionHistory` snapshots and verifies complete
available sender prefixes, then `recoverSetup` reconstructs empty, partial,
complete, or collectively failed setup. Generic capture permits empty seats for
fresh setup, while the Sasku round-recovery layer still requires its complete
four-seat setup. Defaults cover 1,024 envelopes and 16 MiB across all history,
including controls; `historyLimits` may override these bounds. Every selected
setup envelope is also limited to 64 KiB. Capture verifies signatures, exact scope,
sequence/predecessor/head/cache agreement, and source stability without ingestion,
storage calls, or signing. Its seat-grouped output is not a semantic ordering or
canonical export container by itself.

The caller must quiesce previous work and restore the registry from all durable
originals, including authored-but-unapplied records, before construction. Existing
lobby prefixes are retained; setup does not restart sender sequences at zero.
Control effects, registry freshness, and network synchronization remain external
prerequisites. Construction cannot detect a consistently rolled-back database or
cancel already submitted operations elsewhere.

The cached public snapshot contains `state`, `pendingSenders`, per-seat
`publicKeys` and `commitments`, `aggregateKey`, and `seed`. Cryptographic public
values are hex strings or `null`, with frozen containers, not mutable byte views.
No game scalar or beacon preimage appears in this snapshot. Pending obligations
are derived from core setup/beacon state rather than a second mutable ledger.

One bounded FIFO serializes incoming setup receipt and local authoring. Defaults
are 32 admitted operations and 1 MiB of pending wire capacity; incoming setup
envelopes are at most 64 KiB and local authoring reserves the full 64 KiB ceiling.
Admission reserves before copying/verifying. Classification and ingestion each
derive authoritative data from freshly verified canonical signed bytes, not a
mutable decoded envelope view. Independent buffers and correlated transition
metadata prevent a different valid decoded proof from replacing the signed one.

A semantic rejection never reaches accepted-chain persistence. Accepted,
duplicate, and collectively failed candidates first receive a matching durable
receipt, checked against the original bytes, recognized statuses, recorded row,
and cached accepted hash. Only then does setup commit and publish a new snapshot.
Returned artifacts do not alias retained registry or commit buffers. Ordinary
pre-persistence storage errors and chain rejections leave setup unchanged; corrupt
receipts, unexpected classification/commit exceptions, or invariant failures stop
the owner and reject queued/future work for recovery. No partial coordinator is
exposed after such a failure.

The all-valid-shares-but-identity-aggregate result remains a valid durable
`status: "failed"` transition. It publishes setup state `failed`, not an invariant
`failure`, and returns the last original artifact for consistent peer processing.
It does not blame the last contributor, permit randomness commitment/reveal, or
produce a completed handoff.

`close()` cancels queued work and stops admission. Submitted work settles under
the normal durable rules. `whenIdle()` observes the next empty admitted queue,
including local preparation/authoring, but is not a lock or a shared control/
transport barrier. `getCompletedSetup()` returns the concrete coordinator needed
by the round ledger only after complete, idle, non-failed publication; a closed
but successfully completed owner may still hand it off. A completed core has no
new valid setup contribution to accept. Before completion no mutable coordinator
reference escapes.

Pure setup recovery re-verifies the scoped transcript and rejects duplicate
`(sender, sequence)` tuples, another game, non-roster setup senders, malformed
bodies, bad proofs, and impossible phase histories. It ignores non-setup message
types, orders setup contributions by key-share, commitment, and reveal phase,
then by finalized seat and sender sequence, and applies normal semantic checks.
The first commitment from each sender must follow that sender's first key share,
and the first reveal must follow its first commitment. This reconstructs partial,
complete, or collective-failure setup state without using IndexedDB arrival
order. Sender-chain recovery remains a separate prerequisite that proves every
sequence and predecessor link.

## Guarded Setup Authoring

The owning receiver exposes three explicit operations:

```text
authorKeyShare(author, gameSecretStore, expectedSnapshot, source?)
authorRandCommit(author, beaconSecretStore, expectedSnapshot, source?)
authorRandReveal(author, beaconSecretReader, expectedSnapshot)
```

The persistent author must match the owner's game and local identity. Its actual
native store must support readonly head inspection. The authored, accepted, and
private stores must belong to the intended isolated local identity/database;
particularly, the existing game-key store is keyed by game rather than identity.
No caller-selected setup body, sender seat, or wire phase is accepted.

Admission requires the owner's actual cached snapshot. Queued execution and
pre-signing require the captured setup stage and local seat still pending, while
allowing other participants to contribute first within that stage. Both random
message types use `setup.rand`, so the distinct `rand_commit` and `rand_reveal`
states—not that wire string alone—authorize their operations. A consumed local
obligation is rejected before native-head reads, private loads/creation, or proof
generation. Old messages are retransmitted through original-byte replay, not
another authoring call.

Before any private preparation, `author.readHead()` must match the current accepted
own-sender head, its cached hash, and original recorded bytes. An unapplied native
tail or inconsistent checkpoint requires recovery before creating a secret or
fresh proof. A synchronous `beforeSign` guard repeats this check after preparation;
accepted housekeeping may advance both matching heads without changing setup
eligibility. All setup semantic traffic must still pass through this single owner.

`KEY_SHARE` is authorized only during `keys` with the local key pending. It waits
for atomic game-key persistence and a post-await eligibility guard before creating
its fresh PoP. `RAND_COMMIT` is authorized only after aggregate-key completion,
with the local commitment pending, and awaits its scope-bound beacon-secret commit.
`RAND_REVEAL` is authorized only after every roster commitment has been accepted
and the local reveal remains pending. It uses load-only restoration against the
owner's accepted local commitment; missing or mismatched preimages cannot trigger
get-or-create, replacement randomness, or a new signature.

Intended content and author-dependency arguments use independent wire copies.
Returned authored bytes must match the exact guarded unsigned envelope before
the original enters local durable receipt inline within the occupied queue.
An artifact is returned only after local semantic receipt succeeds; a legitimate
aggregate-key failure is also returned as the accepted collective outcome.
There is no broadcast here. Author append and local receipt are separate commits:
an uncertain post-permission append or failed local application stops further
work. Reconstruct from all stored originals before signing again; do not regenerate
a KEY_SHARE proof or re-sign an already recorded commitment/reveal.

Closing before signing prevents further private/proof work and a new signature,
even when secret storage or a native-head read was pending. Once signing was
permitted and the native append succeeds, its original may finish local receipt
after close unless an invariant failure has intervened. The active reservation
lasts until settlement; closing cannot erase a signature, checkpoint, or unused
private value already committed to its store.

Independent IndexedDB peers now exercise all three authoring APIs, restart at
each stored-but-unapplied boundary, replay byte-exact originals, and complete the
same aggregate key and seed. Tests also retain native lobby prefixes and hand the
completed coordinator to a supplied-deck Sasku round. The owner does not schedule
contributions automatically, defer cross-sender future setup phases, route controls,
grant session readiness, establish shuffle provenance, or select dealer/match
policies. Those integrations remain separate work.

The base specification names a phase snapshot in the `games` record but does not
define its byte schema, validation rules, versioning, or atomic relationship to
the transcript append. No authoritative phase snapshot is written until those
choices are profiled. The signed transcript remains the recovery source of truth.

## Signaling and Data Frames

The signaling adapter uses the specification's four-operation interface and
carries opaque directed byte strings only. Its string `roomId` is the lowercase
hexadecimal encoding of the 32-byte `room_id` digest. The deterministic in-memory
adapter admits one active adapter per identity in a room, copies identities and
payloads at its boundaries, queues delivery in microtask order, isolates rooms,
and permits the same identity to rejoin after leaving. These are test-adapter
semantics, not a trust guarantee; signaling remains adversary-controlled.

SDP and ICE signaling payloads are Core Deterministic CBOR. An SDP description
is exactly `{kind: "description", description_type, sdp}`, where the description
type is `offer` or `answer` and `sdp` is non-empty UTF-8 text of at most 256 KiB.
An ICE payload is exactly
`{kind: "candidate", candidate, sdp_mid, sdp_mline_index, username_fragment}`.
Text candidate fields are nullable, the candidate is at most 4 KiB, the other
text fields are at most 256 bytes, and the nullable media-line index is a uint16.
The all-null candidate payload is the end-of-candidates marker. No encoded
signaling payload may exceed 257 KiB.

For every pair in a finalized three-to-eight-seat roster, the implementation
creates one `RTCPeerConnection`. The lexicographically smaller identity is
impolite and the larger identity is polite. Description work is serialized per
peer and follows the perfect-negotiation collision algorithm; the polite peer
relies on automatic ICE rollback, while the impolite peer ignores a colliding
offer and retransmits its outstanding offer. Exact description and candidate
replays are idempotent. Candidates received before their matching description
are bounded and buffered by ICE username fragment. Defaults allow 256 pending
candidates and 512 accepted non-null candidates per peer's active remote ICE
username fragment. Renegotiation with the same fragment does not reset acceptance
or deduplication state; a changed fragment does. The end-of-candidates marker is
deduplicated separately and does not consume a candidate slot.

RTC configuration must contain a STUN URL. The default uses the two STUN URLs in
the base specification with `iceTransportPolicy: "all"` and
`bundlePolicy: "max-bundle"`; deployment configuration may add TURN. Each side
creates the same externally negotiated channel with label `p2pcards`, ID zero,
`ordered: true`, and no retransmit or lifetime limit. Any in-band, duplicate, or
unreliable channel is closed. The channel callback is deliberately named
`onUnauthenticatedDataChannel`: only the authenticated transport facade may
consume it, and application payloads must not be attached directly.

## Nostr Signaling

`TrysteroNostrSignalingAdapter` implements signaling only. Trystero is pinned to
`0.25.4` and supplies its public `createEvent` function and default relay list.
Its `joinRoom`/`makeAction` APIs are deliberately not used: they own negotiation
and an in-band data channel, which conflicts with the profiled mesh and `HELLO`
boundary. All peer connections remain owned by `FullMeshTransport`. This adapter
is not an alternative client for Trystero-managed rooms.

The application namespace defaults to `p2pcards/v1` and is non-empty text of at
most 128 UTF-8 bytes. The room ID remains the 64-character lowercase hex digest
defined above, not the raw game identifier. The exact derivations are:

```text
context = cbor({app_id: appId, room_id: roomId})
topic = lowerhex(SHA-256("p2pcards/v1/nostr-signal/topic" || context))
key = SHA-256("p2pcards/v1/nostr-signal/key" || context)
aad = SHA-256("p2pcards/v1/nostr-signal/aad" ||
             cbor({app_id: appId, room_id: roomId, topic}))
```

Strings before `||` are exact ASCII bytes without terminators. The key is imported
as a non-extractable AES-256-GCM key. Room-key encryption is signaling hygiene,
not identity authentication: anyone who knows the room ID and namespace can
decrypt and author signaling, including arbitrary `from` claims. Neither the
Nostr signer nor a relay acknowledgement authenticates a roster identity. The
reciprocal signed DTLS-fingerprint `HELLO` remains mandatory.

Each directed payload is split using the existing 16 KiB frame schema. The
plaintext of one event is exactly the canonical CBOR map `{from, to, frame}`:
`from` and `to` are 32-byte identity byte strings, and `frame` is a byte string holding
one complete canonical encoded data frame. Only a packet addressed to the local
identity, and not claiming the local identity as its sender, reaches reassembly.
Reassembly is separate for each claimed sender. Signaling frame IDs start at a
random uint32 read big-endian from four CSPRNG bytes on each join and increment
modulo 2^32 for each send. These IDs do not share the data channel's `HELLO`
reservation.

The Nostr event `content` is canonical unpadded base64url of:

```text
0x01 || nonce[12] || AES-256-GCM(key, nonce, plaintext, aad).ciphertext || tag[16]
```

Every fragment uses a fresh 96-bit nonce from the injectable CSPRNG. The tag is
128 bits. Decoding rejects unknown versions, padding, non-zero unused base64
bits, malformed canonical CBOR, extension packet/frame fields, oversized chunks,
and failed GCM authentication. The fixed topic, key/AAD, and encrypted packet
fixture is generated independently with a small CBOR encoder and Node's
`createCipheriv("aes-256-gcm")`; tests also cover nonce, ciphertext, tag, and
wrong-room rejection.

Trystero's ephemeral event kind is `20000 + (sum(ASCII(topic)) mod 10000)` and
the event has the tag `["x", topic]`. The adapter serializes its own stateless
`["REQ", subscriptionId, {kinds: [kind], since, "#x": [topic]}]` request, avoiding
Trystero's module-global subscription bookkeeping. `since` is the integer Unix
time in seconds when the subscription is constructed. Its 32-character
subscription ID is the first 32 lowercase hex characters of:

```text
SHA-256("p2pcards/v1/nostr-signal/subscription" || cbor({topic, self}))
```

Relay URLs must use `wss`, except for local development on `localhost`,
`127.0.0.1`, or `[::1]`. Credentials and fragments are rejected; URLs are
normalized with `URL.toString()` and deduplicated. At most 64 configured URLs,
each at most 2048 UTF-8 bytes, are accepted. By default the adapter selects five
relays, or the whole list if shorter. Selection sorts ascending by:

```text
lowerhex(SHA-256("p2pcards/v1/nostr-signal/relay" || cbor({topic, url})))
```

Ties use normalized URL code-unit order, never locale collation. Peers must use
matching namespace, relay list, and selection settings to obtain the same
subset. Deployment should supply a reviewed relay list rather than assume
public default relays have a particular availability or access policy.

Startup waits for each selected relay to finish subscribing (`EOSE`), fail, or
reach the 10-second connection deadline. At least one ready relay is required.
Failed sockets reconnect with exponential delays from one to 30 seconds and
resubscribe before becoming usable. `CLOSED`, negative publication `OK`, socket
failures, and acknowledgement timeouts are surfaced through bounded diagnostics.
Late callbacks from retired sockets or earlier room memberships cannot modify
the current membership.

A send publishes its bounded fragment set without serial acknowledgement waits,
then requires at least one positive (or `duplicate:`) relay `OK` per fragment.
The default acknowledgement timeout is 5333 ms. Up to 16 whole-message sends may
be active concurrently; admission is checked before copying/encrypting payloads.
The 257 KiB payload bound permits at most 17 fragments per send. Recent events
are eligible for best-effort replay for 30 seconds on newly ready relays that
have not acknowledged them, with a 128-event retention cap. An acknowledgement
from replay can also complete the original pending send.

These are publication acknowledgements, not peer receipts. Nostr events are
ephemeral; late peers, unavailable or disjoint relays, eviction, relay policies,
or a hostile signaling path can still lose traffic. Recovery outside this
bounded replay window requires a caller-driven negotiation retry. The adapter
does not provide reliable exactly-once delivery or session resynchronization.

Receive limits apply before expensive decoding: at most 32 * 1024 UTF-16 code
units in a raw WebSocket message and 24 * 1024 ASCII characters in the base64url
event content. The default queue
holds at most 256 events. Deduplication uses a SHA-256 digest of ciphertext
content rather than trusting relay-supplied event IDs and retains at most 4096
digests. Queue-admission failures are not marked seen; transient reassembly
capacity failures can be retried. Duplicate suppression is bounded, not a
cryptographic replay-prevention guarantee.

Reassembly defaults to 16 concurrent claimed senders, 64 groups per sender,
257 KiB per message, and 514 KiB of aggregate pending chunk bytes. Identical
chunks do not consume extra capacity. Expiry is timer-owned at the earliest
group deadline, 30 seconds after its first chunk; idle sender state is removed.
Failure retention defaults to 128 records. Leave closes owned sockets, rejects
pending publications, cancels reconnect/expiry timers, and clears membership
state; delayed asynchronous work remains isolated from any later join.

## ICE Path Diagnostics

Both mesh APIs expose `connectionPath(remote)`, which reads `getStats()` without
exposing a raw channel. It follows a transport's `selectedCandidatePairId` to
the local and remote candidate records. Without that pointer it accepts one
unambiguous succeeded/selected pair, or one unambiguous succeeded/nominated pair.
Ambiguous fallback pairs produce `unknown`, not a guessed active path.

Either endpoint's candidate type `relay` produces `relayed`. Two known non-relay
types (`host`, `srflx`, or `prflx`) produce `direct`; otherwise the path is
`unknown`. The immutable snapshot includes the selected pair ID and candidate
types, but no addresses or TURN credentials. These are local diagnostics, not
authentication or authorization evidence. Injected peer implementations without
`getStats` report that statistics are unavailable.

## Channel HELLO Authentication

`HELLO` is not an envelope and carries no game field. It is one Core
Deterministic CBOR map with exactly `{pk_id, local_fp, remote_fp, sig}`. The
identity key and both SHA-256 fingerprints are 32-byte strings, the Ed25519
signature is 64 bytes, and the complete encoding is limited to 256 bytes. For a
sender, the signed bytes are exactly:

```text
chan_ds || game_id[16] || local_fp[32] || remote_fp[32]
```

The game identifier is trusted local channel context rather than duplicated in
the map. Signing derives `pk_id` from the signer key. Verification first checks
canonical encoding and the Ed25519 signature, then requires `pk_id` to equal the
expected roster peer, the sender's `local_fp` to equal the remote SHA-256
fingerprint observed locally, and the sender's `remote_fp` to equal the local
certificate fingerprint. Direction is therefore always from the signer's point
of view.

SDP fingerprint extraction accepts one unique, colon-separated `sha-256`
fingerprint. Identical copies across bundled media sections are accepted;
missing, malformed, or conflicting values are rejected. The mesh exposes local
and remote parsed fingerprints only after both SDP descriptions are installed.

Frame ID zero is reserved for `HELLO`, which must fit in exactly one frame with
index zero and count one. Outbound application IDs begin at one. The
authenticated-channel boundary sends no application bytes and invokes no
application receive callback until its local `HELLO` has been queued and the
remote `HELLO` has passed every check. Any other first payload, reused ID zero,
invalid signature, wrong game, wrong identity, fingerprint mismatch, non-binary
message, malformed frame, or resource-limit violation closes the channel. A
configurable local timer defaults to 30 seconds for reciprocal authentication.

`AuthenticatedMeshTransport` is the browser-facing composition boundary. It
requires the local identity to match its Ed25519 signing key, waits for SDP and
the negotiated channel to become available, extracts both fingerprints, and
constructs one authenticated-channel gate per remote roster identity. Its peer
authentication callback reports successful reciprocal `HELLO`, not session
readiness. The application receive callback and ordinary send path additionally
require the explicit synchronization gate below. The lower-level full-mesh
raw-channel callback exists solely for this composition and is not an application
API.

Every data-channel frame is one Core Deterministic CBOR map with exactly
`{id, index, count, bytes}`. `id` is a uint32, `index` and `count` are uint16,
`count` is at least one, and `index < count`. `bytes` contains at most 16 KiB.
The profile represents an empty payload as one frame with empty `bytes`; an empty
chunk is rejected when `count > 1`. The standard splitter fills each non-final
chunk to 16 KiB and copies all source bytes.

Reassembly accepts chunks in any order. An exact repeated chunk is idempotent;
a changed chunk or changed count for an active ID discards that group. The
30-second lifetime starts at the first accepted chunk and is not extended by
later chunks. Callers must invoke expiry on their scheduling boundary when no
new frames arrive. The implementation defaults to 8 MiB per message, 512 frames
per message, 64 pending groups, and 16 MiB of pending chunk bytes. These are
configurable local resource limits rather than additional frame fields.

The framed sender defaults to an 8 MiB outbound limit. It pauses before a frame
when `RTCDataChannel.bufferedAmount` exceeds 4 MiB, sets
`bufferedAmountLowThreshold` to 2 MiB, and resumes on `bufferedamountlow` while
rejecting channel closure or failure. Concurrent sends to one channel are
serialized before applying this policy. Encoded frame and signaling sizes are
bounded before CBOR decoding. Authenticated channel receivers enable timer-owned
reassembly expiry so incomplete groups are discarded even when no later traffic
arrives.

## Peer Reconnection

Each finalized-mesh roster slot has a local safe-integer generation starting at one. A
replacement increments only that slot, creates a new `RTCPeerConnection` and the
same reliable negotiated channel, and performs fresh reciprocal `HELLO` using
that connection's observed fingerprints. Generations are local lifecycle tokens,
not signed protocol fields or shared epochs: a restarted browser can be at local
generation one while its existing peer is at generation two. The transport does
not change the roster, identity key, game ID, sender chains, or durable history.

`reconnectPeer(remote)` retires/replaces the selected roster peer and initiates
SDP negotiation without leaving the signaling room or resetting other peers.
Its promise covers SDP signaling submission only. It does not wait for channel
opening, `HELLO`, or synchronization; applications use `readyFor(remote)` for the
subsequent local readiness barrier. Reconnecting an unknown roster identity is
rejected. The low-level `disconnectPeer(remote, generation?)` is idempotent and
ignores a mismatched expected generation, preventing stale owners from retiring
their replacements. Generation overflow fails closed.

Native connection states `disconnected`, `failed`, or `closed`, and data-channel
closure, retire the current generation. Retirement revokes the generation before
calling observers or closing native objects, cancels queued-operation waits, and
notifies disconnection once. This increment deliberately treats even transient
`disconnected` states conservatively; reconnect attempts are caller-driven, not
an automatic authentication or connection retry loop.

An offer for a retired known peer creates a replacement. A changed SDP origin
session ID or changed valid SHA-256 DTLS fingerprint can also identify a remote
browser restart while the old local connection still appears connected. Ordinary
SDP version changes within the same origin are not restart evidence. Eight
observed retired remote session records per slot suppress known stale SDP.
Answer-derived session metadata is committed only after successful
`setRemoteDescription`; a rejected answer cannot poison restart detection.
In-flight offer metadata is tracked so a fresh offer can supersede a stalled
old operation.

SDP origin IDs, fingerprints before `HELLO`, and ICE ufrags remain untrusted
signaling hints, not identity authentication. No signaling fields were added.
An indistinguishable restart or replay of an evicted session can still require
caller-driven retry; a hostile signaling path can always prevent progress.

Future-ufrag trickle candidates are buffered on receipt, including while the old
slot is retired or its operation queue is stalled. The existing 256-candidate
default bounds this buffer. On offer-driven replacement, only candidates with
non-null ufrags matching the new offer migrate. Known old/ignored generations,
null-ufrag candidates, end-of-candidates markers, and nonmatching candidates do
not migrate. Caller-driven replacement without an incoming offer does not adopt
saved candidates. Only candidate data transfers; old queues, callbacks, and
acceptance counters never do.

All saved native callbacks and asynchronous WebRTC work are checked against
their exact current peer generation. Late completion cannot signal on, mutate,
or retire a replacement. Already-submitted signaling cannot be recalled, so
remote-side checks and fresh `HELLO` remain necessary. Reconnection does not reset
or extend the active game phase's deadline.

## Session Readiness Gate

`AuthenticatedMeshTransport` requires a trusted session-owned
`synchronizePeer(context): Promise<void>` function. There is no default successful
sync. It runs after `HELLO` on every connection, including the first connection
after a browser reload. The local states are:

```text
connecting -> authenticating -> synchronizing -> ready
                    any live state -> closed on retirement/failure
```

The context contains defensive-copy `remote` identity bytes, the local
`generation`, an `AbortSignal`, `send(payload)`, and `onMessage(handler)`.
These capabilities carry authenticated framed bytes without exposing the raw
channel. They are usable only during that exact generation's synchronization.
The synchronizer must register its receive handler before expecting traffic;
pre-ready traffic without a handler fails closed. Before readiness, completed
payloads go only to this handler, never the ordinary application `onMessage`.
The ordinary facade `send` rejects until ready.

Synchronization handlers may be asynchronous and are serialized. The default
queue permits 64 complete messages and 8 MiB of queued payload bytes. Overflow,
handler rejection, a non-promise synchronizer result, synchronizer rejection, or
the local 30-second synchronization timeout closes the generation. A fulfilled
synchronizer promise does not open the gate until its queued receive work has
also settled successfully. A throwing ready observer likewise fails closed.
The timeout is a configurable local resource deadline, not a forfeiture verdict.

After success, `readyPeers` includes the peer, `readyFor(remote)` resolves, and
`onPeerReady` reports readiness. `authenticatedPeers` and `authenticationFor`
continue to describe only the weaker `HELLO` boundary. Resolving a readiness
promise is not a permanent lease: each application send checks current readiness
again, and disconnection revokes it immediately. Successful synchronization
disables the context's send/receive-registration capabilities; retirement also
aborts its signal and rejects any still-pending readiness promise.

Old synchronization completions cannot unlock a replacement. Cancellation
releases unstarted queued payloads even if an external receive handler never
settles, and late rejection remains observed. Already-running external storage
work is not rolled back by the transport; the session owner must honor the abort
signal and its own mutation/commit rules. Diagnostics may retain an obsolete
failure, but identity-only error callbacks are suppressed after that failure's
generation has been replaced, including reentrant abort/disconnect observers.

The trusted synchronizer must resolve only after signature, game, roster, chain,
phase/body/authority validation, required durable commits, and semantic-state
recovery under the active game deadline. It must preserve the serialized
classify-persist-commit owner; calling the mutating `applySyncResponse` helper
directly on a live persistent registry bypasses this boundary. The transport
does not infer success from receiving any one payload, from authentication, or
from an empty/partial witness. This is a per-peer local gate, not a whole-game
resume decision or a proof that a session synchronizer was implemented correctly.

The wire controller for this hook remains unimplemented pending an exact profile
for complete head discovery, completion/watermark agreement, handling chained
control envelopes across the gaps they repair, response correlation, historical
control replay, broadcast routing, bounded range paging, and deadline behavior.
Existing `WITNESS`, `SYNC_REQ`, and `SYNC_RESP` body schemas are unchanged. No
new reconnect phase, chain exemption, unsigned control message, or repurposed
lobby `READY` is implied by this local API. Transport tests use explicit
orchestration fixtures, including the durable requested-range receiver below,
not a production catch-up controller.

## Bounded Range Planning

`preflightSyncResponse` is a pure validation/snapshot operation. It defaults to
128 envelopes per range and 4 MiB of aggregate canonical artifact bytes. Counts,
inclusive range spans, and aggregate byte lengths are checked before artifact
verification/copying. Sequence arithmetic remains safe at
`Number.MAX_SAFE_INTEGER`; a giant advertised range is not expanded into an
array. Valid results contain independently reverified artifact/request snapshots;
invalid metadata, signatures, canonical encodings, or internal links cannot
advance a valid prefix.

`serveSyncRequest` serves only a complete local range of at most 128 envelopes
and 4 MiB of canonical artifact bytes. It reverifies source records and returns
independent snapshots rather than exposing mutable accepted-record buffers.
Oversized ranges fail locally; no partial response, empty terminator, or new
negative-acknowledgement wire format is introduced. `applySyncResponse` shares
preflight but remains an in-memory-only helper: its `applied` result can contain
individual chain rejections and is never a durable catch-up or readiness signal.

`planWitnessSyncRequests` first reverifies a bounded canonical `WITNESS` artifact
and requires that exact outer envelope to already classify as a duplicate in
the registry. An immediately admissible but not-yet-accepted outer is not enough;
gapped, conflicting, wrong-game, and unknown-sender outers cannot authorize claim
planning. Callers must invoke this only after semantic validation and durable
acceptance; registry membership alone is not a proof of persistence.

The planner decodes the existing strict witness body and applies normal
roster/order/conflict checks. It returns at most one next inclusive request per
claimed sender, in seat order, capped to 128 envelopes by default. Conflicts
request exactly the disputed sequence. Even a maximal sequence claim yields
only one bounded next page, not an unbounded list of requests. The result is
`planned`, never `ready` or `complete`: an empty/partial matching witness can
produce zero requests while synchronization remains incomplete. The helper
does not author or transmit requests, validate a phase snapshot, or decide
whether the witness covers all required history.

## Durable Requested Ranges

`PersistentSyncReceiver` accepts a signed outer `SYNC_RESP` plus an explicitly
supplied expected request. It is transport-independent and does not infer wire
correlation, responder freshness, or a complete catch-up target. Any roster
identity may sign the outer response; the original nested authors remain
authoritative for history. Existing envelope and body schemas are unchanged.

Construction requires the `PersistentSessionReceiver` bound to the exact shared
registry and an explicit semantic-capable durable history receiver. A raw
chain-only persistent receiver is not accepted as the history dispatcher.
`PersistentSetupReceiver` is a supported concrete dispatcher for the current
setup slice. The session owner must share the durable chain receiver and preserve
its existing serialization/semantic ownership across live and historical receipt.

Each requested-range operation follows this order:

1. Reverify and snapshot the outer canonical bytes. Require `SYNC_RESP`, the
   current game/roster, and normal outer-chain admissibility or an exact duplicate.
2. Bound and decode the exact response body, then preflight every nested signature,
   count, game, requested sender, sequence, and internal predecessor link. No
   outer or nested record is committed on preflight failure.
3. Durably receive the outer using the shared persistent receiver. Recheck its
   exact receipt and presence in the shared registry before invoking history.
4. Process nested originals sequentially. Check local-chain attachment before
   dispatch, require semantic validation before accepted persistence, and require
   an exact committed receipt before recording progress or processing the next
   artifact. Stop on the first rejection or failure.

An outer response at sender sequence 15 cannot repair that sender's locally
missing 11-14 by placing them in its body. The outer fails its chain prerequisite
with zero history effects and zero persistence. This is deliberately not a
bootstrap exemption. Metadata preflight is validation only; nested control
effects, requests, or phase transitions are never executed before outer commit.

History dispatch must reject unsupported types and must not re-execute historical
housekeeping network effects. A sender-ordered range is not necessarily a legal
semantic replay schedule: for example, a historical `RAND_REVEAL` can still lack
other senders' prerequisite commitments. Missing prerequisites stop receipt;
they do not justify bypassing the coordinator. A durably accepted terminal setup
failure is recorded as a `failed` receipt and stops the operation rather than
reporting range success or blaming one seat.

Results distinguish `range_received`, `stopped`, `failed`, and `cancelled`.
`outerStatus` reports a confirmed accepted/duplicate outer receipt or `null`;
`receipts` lists confirmed durable history outcomes in requested order.
Stopping/failure includes a stage and failing history index where applicable.
These are per-envelope transactions, not an atomic batch: an accepted outer and
valid history prefix remain durable after later rejection or failure. Explicit
retry can confirm them as duplicates. A thrown persistence/dispatcher error may
occur after an additional commit, so the reported prefix is only what was
confirmed; callers must reconcile/recover uncertain state before resuming.

Defaults allow 128 nested envelopes, 4 MiB for the entire encoded outer response,
eight pending responses including the active operation, and 16 MiB of aggregate
pending outer bytes. Admission checks bounds before copying or signature work.
The whole-outer limit includes wrapper overhead, unlike the pure preflight's
aggregate-artifact limit; callers must budget the final encoded outer as well.
These are local resource policies, not new wire fields or an automatic paging
protocol.

The operation accepts an AbortSignal-compatible `SyncCancellationSignal` without
making the session package depend on DOM types. Cancellation removes queued,
unsubmitted responses and releases their budgets/listeners. An already-submitted
durable operation is awaited to preserve chain/semantic commit consistency; its
confirmed result is recorded, then no next artifact is submitted. Cancellation
does not roll back commits, release the active mutation lock prematurely, or
grant readiness. Reuse the session-owned receiver across connection generations
rather than creating competing mutation owners.

This module does not broadcast envelopes, advance durable authoring heads,
implement complete-head discovery, produce a completion certificate, or resolve
`synchronizePeer`. Its readiness integration test explicitly keeps the gate
closed after `range_received` until a separate session-owned decision completes.
IndexedDB integration tests use `IndexedDbSessionStore` with `fake-indexeddb` and
the setup coordinator to verify restart recovery, duplicate repair, semantic
rejection, delayed/failed persistence, and durably accepted terminal failure.

## Authored History Replay

`AuthoredHistoryStore` is a separate read capability from `AuthoredEnvelopeStore`.
The IndexedDB authored store implements both without changing database schema
version one. `readAuthoredHead(gameId, sender)` returns the verified durable
checkpoint or `null` only for empty indexed sender history. It never treats a
missing checkpoint alongside transcript rows as a safe empty history.

`readAuthoredPage(gameId, sender, fromSeq, toSeq)` reads an inclusive range of at
most 128 sequences, not beyond the current checkpoint, and returns a verified
nonempty prefix containing at most 8 MiB of canonical envelope bytes. A byte cap
may shorten the page. Records must retain `authored = true`, match their signed
game/sender/sequence, and be contiguous and internally linked; sequence zero
also requires the zero predecessor. The caller/replayer checks links across
page boundaries. Missing, invalid, or oversized individual records fail rather
than being skipped. Reads resolve only after their readonly transactions finish
and expose no aliases of persisted buffers.

Checkpoint consistency reads use the sender/sequence index and scoped key
ranges, not a whole-database scan. Tests injecting `fake-indexeddb` supply both
its `IDBFactory` and `IDBKeyRange` via `{factory, keyRange}`; browsers use the
native globals. Game and identity bytes are snapshotted before asynchronous
database access. Source history may grow concurrently, but a replay keeps the
head captured at its start rather than chasing subsequent appends.

`replayAuthoredHistory(store, gameId, sender, send, options)` performs two passes:

1. Capture and reverify the checkpoint, then verify the entire prefix from
   sequence zero through that checkpoint in bounded pages. Check every original
   signature, scope, sequence, predecessor, and the final checkpoint hash before
   sending any bytes. Retain only page boundary hashes, not the whole decoded log.
2. Re-read each captured page, verify its complete chain and captured endpoint
   hash again, then submit each original canonical envelope in ascending order.
   If the store returns shorter prefixes on this pass, assemble them within the
   same count/byte budget and verify the captured endpoint before sending that
   page. A changed or incomplete page stops replay.

This procedure detects late corruption before the first transmission, and
detects changes between verification and transmission before submitting the
affected page. Already-submitted valid earlier pages cannot be recalled. Default
total limits are 4096 envelopes and 64 MiB of canonical payload bytes; pages
remain bounded to 128 envelopes and 8 MiB. These are local operational budgets,
not new protocol fields. A page or total-limit failure never causes a truncated
prefix to be reported as successfully replayed.

The operation never signs or reauthors history, advances `authored_heads`, resets
sequences, or emits a special completion message. Its `send` callback must return
a promise and receives its own byte copy. With a transport synchronizer, callers
can use that generation's existing send capability. A receiver must process
replayed originals through its historical semantic/durable path without
re-executing historical housekeeping network effects.

Results are `replayed`, `cancelled`, or `failed`, carrying the captured checkpoint
summary and confirmed `submittedCount`/`submittedBytes`. The byte count is for
canonical envelope payloads, not framing overhead. Fulfilled send callbacks do
not prove peer receipt, and a failed callback may have partially transmitted its
last payload. Cancellation is checked before and after store operations and
between submissions; already-running store/send promises must settle or honor
the caller's cancellation mechanism. It does not undo transmission or mutate
the source log.

`replayed` means only that the captured local prefix was submitted successfully;
an empty log can also produce this result. It proves neither globally latest
history nor peer/session readiness, and must not alone resolve `synchronizePeer`.
Lost/rolled-back authoring state and remotely recovered own history still need a
separate recovery policy; no automatic checkpoint repair is introduced.
Integration tests show original signed records restoring a receiver's sender
chain so the next normally authored control is admissible without a predecessor
exemption. The automatic bootstrap, historical-control routing, complete-head
agreement, and readiness protocol remain unimplemented.

## Browser Connection Check

The initial usable browser milestone is the non-playable `connection-check@1`
profile, not Sasku. Its self-contained checked-in ESM module has four seats and
declares gameplay unavailable. `rules_hash` is SHA-256 of that module's exact
UTF-8 bytes imported with Vite's raw loader, not a placeholder hash or a hash of
the prose Sasku rules. No remotely supplied module is executed.

Invitations use exactly the fragment parameters `g`, `h`, `r`, and `s` once each.
`g` is 32 lowercase hex characters for the 16-byte game ID; `h` is 64 lowercase
hex characters for the strict Ed25519 host key; `r` is `connection-check@1`; `s`
is `trystero-nostr`. The builder writes these in that order, preserves the static
deployment path, and removes unrelated query/fragment data. Parsing accepts an
HTTP(S) URL or a fragment, rejects credentials, unsupported profiles/strategies,
missing/duplicate/unknown fragment fields, malformed keys, and inputs exceeding
4096 characters. Pasted URLs are parsed, never navigated or used to load code.
Possession remains the out-of-band invitation credential; identities still
require reciprocal `HELLO` authentication.

The browser uses the specification's two STUN URLs, `iceTransportPolicy: "all"`,
and `bundlePolicy: "max-bundle"`. Its ICE hash is SHA-256 of canonical CBOR of
the exact map `{iceServers: [{urls: [the two URLs]}], iceTransportPolicy: "all",
bundlePolicy: "max-bundle"}`. TURN is not configured. An optional local setting
allows up to five normalized relay URLs with no credentials/query/fragment;
`wss` is required except for loopback development. Custom relay lists are not
invitation fields and must be supplied consistently by participants.

`FullMeshTransport` now has an explicit `membership: "lobby"` mode. Only this
mode permits initial rosters of one to eight identities and dynamic `admitPeer`
and `removePeer`. Default finalized mode keeps its fixed three-to-eight-member
invariant. A valid unknown SDP offer creates no resources unless the lobby's
`onUnknownPeer` policy returns literal `true`; unknown candidates/answers do not
admit peers. Capacity is bounded to eight transport identities, including self.
Unknown initial candidates may be dropped, so signaling loss/reordering can
still require negotiation retry.

Lobby membership changes use a mesh-local monotonic generation counter so
removing and re-adding the same identity cannot reuse an old token. Removal
revokes membership before native cleanup and notifications; saved callbacks and
in-flight work remain guarded by current peer identity and membership. Provisional
transport membership is not signed-roster or game authority.

The browser's private lobby transport composes this mode with
`AuthenticatedPeerChannel`, never exposes raw channels, and accepts only the
authenticated remote author's signed `JOIN`, `ROSTER`, and `READY` for this game,
round zero, phase `lobby`. Envelopes are capped at 4 KiB, the controller queue at
32 operations, and local connection-check history at 128 records. Provisional
connections must authenticate and deliver a valid lobby record within 30 seconds.
Finalized-session `AuthenticatedMeshTransport` and its required synchronization
gate are not relaxed; there is no gameplay send path in this browser profile.

The host durably authors/applies a one-seat `ROSTER` as genesis, not a host `JOIN`.
Guests durably author their `JOIN` genesis before connection. The host admits a
guest only after `HELLO` and valid durable `JOIN` receipt, then appends a signed
roster of at most four seats. Guests admit other transport peers only from the
accepted host roster and bootstrap their own/member JOIN chains through the
roster-authorized path.

Each authenticated link receives the local author's original signed history.
Per-peer coalesced flushes replay history before later publications can overtake
genesis, and all newly authored lobby controls are scheduled to every connected
peer. Offline peers get originals on reconnection; retries never allocate new
sequences. Exact already-durable duplicates have no repeated semantic effects.
There is no relay of another author's envelopes in this normal lobby flow.

One serialized controller queue owns local and incoming lobby effects around
the existing classify-persist-commit receivers. The UI permits a readiness vote
only with exactly four seats, all other identities authenticated, and nonempty
member chains. Votes are signed and durable before display/broadcast. All four
votes for the same roster produce a saved lobby agreement; no game is started,
and there is no new unready or host-start message.

Initialization loads identity without connecting to relays; opening/joining is
an explicit user action. A Web Lock for the exact local game/identity excludes
concurrent tabs from writing the same lobby. Existing transcript/roster data is
recovered before live traffic. A derived local-host roster snapshot missing or
behind a fully verified locally authored roster may be repaired through the
existing roster store after validating the authored checkpoint and full lobby
history. This does not repair a missing authored checkpoint or trust remote
history as local authoring authority.

Reloaded agreements reconnect only to redeliver original lobby records, so a
vote persisted before a crash is not permanently withheld from the other seats.
They do not run game recovery or claim full-session synchronization. Leave keeps
identity/history, revokes callbacks, closes links and stores, and releases the
Web Lock. Browser snapshots contain only public identity, roster/readiness,
connection and relay information; diagnostics are bounded. The React UI subscribes
to cached immutable snapshots rather than creating network work during rendering.

Playwright tests use four isolated browser contexts, a local Nostr-compatible
relay, real WebRTC/DTLS, and real browser IndexedDB. They verify identical
11-envelope lobby transcripts, joiner reload, duplicate-tab exclusion, local
snapshot repair, and responsive layouts. This does not validate public relay
availability, TURN behavior, Firefox/Safari, real mobile devices, or a playable
Sasku game.

## Pending Profile Sections

- Remaining per-message body schemas and field-specific integer bounds
- Bayer-Groth proof transcript and serialization
- Final transcript container and transcript hash
- Phase-snapshot schema, versioning, validation, and commit semantics
- Timeout certificates
- Reconnect synchronization discovery, completion, correlation, chained-control
  gap handling, routing, and bounded-history exchange
