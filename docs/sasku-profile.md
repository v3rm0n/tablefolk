# Sasku Rules Implementation Profile

Source: `RULES.md` and the user's confirmed choices. Status: deck, auction,
effective-suit following, reference/public-only hand execution, positional action
mapping, disclosed-hand audit, and scoring.

`@p2pcards/rules-sasku` is not yet the complete rules-module interface or a playable
rules bundle. Its functions are deterministic, network-free, and independent of
transport, storage, clocks, and random sources. No Sasku invitation/rules hash is
registered by this increment. The browser lobby remains `connection-check@1`.

## Fixed Facts

Seats are zero-based in code. Partnerships are `{0, 2}` and `{1, 3}`, displayed as
seats 1 + 3 and 2 + 4 in the browser. `partnershipForSeat` validates the seat and
returns partnership 0 or 1; it does not choose a dealer or first leader.

Public card point values are ace 11, ten 10, king 4, queen 3, jack 2, and other
cards zero. `other` is a scoring category, not an approved card rank/identifier.
The strongest-first permanent court order is:

```text
K clubs, Q clubs, J clubs,
K spades, Q spades, J spades,
K hearts, Q hearts, J hearts,
K diamonds, Q diamonds, J diamonds
```

The confirmed non-court order is `A > 10 > 9 > 8 > 7 > 6`, both within a plain
suit and below the courts in the chosen trump suit.

## Canonical Deck

The confirmed deck has 36 cards: ranks `6`, `7`, `8`, `9`, `10`, `J`, `Q`, `K`,
and `A` in clubs, spades, hearts, and diamonds. `SASKU_DECK_SPEC` uses the exact
ASCII ID `sasku-36/v1`. Canonical card identifiers concatenate rank text and one
suit letter: `C`, `S`, `H`, or `D`. For example, `6C`, `10H`, and `AD` are valid;
`TC`, lowercase aliases, suit glyphs, and unknown ranks are rejected.

The canonical initial deck is suit-major in clubs/spades/hearts/diamonds order,
with ranks `6, 7, 8, 9, 10, J, Q, K, A` inside each suit. This serialization order
is not playing-strength order. Card descriptors, rank lists, and the deck spec
are immutable. `parseSaskuCard` returns the validated descriptor, including point
value and court classification.

The spec is structurally compatible with `CardPointTable` and therefore uses the
existing card-point derivation domain and encoding. Integration tests fix
independently calculated SHA-512 fixtures for `sasku-36/v1` with `6C` and `AD`,
then check all 36 Ristretto points are distinct and identifiable. This defines
the plaintext deck mapping; it does not implement or validate a shuffle proof.

## Following and Trick Winners

The user selected effective-suit following with free discard, superseding the
earlier printed-court-suit restriction. Every court belongs only to the effective
`trump` suit, regardless of its printed suit. Non-courts of the chosen trump
suit also belong to `trump`; remaining cards retain their plain suit.

`legalSaskuCards(hand, trick, trump)` requires following the effective suit of the
first play when possible. If none of the hand's cards match, every card is legal:
there is no forced trumping or overtake requirement. Leading an empty trick
permits any card. Hands contain at most nine distinct validated cards and cannot
overlap cards already played in that trick. A completed four-play trick rejects
further legal-move queries.

Examples with diamonds as trump:

- Hearts led, only `QH` among printed hearts: the hand is void in hearts, so
  trumping or discarding is allowed.
- Hearts led, both `AH` and `QH` held: `AH` follows; `QH` does not.
- `JH` led: trump is led, so all courts and diamond non-courts can follow, but
  a plain heart cannot follow if a trump is available.
- Hearts led and another player already trumped: holding `AH` still requires
  following hearts, even though it cannot beat that trump.

`winningSaskuPlay` handles zero to four ordered public plays, returning `null`
for an empty trick. `resolveSaskuTrick` requires four distinct seats and cards,
then returns the winner, its partnership, and the trick's card-point total.
Highest trump wins if present; otherwise highest card in the led plain suit
wins. Off-suit discards cannot win. All returned play/result values are snapshots.

These helpers do not prove hand ownership, a valid deal, or the legality of other
players' earlier choices. They also do not choose a first leader, turn direction,
or the next expected actor. The caller must supply an ordered trick and enforce
turn/phase/ownership rules before accepting a play. The complete-information hand
controller below performs those checks given a full deal; cryptographic deal
validation and signed game-message integration remain separate work.

## Confirmed Auction

`saskuBidStrength` requires a complete, unique nine-card hand. It counts courts
once, excludes them from every printed-suit count, and adds the largest remaining
plain-suit count. Four courts and three non-court hearts therefore give strength
seven regardless of the courts' printed suits. Valid nine-card hands have
strengths from three through nine.

Bidding starts at `(dealer + 1) mod 4` and advances in cyclic seat order 0, 1, 2,
3. On a bidding turn, a player may pass, make an exact-strength bid strictly
higher than the current high bid, or call diamonds immediately. Equal bids
cannot displace the first bidder. Passing does not eliminate a player; a prior
passer can later bid if their exact strength beats the current high bid. Advice
against outbidding a partner is not a prohibition.

Every successful numerical raise resets consecutive passes. Three consecutive
passes after a bid end the auction and let its winner choose any supported trump
suit. Four passes before any bid create a pass-round with default diamonds and
no declarer. A diamonds call is legal only on the caller's bidding turn; it ends
bidding immediately, requires no numerical overbid, and makes that caller the
declarer even if somebody else held the highest numerical bid.

## Single-Hand Controller

`SaskuHandController` is a complete-information reference controller. Construction
requires an explicit initial dealer and four nine-card hands that together
contain each canonical deck card exactly once. It does not shuffle, choose an
initial dealer, prove a deal, or obtain hidden hands from the network. It is
appropriate for public practice and replay after all required hands are known,
not for installing every player's hidden cards in a live peer's state.

Its local phases are `bidding`, `choosing_trump`, `playing`, and `complete`.
Actions have explicit `type` and `seat`, with only the fields for that action:

- `pass` and `diamonds`: no extra fields
- `bid`: exact integer `value`
- `choose_trump`: supported `suit`
- `play`: canonical `card` identifier

These remain local API actions. The positional wire adapter below maps the
supported `ACTION` payloads to them after separate authority and reveal checks.
The controller enforces the expected seat and phase, rejects unknown
or extra action fields, checks exact bids and ownership, and applies the confirmed
effective-suit following rule. Validation computes a new private state before
committing it, so any rejected action leaves the current state and history intact.
`preview(action)` returns the prospective public snapshot without mutation;
`apply(action)` commits the same transition.

The named-trump declarer leads the first trick. A pass-round begins with the
player after the dealer. Players advance by one seat within a trick, its winner
leads the next trick, and the winning partnership receives the trick's card
points. After all nine tricks, all 36 cards are consumed, the point totals sum to
120, and the existing completed-hand scorer produces the result. No early finish
at 61 points is introduced. The completed snapshot has no active turn and provides
`nextDealer = (dealer + 1) mod 4` for a subsequent hand; it does not start a new
hand or choose a match winner automatically.

Public snapshots contain hand sizes, declared bids/contracts, played cards,
completed tricks, totals, and the final score, but not unplayed card identities.
The explicit `handFor(seat)` method is for the trusted complete-information
caller and returns an immutable copy. Initial deal and action inputs are copied;
returned snapshots and action histories cannot mutate controller state.

`replaySaskuHand(setup, actions)` reconstructs a new controller using the same
transition logic and rejects invalid histories. Replay is bounded to 64 actions,
sufficient for the strictly increasing, finite auction plus 36 plays. It may
restore a partial hand, but is not durable network recovery or proof that the
supplied deal/actions match a signed game transcript. Live receipt must validate,
durably commit the signed action, then apply through one mutation owner.

## Public Progression and Hand Audit

`SaskuPublicHandController` requires exactly `{dealer}` and never receives or
stores hidden hands. It shares the reference controller's transition logic for
auction phases, expected seats, trick winners, point totals, and dealer rotation.
It offers immutable snapshots/history and non-mutating `preview`, but deliberately
has no `handFor` or `legalCardsForTurn` method. A live caller can filter its own
verified private hand using `legalSaskuCards` and the public trick/contract.

Public checks reject malformed actions, wrong turns/phases, bids outside 3 to 9,
non-increasing bids, and repeated card identities, including across tricks.
Because the hand is unchanged during bidding, a numeric bidder cannot later
declare a different exact strength; a previous passer can still re-enter.
Card counts start at nine per seat and decrease only after accepted plays.
Exact bid strength, ownership in the original deal, and following obligations
require the private deal and are not assumed by the public controller.

`SaskuPublicHandSnapshot` exposes `provisionalScore` instead of `score`. A complete
public hand is not an audited result, and its suggested next dealer does not
authorize starting another hand. Sender authentication, phase binding, revealed
card proofs, and encrypted-position ownership remain mandatory engine checks
before accepting a live action; this local controller does not replace them.

`auditSaskuHand(setup, actions)` first validates a complete 36-card disclosed deal
and replays the entire supplied history through public checks. Malformed deals,
oversized/sparse action arrays, and publicly impossible histories throw rather
than assign hidden-hand blame. The bound remains 64 actions. Normalized action
snapshots then replay through the complete-information controller in order.
The result is exactly one of:

- `status: "valid"` with the reference snapshot, only after all nine tricks
- `status: "incomplete"` with the reference snapshot for a valid prefix
- `status: "violation"` with `seat`, zero-based action index `at`, and `rule`:
  `bid_strength`, `card_ownership`, or `follow_suit`

The first hidden-hand violation is deterministic, and its result contains no
disclosed hand data. The same private-check failures carry a `rule` on
`SaskuHandError`; other hand errors have `rule: null`. Audit is pure and does not
mutate the deal, history, or any live controller. A caller must independently
bind the supplied dealer, deal, and ordered history to verified game artifacts.
Neither `valid` nor any violation result is a shuffle/signature verification,
a signed violation certificate, a match result, or a session-readiness signal.

## Positional Action Mapping

Sasku uses the generic `ACTION {kind, data, reveal, shares}` body from the protocol
profile. The supported shapes are:

| Kind | Data | Reveal/Share Requirement |
|---|---|---|
| `pass` | `{}` | No reveals or shares |
| `diamonds` | `{}` | No reveals or shares |
| `bid` | `{value}` with integer 3 through 9 | No reveals or shares |
| `choose_trump` | `{suit}` using the exact supported suit name | No reveals or shares |
| `play` | `{}` | One position 0 through 35 and its matching owner share |

The actor is derived from the authenticated envelope's `from` and the finalized
roster. It is never a `seat` supplied in the body or data. A play never carries
a claimed plaintext card ID: its card comes from decrypting the scheduled
ciphertext with verified shares and identifying the resulting card point.
Encrypted deck position and plaintext deck index are not interchangeable.

`decodeSaskuAction(actor, {kind, data, reveal}, revealed)` is a pure rules adapter.
The engine must verify authority, decryption proofs, ownership, and reveal
freshness before constructing this public-only input. The adapter never receives
points or proof fields. It requires an exact matching position-to-card map for
a play, an empty map for auction actions, and the exact data fields above. It
rejects unsupported kinds, aliases, extra fields, invalid positions/cards, and
accessor-bearing/non-data maps, and returns a frozen local `SaskuHandAction`.
It does not perform cryptography or mutate the hand. The public controller still
owns turn/phase and public-rule checks; the disclosed-hand audit owns hidden-hand
checks after the deal is known.

For a single hand, the action index in `round.<r>.play.<t>` is the zero-based
accepted hand-action count, including auction actions and trump choice, not just
card plays. Only durable accepted actions may advance it; envelope sender
sequence numbers remain independent. The engine's `RoundRevealLedger` tracks this
counter through explicit commits; `PersistentSaskuRoundReceiver` now owns those
commits alongside the public rules state after durable session receipt. These
components neither register a Sasku rules hash nor enable a game through the
connection-check lobby.

The ledger verifies signed scheduled deal shares, owner action proofs, and
unrevealed-position ownership relative to supplied setup/deck/schedule context.
Its classified card map can feed this adapter and public-rule preview before
durable receipt and commit. Construction still requires an externally verified
shuffle in production; the ledger does not establish one. Integration tests use
explicit nine-card allocation steps and a supplied masked-deck fixture to play
and audit a complete hand, persist all 65 setup/deal/action/disclosure envelopes,
and rebuild the same public and audit state from those records. That test
distribution is not a chosen production dealing convention.

## Durable Round Receiver

`@p2pcards/game-sasku` composes the generic engine/session layers with these rules.
`PersistentSaskuRoundReceiver` requires an explicit dealer and a schedule assigning
all 36 positions, exactly nine to each of the four setup seats. Its supplied
durable receiver must be bound to the same game and seat-ordered session registry.
The ciphertext deck and configuration still require externally established
shuffle/rules provenance.

The receiver privately owns the ledger and public controller, serializes bounded
incoming work, validates reveals and public rules before persistence, and changes
both states only after a matching durable receipt. Its cached snapshot includes
public hand state, public history, revealed-card ledger state, and local audit
participation/result, never private hand contents. Disk errors and chain
gaps/conflicts do not consume a turn or position. Exact replay is idempotent,
including after the hand completes; already
durable history can rebuild fresh semantic state through the same receive path.

Receipt corruption or an unexpected commit invariant failure requires recovery
rather than further play. Closing cancels queued work but lets an already
submitted write settle consistently. The receiver does not choose a dealer or
match target, validate shuffle proofs, emit violation certificates, establish
peer agreement on a result, or upgrade `provisionalScore` into a finalized game
result.
The IndexedDB integration suite now uses this production component rather than
its earlier test-only driver.

## Local Private Hand

`PersistentSaskuRoundReceiver.readPrivateHand(identity, secretKey)` provides an
explicit local-only read, separate from its public `snapshot`. It resolves the
identity's roster seat and requires the key to match that seat's accepted setup
public key. A wrong key cannot open another player's cards and does not poison
the receiver. The key is supplied per call and is not retained by the receiver.

The reader returns `null` until all initial-deal batches have durably committed.
Afterward, its frozen `dealt` map contains the local seat's original nine cards
by encrypted-deck position, and `remaining` excludes committed public reveals.
The explicit schedule determines ownership, including non-contiguous hands.
Reads generate no proofs, reveal no owner shares, and modify neither public
state nor persistence. A pending, rejected, or failed play does not remove a
card; exact duplicate replay cannot remove it twice.

Callers can pass the dealt card IDs to `saskuBidStrength` and remaining card IDs
to `legalSaskuCards` with the public trick/contract. This is not automatic input
validation, action authoring, proof of shuffle provenance, or a transport
readiness signal. The public controller remains independent of private hands.

Recovery loads the existing persisted game secret and replays verified original
round messages against the same trusted context. No plaintext hand store is
needed. Missing or corrupt keys must not be regenerated during recovery. Reads
reject closed or failed receivers; locally detected deck inconsistencies require
recovery, not player blame. Private cards must stay out of shared/public snapshots
and logs. Browser private-hand rendering and input handling remain unimplemented;
explicit headless action authoring is available through the boundary below.

## Local Action Authoring

`receiver.authorAction(author, secretKey, receiver.snapshot, intent)` composes
private-hand legality, public rules, owner proofs, durable signing, and local
receipt in the receiver's existing queue. The caller supplies a persistent author
for a roster identity, that identity's game secret, and the exact snapshot object
on which the move was chosen. Stale requests are rejected, not moved to another
turn. Intent fields are limited to `type` and, when needed, bid `value`, trump
`suit`, or encrypted-deck `position`; callers cannot claim an actor or plaintext
card identity.

Before generating a play proof or signing, local checks enforce exact bid
strength and effective-suit following as well as public turn/phase legality and
ownership. Remote actions still receive only the public checks until audit;
local preflight does not give the receiver opponents' private cards. A successful
local action uses the existing positional wire format and updates the public
state only after both durable authoring and local receipt. It returns the
original signed artifact without broadcasting it.

The signing-time guard requires the native authored and accepted own-sender heads
to agree. Failures after signing permission or durable authoring require recovery
from original history, never an automatic re-sign. Queued local actions reserve
one slot and 64 KiB; close before signing cancels them, while an already signed
active operation may finish its submitted commit and local receipt. The complete
lifecycle and failure rules are in `docs/protocol-profile.md`.

Native IndexedDB tests establish the local authored prefix from setup onward,
play all nine local cards among the 36 moves, complete the signed hand audit, and
recover an authored-but-not-applied action before advancing the sender chain once.
These are supplied-deck fixtures, not verified shuffles or browser gameplay.

## Local Contributions

`authorDealShares(author, secretKey, receiver.snapshot)` prepares and durably
authors the local seat's whole currently scheduled nonrecipient batch. The
receiver selects the recipient and positions from its retained explicit schedule;
callers cannot request extra positions or the recipient's missing share. Each
position receives a fresh proof bound to the deal phase. Preparation does not
open a private hand and works before the full initial deal is complete.

`authorAuditDisclose(author, receiver.snapshot)` authors the completed-hand empty
disclosure using the audit phase. No game secret or new decryption proof is needed
because all 36 cards were already opened. All four identities must still durably
contribute before a local audit result is published.

Both methods require the receiver's actual current snapshot at admission. Once
queued, they tolerate other contributors arriving in the same captured phase,
but the local seat must remain pending. They reject a consumed local obligation
or a different deal phase instead of generating another signed contribution.
This does not relax the turn-bound snapshot requirement for `authorAction`.

Contribution authoring reuses the same queue limits, durable native-head guard,
byte isolation, close handling, and recovery rules as local actions. Proof
preparation checks phase/member/lifecycle changes after every random draw, even
one rejected by nonce sampling. Failures after signing permission require original
history recovery, not automatic re-signing or nonce reuse.

A four-peer IndexedDB test completes the supplied-deck hand using all three
authoring APIs, with an independent local key and authored checkpoint per peer.
It recovers an authored-but-unapplied deal batch and final disclosure without
regenerating either, then checks identical 65-envelope canonical sets, public
states, and audited results. No real transport, shuffle proof, automatic phase
producer, initial-dealer policy, or match policy is supplied by this test.

## Signed Hand Audit

After the final durably committed play, `snapshot.audit` changes from `null` to
an immutable `round.<r>.audit` snapshot with all four seats pending and no result.
All 36 positions have been publicly opened by then. Accordingly, every seat's
signed `AUDIT_DISCLOSE` must contain exactly `{items: []}`; there are no remaining
cards for that seat to reveal. Empty bodies do not waive signatures, scope,
sender-chain validation, durable receipt, or the requirement to hear from all seats.

The receiver counts each seat once, accepts exact retransmission idempotently,
and rejects newly signed equivalent contributions. Arrival order does not change
the result. Until all four contributions are durable, `audit.result` remains
`null`, including across storage failure and recovery of an interrupted audit.

On completion, the receiver reconstructs the original hands from verified card
openings and scheduled position ownership, then calls `auditSaskuHand` with the
committed public history. `audit.result` is either `{status: "valid", score}`
or `{status: "violation", seat, at, rule}` with no score. A false bid or failure
to follow suit points to the earlier action and actor, not the final discloser.
The public hand's `provisionalScore` remains unchanged and separately labeled.

This is a locally reproducible, transcript-backed hand audit relative to the
supplied round context. The disclosures do not sign the computed result or prove
peer agreement on it. No next hand, cumulative match score, game-key deletion,
forfeit certificate, or network gameplay is authorized by this result alone.

## Read-Only Round Recovery

`PersistentSaskuRoundReceiver.recover(options, limits?)` replaces the tests'
hand-written phase sorting with synchronous production reconstruction. It takes
the same trusted round inputs and an already restored, quiescent session registry
with its bound durable receiver. It reads complete sender prefixes, reverifies
their signatures/chains/cache hashes, and requires the recorded setup's keys and
beacon seed to match the supplied completed setup.

Round replay preserves each sender's sequence order while merging eligible
deal/action/audit messages in deterministic seat order. It does not move a later
message ahead of an earlier one merely because its claimed phase looks useful.
Partial prefixes are allowed; surviving messages behind missing prerequisites,
malformed phases, bad proofs, or invalid public actions cause recovery to fail
without returning a partial receiver.

The result reconstructs public history, private-hand prerequisites, exact replay,
and pending/completed audits through shared semantic logic. No storage writes,
duplicate persistence, bound-registry ingestion, signing, game-key access, or
new proof nonces occur. The caller can subsequently load the saved key and use
the normal private-read/authoring APIs on the recovered receiver. Snapshot
identities from the old instance do not authorize new local operations.

Default bounds are 1,024 scanned envelopes and 16 MiB, including setup and ignored
controls. Only one gameplay round is supported: other-round game traffic is
rejected. Lobby/control effects and shuffle provenance remain external
prerequisites, so successful reconstruction is not a complete game verifier or
a reconnect-readiness signal. Stop and settle old live operations before capture;
the factory neither waits for them nor proves that no newer durable/peer history
exists. The IndexedDB restart suites now use this factory and assert no writes
during reconstruction before testing ordinary continuation.

## Incoming Round Scheduling

`SaskuRoundInbox` wraps a matching round receiver/session and a fixed local roster
identity. Its `receive(remote, bytes)` entry point is only for authenticated,
session-ready direct-peer `SHARES`, `ACTION`, and `AUDIT_DISCLOSE` traffic. It
checks signed source/scope, canonical phase names, and wire syntax, then holds
future phases or sender gaps in bounded memory instead of persisting them early.

Only the earliest queued sequence from each sender is considered. Other senders
can supply missing prerequisites without being blocked by a future message at
the front of one stream. A later message from the same sender cannot overtake
that head. Once eligible, the original passes through normal durable proof/rule
receipt. No card, turn, contribution, or audit result advances merely because a
future message was admitted.

External local authoring or validated housekeeping progress must explicitly call
`processPending()`. The inbox's idle promise can resolve with deferred messages
still pending; it is not a game/readiness result. The receiver's separate
`whenIdle()` waits for its admitted semantic operations to settle, but is not a
lock against future work or a barrier for other session/control producers.

Defaults bound active plus deferred messages to 32 envelopes/1 MiB, with a 64 KiB
frame ceiling. Duplicate calls also consume capacity. Closing cancels unsubmitted
work, but already submitted receipt may complete consistently. The inbox does
not own transport authentication, peer generations, outgoing sends, witnesses,
missing-range requests, timeouts, automatic retries, or match decisions.

An independent-database four-peer test now delivers legal cross-sender reorders
during dealing, play, and the final-play/audit transition. It verifies unchanged
durable/public state while prerequisites are missing and identical final records
and results after they arrive. The sender identities, supplied ciphertext deck,
and delivery routing are test inputs, not live browser authentication or verified
shuffle provenance.

## Completed-Hand Input

`scoreSaskuHand` accepts two partnership card-point totals, two trick totals, and
one explicit contract:

```ts
type SaskuContract =
  | { kind: "named"; suit: SaskuSuit; declarerSeat: 0 | 1 | 2 | 3 }
  | { kind: "pass_round" };
```

Named diamonds and default diamonds in a pass-round are different contracts.
A pass-round has no declarer; contradictory fields are rejected, not ignored.
The scorer does not validate how a bid was made or whether a player could name
the chosen trump.

All numeric inputs must be bounded whole numbers, excluding negative zero.
Card points sum to 120 and tricks sum to nine. Each of four players contributes
one card to each completed trick, accounting for the 36 played cards implied by
nine-card hands. For scoring feasibility, these contain four each of the five
scoring ranks and sixteen zero-value cards: the sixes, sevens, eights, and nines.

A bounded subset-sum table checks that the point total is possible for the
number of captured cards, using that point inventory. For example, 119 : 1 is
impossible because there is no one-point card; 90 points in two tricks is
impossible because even the eight highest-value cards total only 84. Zero points
with one or more zero-value tricks is possible and is not automatically karvane.
These checks are necessary consistency checks, not proof of a legal deal, legal
plays, or correct trick winners.

## Scoring Precedence

Apply special cases before ordinary named-trump scoring:

| Contract / result | Award |
|---|---|
| Pass-round, 60 : 60 | Neither side scores |
| Pass-round, unequal card points | Higher-card-point partnership scores 2 P |
| Named trump, 60 : 60 (pokk) | Non-declaring partnership scores 2 P |
| Named trump, opponents took no tricks (karvane) | Winning partnership scores 12 P |
| Other named-trump result | Named-trump base plus the applicable bonus |

The pass-round award has no bonus for exactly 90 points, jann, or karvane.
Karvane is based on zero tricks, not merely zero card points. Its 12 P replaces,
rather than adds to, the ordinary named-trump award.

The ordinary base table is:

| Named trump | Winners' partnership named it | Opponents' partnership named it |
|---|---:|---:|
| Clubs, spades, or hearts | 2 P | 4 P |
| Diamonds | 4 P | 6 P |

| Winning card points | Bonus |
|---|---:|
| 61-89 | 0 P |
| Exactly 90 (seajann) | 1 P |
| 91-120 (jann), where the totals are feasible | 2 P |

Results contain a reason/kind, winning partnership or `null`, immutable
partnership game-point totals, and base/bonus components. Only the awarded
partnership receives game points. The function does not accumulate a match score,
choose a target score, write a transcript, or emit a signed game result.

## Browser Reference

The `scoring.html` page uses this same package for manual examples.
Changing its inputs has no lobby, identity, storage, or network effect. Invalid
totals show a validation message instead of a misleading score. Pass-round mode
disables the named-suit/declarer inputs and always represents default diamonds.
The existing connection-check rules bundle and lobby agreement are unchanged.

## Remaining Decisions

- Initial dealer selection and match termination/target score
- Production deal distribution and its binding to the verified encrypted deck
- Browser integration of the durable receiver, verified shuffle/schedule provenance,
  private-hand rendering/input, readiness-aware round-message delivery, outgoing
  setup coordination, automatic contribution scheduling, and round/match finalization
- A complete content-addressed Sasku rules bundle and integration with verified
  shuffle/deal/play, persistence, and offline replay

No missing choice is supplied by the scoring calculator. Verification includes
scoring-table boundaries, all declaring seats/suits, special-result precedence,
impossible-input rejection, partnership-swap symmetry, all 85,680 combinations
of trump/lead/disjoint two-card hand, rank comparisons, cryptographic deck
binding, auction transitions, every named suit/dealer combination through a
complete hand, replay after each play, atomic rejection, and browser interactions.
Public/reference equivalence covers every dealer and contract on both public
fixture deals. Audit tests cover false bids, original-deal ownership, effective-suit
violations, first-violation ordering, incomplete histories, malformed input, and
complete but unaudited public scores.
Durable audit tests cover reordered disclosures, non-contiguous schedules, strict
signed scope and empty schedules, failed fourth writes, hidden-rule violations,
receipt corruption, local audit exceptions, and partial/completed audit recovery.
Positional-action tests cover all actors, exact data fields, reveal-map matching,
and rejection of forged actor/card claims. A separate engine fixture composes
scoped signed decoding, explicit DLEQ verification/card lookup, and public hand
progression without claiming a verified shuffle or production deal.
