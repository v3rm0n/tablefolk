# Candidate Sasku semantic phase owner

`CandidateSaskuRoundOwner` is the single admission and authoring owner from
completed setup through shuffle, private dealing, play, and local audit. It opens
from durable session history with the same explicit roster/round/deal policy as
`recoverCandidateShuffledSaskuRound`. It keeps the mutable phase receivers private.

## Scheduling and handoff

The owner admits signed `SHUFFLE`, `SHARES`, `ACTION`, and `AUDIT_DISCLOSE` messages
into one bounded queue. Admission validates signature, game, round, sender, and
canonical phase syntax. Missing sender predecessors and future phase/index values
are deferred. An eligible predecessor can pass a blocked future message, including
one from a different seat. Proof/share/game semantics remain the responsibility
of the concrete durable receivers at execution time.

Exactly one operation runs at a time. Incoming messages, historical originals,
and local authoring therefore cannot advance the session while a shuffle proof
is being verified. After the fourth shuffle commits, the owner opens the
shuffle-backed Sasku round receiver and only then processes deal contributions.
The handoff re-verifies durable shuffle provenance; this costs extra proof work
but avoids adding a trusted in-memory bypass. Exact old shuffle replays can confirm
storage after handoff; new shuffle contributions cannot re-enter the completed phase.

Queue limits default to 32 operations and 1 MiB, counting active work. Incoming
messages are limited to 64 KiB and charged before copying/signature work. Local
deal/play/audit operations reserve 64 KiB. Future messages keep their budgets until
processed or rejected. Conflicting queued bytes at one sender sequence are rejected.
No hidden unbounded queue sits behind an active proof.

`whenIdle()` means the current drain is quiescent; deferred work may remain and it
is not a readiness signal. `close()` rejects queued work immediately. An already
submitted durable operation finishes and reports its result; close does not roll
back storage. Receivers close after that operation finishes. Fatal receiver or
handoff failures reject queued work and require recovery.

## Admission surfaces

- `receive(remote, bytes)` is for direct authenticated, session-ready peers. The
  caller supplies the transport-authenticated identity; it must match the envelope
  signer and cannot be the local seat. This method does not establish readiness.
- `receiveHistory(artifact)` admits original signed semantic messages from a
  separately preflighted sync range, including the local sender's historical
  originals. It is not a `SYNC_RESP` wrapper decoder or range validator.
- `authorShuffle`, `authorDealShares`, `authorAction`, and `authorAuditDisclose`
  share the same queue. They require the local author and the relevant captured
  receiver snapshot. Delayed stale requests fail through the existing receiver
  guards. Shuffle preparation and local private-hand reads are available only
  while no operation is active.

[Sync request/response receipt and authoring](candidate-owned-sync.md) now runs under the same
owner through explicit control methods. The ordinary semantic methods still reject
controls. The standalone sync receiver must not write concurrently with this owner.
Other control types and setup traffic remain
outside this candidate boundary. External writes
to the registry or durable receiver are outside this owner's contract and can
force recovery; possession of a registry reference does not grant a concurrent
mutation lease.

The owner does not broadcast, execute control effects, infer dealer/beacon policy,
or enable a live-game UI. Authenticated readiness, policy/profile agreement,
independent proof review, and peer-signed result agreement remain separate gates.

## Validation

Tests cover reversed shuffle/deal delivery, deferred prerequisites, private-hand
availability after handoff, local authoring that unblocks a peer contribution,
proof-time serialization, peer binding, unsupported controls, queue budgets, and
close during durable persistence followed by recovery.

The browser harness submits all 57 signed shuffle/deal/play/audit originals from a
completed real-proof hand in reverse arrival order into a fresh IndexedDB-backed
owner. Development and nested-path production builds must reconstruct the same
completed snapshot and valid local audit with an empty queue. The harness emulates
four identities locally; it is not a test of four-peer network readiness.
