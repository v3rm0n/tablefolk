# Candidate owner-coordinated sync

`CandidateSaskuRoundOwner` now admits `receiveSyncRequest(remote, bytes)` and
`receiveSyncResponse(remote, bytes, request, signal?)` through the same exclusive
queue as proof verification, semantic receipt, and local authoring. The caller
supplies the authenticated peer identity; these methods are usable during catch-up
before that peer is marked application-ready. They do not authenticate a transport
or declare it ready.

The candidate control scope uses the current game and round with phase
`control.sync`. Direct control signer and authenticated remote must match a
nonlocal roster seat. Other control types and setup traffic remain unsupported.
The caller must match responses to outstanding requests from the expected peer;
the method validates the supplied requested range but does not maintain a network
request ledger or invent an agreed sync policy.

## Bounded response processing

Responses are limited to 64 KiB and 32 originals. The owner reserves twice the
outer canonical byte length for the outer message plus its retained originals,
within the existing shared queue budget, before decoding. The range uses one queue
operation. Signature, range length, requested sender/sequence, linkage, supported
original scope, and control-schema checks all precede control persistence.
Original game-body decoding and proof/rule checks run through the concrete receiver
when each original becomes eligible.

Once the operation owns the queue, it admits the outer sender chain and persists
that control first. Its nested range cannot repair a gap in the outer chain. Each
original is then executed directly through its concrete semantic receiver under
the same ownership lease. It never enqueues a child operation and waits for itself.
Historical sync controls are recorded without replaying control effects or
recursively applying their nested histories.

If an original needs an earlier shuffle/deal/play phase or sender predecessor,
processing stops with `missing_prerequisite`. The range releases the owner so a
separate peer contribution can arrive; retrying the same response is idempotent.
This is intentionally different from direct semantic delivery, whose bounded
queue can defer future messages. Other rejections or exceptions return progress
identifying the outer status, completed original receipts, stage, and index.
A range failure does not roll back previously committed envelopes.

A control changes the session prefix captured by the shuffle receiver. While the
owner still handles shuffling, it reconstructs and re-verifies that prefix under
the same lease before allowing another operation. An ambiguous committed control
or reconstruction failure requires recovery. During round play, sync controls do
not change the semantic round state.

## Cancellation and lifecycle

A queued response can be cancelled, releasing the entire reservation without
writes. An active response checks cancellation between durable operations. It lets
a submitted write finish, reports committed progress, and stops before another
original. Closing the owner cancels deferred work and lets active persistence
finish. Existing owner budgets and failure behavior apply to controls as well as
game messages.

## Outgoing controls

`authorSyncRequest(author, range)` queues a copied, validated request.
`authorSyncResponse(author, remote, requestArtifact)` serves an authenticated,
already-admitted request from the session history while holding the same queue.
Both return a durable receipt containing the signed artifact for the caller to
send. They do not send network traffic. Missing, unsupported, oversized, or
unadmitted ranges fail before signing. Serving supports the same current-round
controls and semantics as receipt, at most 32 originals and 64 KiB per envelope.
Each outgoing operation reserves 64 KiB in the shared queue.

Before signing, the owner compares the author's durable head with the admitted
sender prefix, including exact predecessor bytes. It rechecks that head and the
captured session history inside the append transaction. The encoded unsigned
control plus a conservative signature allowance must fit the envelope limit.
After authoring, the normal control receipt path persists admission and refreshes
the shuffle checkpoint. An uncertain append or subsequent receipt failure poisons
the owner: recover durable history instead of generating a replacement signature.

## Validation and remaining boundary

Tests exercise proof/control serialization, checkpoint refresh, relayed originals,
exact retries, preflight failures before writes, missing prerequisites, outer gaps,
and cancellation before dispatch. The browser harness records a real signed
response and duplicate historical shuffle through the owner against browser
IndexedDB in development and nested-path production builds.

Tests also cover outgoing proof/control queue order, admitted-request serving,
missing ranges, authored-prefix mismatch, and a committed append with a lost
receipt. The browser harness authors requests and serves responses through the
owner using IndexedDB after a fully audited hand.

The first-round UI uses a separate [original-author replay and prefix/ack
barrier](first-playable-round.md), bound to authenticated peer generations.
Outstanding-request matching and general range-based readiness remain future
work for this request/response API.
Standalone sync receivers must not mutate the same registry concurrently. A
`range_received` result alone does not establish complete history or readiness.
