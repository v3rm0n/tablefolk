# Candidate shuffle-backed Sasku round recovery

`recoverCandidateShuffledSaskuRound(options)` is the candidate entry point from a
restored durable session to private dealing, play, and audit. It does not accept a
ciphertext deck or a caller-supplied setup coordinator. It reconstructs setup from
captured sender histories, re-verifies all four shuffle proofs using the fixed
Sasku card table, and supplies only that final deck to the existing durable Sasku
round receiver. Partial or invalid shuffle chains cannot open dealing.

The caller must supply the admitted roster, setup/shuffle round, local identity,
proof verifier, bound durable session receiver, and explicitly agreed dealer and
deal schedule. The schedule must cover all 36 cards, nine per seat. Policy is
validated and copied before asynchronous proof work, so caller mutations cannot
change the eventual deal. No beacon-to-dealer convention, deal packet order, or
policy agreement is inferred. Agreement and policy identity still need to be
bound by the eventual game profile; this API's input is not evidence of consensus.

Recovery captures the history before proof work and checks that it remains
unchanged before handing off to the round receiver. The temporary shuffle owner
is closed on exit. The returned `PersistentSaskuRoundReceiver` owns subsequent
deal/play/audit receipt and local authoring. Existing applications using its
supplied-deck constructor retain their previous semantics; that constructor does
not independently establish shuffle provenance.

The same entry point restores an undealt, partially dealt, playing, or audited
round. It rechecks the shuffle chain on each open, then replays durable decryption
shares and actions with the same explicit policy. Private hands are reconstructed
locally using the corresponding game secret and accepted donor shares. They are
not returned by the shuffle worker, broadcast, or added to the transcript.

## Validation

Unit tests use real permutation/remasking arithmetic with an injected test proof
verifier to cover incomplete/invalid chains, explicit policy validation, policy
capture during asynchronous verification, private dealing, and private-hand
reconstruction without recovery writes.

The browser harness uses actual candidate WASM proofs and browser IndexedDB. In
both development and a nested-path production build it:

1. Completes and persists four shuffles, recovering each prefix.
2. Opens the round through the new entry point and authors all donor shares.
3. Checks four nine-card private hands containing 36 distinct cards and restores
   those hands by replaying the durable history.
4. Authors a diamonds contract and 36 legal plays, then all four audit disclosures.
5. Reopens IndexedDB, re-verifies the shuffle chain, and reproduces the completed
   round snapshot and valid local audit.

This is an isolated integration harness that emulates all four native identities
in one process/database. It is not four-peer network play, a reviewed cryptographic
profile, or peer-signed result agreement. Test output includes counts and audit
status, never private hand contents or shuffle witnesses.

The [semantic phase owner](candidate-round-owner.md) now serializes shuffle and
round traffic plus local authoring. Coordinated ready/control/sync delivery and
actual lobby-to-game wiring with an agreed policy/profile remain open. Independent vectors,
cryptographic review, and the existing release gates remain open.
