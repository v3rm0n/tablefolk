# Sasku round-start performance profile

The short-lived table still treats every player as an untrusted peer. Signed
sender chains, four verified sequential shuffles, private decryption shares,
share proofs, and audited play remain required. A short game does not reduce the
value of cheating in that game.

The `sasku-match-candidate@3` profile removes work that does not protect those
properties:

- Setup needs four signed `KEY_SHARE` contributions and their possession proofs.
  It does not run the commit/reveal randomness beacon. The current dealer and
  deal order are fixed, while each player independently remasks and permutes the
  deck in a verified shuffle. The old beacon seed was recorded but unused by
  those choices. The existing beacon-capable engine remains available for other
  profiles; the candidate match explicitly selects key-only setup.
- The deal still assigns positions 0–8, 9–17, 18–26, and 27–35 to seats 0–3.
  Each seat contributes one signed `SHARES` envelope in `round.N.deal.0`, with
  `to: 4` denoting the four-seat all-recipient batch and exactly the 27 positions
  owned by the other seats, in ascending order. Every position retains its
  individual Chaum–Pedersen proof bound to that phase. All four valid batches
  are required before any private hand or bid becomes available. This replaces
  twelve nine-share envelopes and four serial recipient phases.
- The browser keeps a warmed verifier worker between operations. A proving
  worker must discard its permutation and randomizers after the result; workers
  remain cancellable and off the main thread. Reusing public verifier state
  does not change what peers must verify.

Authenticated history-prefix acknowledgements remain the reconnect and
readiness boundary. Any later reduction of acknowledgements must preserve
prerequisite admission before a player acts and must be based on separate-browser
timings. Existing `@2` transcripts remain stored, but this build does not resume
them. The new invitation identifier and rules hash prevent unlike clients from
joining the same table.

In a controlled production-browser comparison on 2026-09-26, the local four-player
demo reached bidding in 18.3–18.4 seconds with this profile, versus 25.6–26.4
seconds with the old beacon and 12-message deal enabled in the same build. The
four-browser WebRTC match reached bidding 8.6 seconds after the last ready click
in one run. These are development-machine observations, not latency guarantees;
the full production browser suite also completed a four-browser match with reload.
