# Architecture and Delivery Decisions

## 2026-09-17: Preserve Security, Narrow the First Playable Milestone

Status: **Accepted** following the architecture/scope discussion.

These decisions revise delivery scope and sequencing in the implementation plan.
They do not change signed wire formats or authorize weaker cryptographic checks.

### D1 — Keep the Untrusted-Peer Security Model Explicit

Keep authenticated peers, canonical signed history, conflicting-history detection,
verified shuffling and private dealing, deterministic rules, and bounded processing.
Public progression and hidden-hand legality remain distinct: some hidden-rule
violations are established only by the prescribed proof or later disclosure/audit.

The model assumes a trustworthy local client/device, working CSPRNG, appropriate
cryptographic assumptions, and at least one honest shuffle participant. It does not
promise completion against a peer withholding messages/shares, prevent voluntary
out-of-band hand sharing, or prove malicious intent from a network interruption.
Shuffle fairness does not supply abort resistance.

### D2 — Complete One Verifiable Live Sasku Hand Before Broadening the Platform

Prioritize the Bayer-Groth implementation/profile and review path, then integrate
one four-peer hand through setup, sequential verified shuffles, private dealing,
legal play, and audited scoring. Preserve the requirement for off-main-thread
proof work and independent review before a public cryptographic security claim.

An unproven shuffle, supplied-deck test, or successful local audit cannot unlock
verified multiplayer gameplay. Do not substitute a different proof system or curve
silently. Resolve implementation feasibility before expanding surrounding machinery.

The single-hand milestone is a delivery boundary, not a decision about Sasku match
termination. Initial dealer, production deal schedule, beacon scheduling, and match
policy still require explicit agreement; tests continue to supply named fixtures.

### D3 — Retain Durable Foundations; Defer Broader Recovery Automation

Keep tested persistence-before-publication, durable private material, original-byte
replay, guarded signing, and existing read-only recovery. Once the same game is
resumed, these are correctness requirements rather than optional UX polish.

Do not make seamless reconnect, generalized whole-session/multi-round recovery,
or a polished transcript export/offline-verifier flow prerequisites for completing
the first live-hand integration. Those remain later release milestones. Implement
only the readiness and history agreement needed by that live path; authentication
alone is not session readiness. Interrupted sessions must stop safely unless an
implemented, verified recovery path establishes readiness. A new game uses fresh
session identity/material; retrying a contribution never means re-signing it.

### D4 — Reuse Concrete Boundaries, Not a Speculative Universal Engine

Keep shared transport/session/cryptographic deck operations separate from game
rules and their composition. Additional games should reuse the security machinery.
Generalize draws, exchanges, reshuffles, rules packaging, or other mechanics when
a second game supplies actual requirements.

Consolidate demonstrated duplication in durable orchestration and local rule checks
when the live path makes the common contract clear. Avoid a broad framework rewrite
or package expansion before the first complete hand. Test count is not a measure
of unnecessary architecture; repeated responsibilities and delivery dependencies are.

## Consequences

- The next engineering priority is a credible verifiable-shuffle path, followed by
  end-to-end hand integration using the components already built.
- Existing security invariants and recovery tests remain useful foundations.
- Broader recovery automation and speculative abstractions move behind that path.
- A backend feasibility blocker is recorded explicitly rather than hidden behind
  a placeholder verifier or further unrelated infrastructure work.
