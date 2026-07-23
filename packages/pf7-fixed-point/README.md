# PF7 fixed-point closure

This local-only package closes the otherwise circular relation among a final
PF7 build, the complete settlement wire size, the one-satoshi-per-byte fee and
change output, the SCCT context digest, and the action packet/public inputs.

It accepts raw unlocking bytecodes from an already-built PF7 result. It never
accepts a `proofValid` flag, never manufactures a proof, never imports
`verifier.cash`, never receives a private key, and has no network, node,
indexer, broadcast, relayer, or hosted-prover path.

`measurePf7FixedPointCandidate` decodes a canonical BCH transaction and:

- requires exactly ten inputs and exactly seven PF7 rows at inputs `0..6`;
- checks that those rows are byte-identical to the decoded transaction;
- reconstructs the complete transaction from the supplied SCCT materials and
  the decoded unlocks;
- derives SCCT itself and requires its digest to equal the packet field;
- derives the wire bytes and fee itself; and
- enforces the frozen `10,000`-byte unlock and `59,000`-byte wire limits, with
  exactly `1 satoshi / serialized byte`.

`verifyPf7FixedPointCandidate` additionally requires the prior plan to match
the post-build row lengths, total, fee, wire bytes and full SCCT preimage. It
requires a caller-provided `pf7Compatibility` predicate to return literal
`true` over the exact public packet, SCCT and PF7-row bytes. A missing, false,
or throwing predicate fails closed.

That predicate is deliberately not called a proof verifier: successful closure
is **not** Groth16/PF7 validity, BCH VM acceptance, standardness, relay,
confirmation, or Chipnet qualification. Those remain independent gates.

`enumeratePf7FixedPointCandidates` invokes a caller-provided packet/public-
input evaluator sequentially over distinct canonical 32-byte seed candidates,
then passes each build through the same closure check. It reports rejected
attempts in deterministic input order and promotes no rejected candidate.

The package is a protocol-integration boundary. Its caller must obtain PF7
rows from the authenticated profile-bound builder and must run the real proof,
VM, node, and conformance gates separately.
