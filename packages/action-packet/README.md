# `@shield.cash/action-packet`

Strict codec for the fixed 752-byte `SCAR` v1 action packet used by the
development G2 candidate. It is the byte-layout authority shared by the
relation reference, PF7 terminal seam, settlement covenants, SDK, and
conformance vectors.

The codec:

- accepts only Chipnet network discriminator `2`;
- fixes deposit, transfer, and withdrawal kind codes;
- rejects nonzero reserved and inactive fields;
- preserves immutable profile, instance, and maximum-reserve fields;
- exposes the transaction-context digest at bytes `720..751`; and
- derives the verifier's two public inputs as unsigned big-endian halves of one
  SHA-256 digest of the exact packet.

It does not validate a Groth16 proof, recompute the settlement-context digest,
or execute BCH covenants. Those are separate gates over the same bytes.
