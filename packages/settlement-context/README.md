# Settlement context

`settlement-context.mjs` encodes the G2 candidate's `SCCT` v1 context from raw,
canonical transaction fields and source outputs. It commits to exactly ten
ordered inputs, exact source locks/values/CashTokens prefixes, and the
action-dependent canonical output order. It excludes unlocks, signatures, and
proofs to avoid a circular transaction identifier.

No-token is explicitly `null` in the input schema and hashes libauth's empty
CashTokens prefix. Non-null CashTokens are encoded by pinned
`@bitauth/libauth@3.1.0-next.8`; JSON forms and caller-supplied hashes are never
accepted. `validateSettlementContext` recomputes the full context from an
independently supplied transaction/source-output structure before accepting an
expected preimage, digest, or public limbs.

This is an encoder/validator only. It is not a covenant, proof verifier,
transaction builder, VM execution, standardness result, or broadcast path.
