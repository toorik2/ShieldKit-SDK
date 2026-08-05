# FriStark-Formal Warrant v1.0 — short note

## What this is

A machine-checked **verifier-side warrant** for a BCH Goldilocks DEEP-ALI FRI-STARK product path under production params (2048/8/24/8), with:

1. **One Accept kernel** — `Full.Verify.verify` pure (no Id.run), characterized by `verify_ok_iff`.
2. **Public statement Φ** — ProductV1 checklist matching freeze-a0 in-scope clauses (PHI_SPEC); trees out of scope.
3. **Residual games** — FriSecurityGame + FS RO + collision resistance (4 underlying axioms packaged as 3 games).
4. **CovenantAccept model** — topology + binding + role-order packing + verify + product checklist, refined to Lean verify.

## What this is not

Empty residual STARK soundness; prover proof; full script VM; private-trace extraction.

## How to check

```bash
bash release/warrant-v1.0/REPRODUCE.sh
```

Expect `=== CI GREEN ===` and `WARRANT_OK`.

## Theorem map

See `THEOREM.md` in this directory.
