# FriStark-Formal agent rules

- Home: `ShieldKit-SDK/FriStark-Formal/` (published under the ShieldKit-SDK repo).
- Write ONLY under this package directory (`FriStark-Formal/`).
- Do not edit ShieldKit product trees (`01-*`, `02-*`, `03-*`) or LeanBCH / verifier.cash unless the user explicitly opens that scope.
- Production params only for product corpora: BLOWUP=2048 QUERIES=8 GRIND_BITS=24 FOLD=8.
- Parallel tracks: exclusive paths under FriStark/{Field,Hash,FRI,Verify,Binding,Packing,AIR,Host}.
- T-MERGE owns lakefile, FriStark.lean, evidence/STATUS.md.
