# Real deposit LeanBCH cross-check

`bch/g2-compressed-covenants/fixtures/deposit-complete-real-v1.json` is a
public, stripped replay fixture for complete deposit transaction
`56563c2c3a81857216853b53293c0cedc8f4baaa15b2430553be57a0d57a6cf1`.
It retains the exact serialized transaction, ten source outputs, role metadata
for inputs 7 and 8, and SHA-256 provenance pins. It excludes proving inputs,
proof bytes, wallet material, and any broadcast state.

Regenerate it only from the public complete-deposit artifact, then review the
diff before replacing the committed fixture:

```sh
node bch/g2-compressed-covenants/extract-real-deposit-fixture.mjs \
  --source /path/to/deposit-complete.json \
  --output bch/g2-compressed-covenants/fixtures/deposit-complete-real-v1.json
```

Replay the exact structural roles with the pinned LeanBCH checkout:

```sh
TMPDIR=/home/toorik/Projects/ZK-Proofs/.codex-artifacts/tmp \
node bch/g2-compressed-covenants/real-deposit-leanbch-crosscheck.mjs \
  --lean-root /path/to/LeanBCH \
  --lake "$(command -v lake)" \
  --output /path/to/real-deposit-leanbch-crosscheck.json
```

The runner first checks both roles in Libauth, serializes the exact transaction
and source outputs expected by LeanBCH's `xcheck_idxN.lean`, and then checks
LeanBCH `verifyInput`, `txValid`, and `verifyTokens` independently for inputs
7 and 8. It intentionally does not execute PF7 proof roles 0 through 6 in
LeanBCH, does not validate the fee signature, and is not standardness, BCHN,
relay, inclusion, or qualification evidence.

The acceptance verdict is the cross-check criterion. The runner records both
operation costs, but does not require them to agree; LeanBCH's full-cost path
currently differs for the state helper and must not support a cost claim.

The runner refuses a dirty LeanBCH checkout and records its commit, tree hash,
and tooling-manifest SHA-256 in the result.

The runner uses `leanbch/xcheck_idxN_iter.lean`, a project-local copy of the
LeanBCH xcheck whose only semantic change is an accumulator-based hex decoder.
The stock recursive decoder overflows the Lean interpreter stack while parsing
the 56,767-byte transaction, before it can evaluate either covenant role.
