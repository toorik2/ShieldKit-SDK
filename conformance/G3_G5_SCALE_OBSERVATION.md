# G3/G5 scale observation — local, fixture-bound

Source commit: `2ddfe0b30db04729c6891c7091023383e05a7e16`

Commands:

```sh
cd packages/recovery && node scale-history-conformance.mjs \
  /home/toorik/Projects/ZK-Proofs/.codex-artifacts/g3-g5-scale-conformance-20260724/history-10000 10000
cd bch/g2-compressed-covenants && node real-action-mutation-matrix.mjs \
  /home/toorik/Projects/ZK-Proofs/.codex-artifacts/g3-g5-scale-conformance-20260724/real-action-mutation-matrix
```

The 10,000-transition history result is SHA-256
`ef06fa71508d910e8cc797cf6316a3048553d6ab27f79ff9e10b0ca132d1655e`.
Its 7,520,000-byte packet stream is SHA-256
`f973c971d0bad5eda3a46bc32dc49fb87c2f00d7b776279864c37224b4bfdf9e`.
It generated 3,334 deposits, 3,333 transfers, and 3,333 withdrawals;
reference and portable recovery agreed on 6,667 notes with one unspent note.
Missing, duplicate, reordered, truncated, and discontinuous-equivocation
streams all rejected. Rollback/replay depths 1, 2, 10, and 100 restored the
same terminal commitment.

The real complete-action matrix result is SHA-256
`f6f99b566b515754e3f4bcbfe8a61c385d56c579633adc7e6c11ef0b59f31f8e`:
all ten inputs accepted for each public deposit, transfer, and withdrawal;
224 field/role mutation families had zero false accepts and zero unexecuted
cases. The exact fixture fees equal serialized bytes at one satoshi per byte.

These are local deterministic transition/recovery and Libauth BCH-2026 VM
observations. They do not establish a 256-proof corpus, BCHN standardness,
peer relay, miner inclusion, or production qualification.
