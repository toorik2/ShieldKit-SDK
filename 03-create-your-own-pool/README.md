# ShieldKit

This directory contains the explicitly unqualified V2 beta product CLI. Read
the [V2 Direct implementation plan](docs/protocol/v2-direct/IMPLEMENTATION_PLAN.md)
for the underlying protocol and qualification boundaries.

```bash
npm test
node scripts/shieldkit.mjs --help

# End-user beta product surface.
node scripts/shieldkit.mjs pool create --funding-wallet <absolute-wallet-path> --funding-utxo <txid:vout>
node scripts/shieldkit.mjs deposit
node scripts/shieldkit.mjs withdraw --to <bchtest-p2pkh-address>

# Low-level protocol internals are hidden behind an explicit namespace.
node scripts/shieldkit.mjs dev --help
```

V2 Direct is unaudited, development-only work. It makes no production,
mainnet, BCHN, LeanBCH, or final-qualification claim. Normal help does not list
its low-level wallet, descriptor, synchronization, or operation-lifecycle
commands. Those commands require the `shieldkit dev` namespace, which implies
V2 Direct and rejects `--protocol`. The CLI does not provide automatic resend,
sponsor, faucet, or batching behavior.

The former V1 `init`/`create-pool` material is quarantined and superseded.
Archived V1 mutation research remains available only through explicit
`--protocol v1-legacy` invocations with the mandatory linkability warning. It
is not a V2 fallback and cannot create or migrate V2 state or artifacts.

```text
packages/   kit · profile · action · prove · recover · unlock-builder
scripts/    shieldkit · V2 qualification and development runners
docs/       protocol/v2-direct implementation plan and archived research
```
