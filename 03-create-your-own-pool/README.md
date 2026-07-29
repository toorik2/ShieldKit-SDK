# ShieldKit V2 Direct

This directory's active product path is the development-only V2 Direct
surface. Read the [V2 Direct implementation plan](docs/protocol/v2-direct/IMPLEMENTATION_PLAN.md)
before configuring a local instance or attempting an operation.

```bash
npm test
node scripts/shieldkit.mjs --help

# Explicit V2 Direct local surface; final qualification remains blocked.
node scripts/shieldkit.mjs wallet create --protocol v2-direct
node scripts/shieldkit.mjs pool add <descriptor> --protocol v2-direct
node scripts/shieldkit.mjs status --protocol v2-direct
node scripts/shieldkit.mjs deposit|transfer|withdraw ... --protocol v2-direct --broadcast
```

V2 Direct is unaudited, development-only work. It makes no production,
mainnet, live-chain, BCHN, LeanBCH, or final-qualification claim. The CLI does
not provide automatic resend, sponsor, faucet, or batching behavior; recovery
and any broadcast remain explicit operator actions.

The former V1 `init`/`create-pool` material is quarantined and superseded.
Archived V1 mutation research remains available only through explicit
`--protocol v1-legacy` invocations with the mandatory linkability warning. It
is not a V2 fallback and cannot create or migrate V2 state or artifacts.

```text
packages/   kit · profile · action · prove · recover · unlock-builder
scripts/    shieldkit · V2 qualification and development runners
docs/       protocol/v2-direct implementation plan and archived research
```
