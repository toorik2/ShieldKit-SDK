# `@shieldkit/v2-direct`

ShieldKit Protocol **V2 Direct** — native 128-byte SKS2 state, 552-byte SDA2 action packet, one local Groth16 proof, one self-funded settlement transaction.

**Publish surface:** `Protocol-design-v2/` (docs, maturity banner, bin entry).  
Authority: `docs/protocol/v2-direct/IMPLEMENTATION_PLAN.md`

```
DEV KEYS ONLY — not for real-money privacy · Mainnet gated until Phase D
```

## Status

See `docs/protocol/v2-direct/STATUS.md` and `Protocol-design-v2/MATURITY.md`.

## Quick test

```bash
node --test 03-create-your-own-pool/packages/v2-direct/**/*.test.mjs \
  03-create-your-own-pool/packages/v2-direct/*.test.mjs
```

## CLI

```bash
# Product entry
node Protocol-design-v2/bin/shieldkit-v2.mjs --help

# Implementation entry (same)
node 03-create-your-own-pool/packages/v2-direct/cli/shieldkit-v2.mjs wallet create
```

No faucet. Funding via blank-machine `funding-wallet.json` only. Secrets mode `0600`.
