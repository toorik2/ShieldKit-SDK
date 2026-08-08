# PF10 implementation

This directory contains the implementation behind the root `shieldkit` command.
PF10 is the supported Product shelf, but it remains an unaudited, Chipnet-only
research beta and is not production-qualified.

From the repository root:

```bash
npm ci
npm run shieldkit -- --version
npm run shieldkit -- pool --help
```

Use the root [Start guide](../../docs/product/start.md) for operation, the
[product model](../../docs/product/model.md) for boundaries, and
[Security](../../SECURITY.md) before handling a funded wallet.

Exact artifacts and qualification methods live beside the code under `pins/`,
`bench/`, and `scripts/`. Those records are evidence, not an audit or a mainnet
claim.
