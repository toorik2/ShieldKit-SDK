# Unified CLI kernel

This directory contains ShieldKit's package entry point, strict command parser,
closed design catalog, immutable home binding, capability model, PF10 bridge, and
transactional lifecycle conformance kernel.

```bash
node cli-kernel/bin/shieldkit.mjs --help
npm run cli:kernel -- design list
npm run cli:kernel:test
```

## Boundary

| Part | State |
| --- | --- |
| Unified parser, result envelope, identity/home rules | Implemented |
| PF10 create/actions/recovery | Delegated to the existing beta product lifecycle |
| Shared durable operation coordinator | Implemented and conformance-tested; not wired as another PF10 send path |
| PF10 status/sync | Blocked rather than mapped to a local doctor |
| PF6/FRI mutations | Blocked; no evidence-fixture emulation |
| Signed demo catalog | Not available |
| Wallet/developer groups | Not advertised until real implementations exist |

The package `shieldkit` binary points here. The PF10 product CLI remains an
internal lifecycle backend and a bounded compatibility command:
`npm run shieldkit:legacy-pf10`. The old Lab router is deprecated through
**2026-11-07**.

See [Operator guide](./docs/OPERATOR.md).
