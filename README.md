# ShieldKit SDK

Local tooling for creating and operating Bitcoin Cash shielded pools.

> Research beta. Chipnet only. Unaudited. Nothing in this repository is
> mainnet-qualified, production-qualified, or a promise of anonymity.

## Start

The package exposes one CLI grammar:

```bash
npm ci
npm run shieldkit -- --help
npm run shieldkit -- design list
npm run shieldkit -- --design pf10 design doctor
```

PF10 is the only money-moving backend. It delegates to the existing beta
lifecycle and requires an exact, validated instance home. PF6 and FRI-STARK are
visible for inspection, but every mutation remains blocked.

Read [Start](./docs/product/start.md) before using a funded wallet. Successful
zero-confirmation mempool admission plus exact transaction readback is the
operational completion boundary; it is not confirmation or finality.

## Current boundary

| Surface | State |
| --- | --- |
| Design catalog and local doctor | Available through the unified CLI |
| PF10 create, deposit, transfer, withdraw, and delivery recovery | Delegated beta path; Chipnet only |
| PF10 instance status and canonical sync | Blocked until real lineage observation is wired |
| PF6 and FRI-STARK mutations | Blocked; no emulated lifecycle |
| Demo catalog | Unavailable until a real descriptor is signed by a pinned key |
| Wallet/developer command groups | Not exposed until real backends exist; benchmarks use explicit npm scripts |

The shared transactional lifecycle kernel is conformance-tested infrastructure.
It is not a parallel PF10 send path and does not make PF6 or FRI executable.

## Read

- [Start](./docs/product/start.md) — install, import or create a PF10 instance,
  then operate it
- [Model](./docs/product/model.md) — design, profile, instance, home, operation,
  and tip
- [Verify](./docs/product/verify.md) — tests, evidence, and qualification language
- [Security](./SECURITY.md) — secrets, privacy limits, and reporting
- [Lab](./docs/lab/README.md) — PF6 and FRI-STARK boundaries
- [Record](./docs/record/README.md) — protocol and historical material

ShieldKit is a toolkit, not a hosted pool, relay, wallet service, or custody
provider. Each pool instance has its own genesis and anonymity set.
