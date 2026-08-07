# ShieldKit SDK

Local tooling for creating and operating Bitcoin Cash shielded pools.

> Research beta. Chipnet only. Unaudited. No profile in this repository is
> mainnet-qualified, production-qualified, or a promise of anonymity.

## Start

The supported root command runs the PF10 Groth16 beta:

```bash
npm ci
npm run shieldkit -- --version
npm run shieldkit -- pool --help
```

Read [Start](./docs/product/start.md) before using a funded wallet. Successful
zero-confirmation admission and readback is the operational completion boundary;
it is not confirmation or finality.

## What is here

| Shelf | Surface | Meaning |
| --- | --- | --- |
| **Product** | Root `shieldkit` command · PF10 | Supported beta path; Chipnet only and not production-qualified |
| **Lab** | `cli/` · PF6 · FRI-STARK | Executable research with known portability or qualification gaps |
| **Record** | Specs · evidence · audits · archives | Versioned observations and decisions, not current instructions |

The experimental router in `cli/` is not the root product command. In
particular, `npm run shieldkit -- --profile …` is unsupported; see
[Lab profiles](./docs/lab/README.md) for the exact boundary.

## Read

- [Start](./docs/product/start.md) — install, inspect, and operate PF10
- [Model](./docs/product/model.md) — toolkit, profile, instance, and data flow
- [Verify](./docs/product/verify.md) — tests, evidence, and qualification language
- [Security](./SECURITY.md) — secrets, privacy limits, and reporting
- [Lab](./docs/lab/README.md) — PF6, FRI-STARK, and the profile router
- [Record](./docs/record/README.md) — deep protocol and historical material

ShieldKit is a toolkit, not a hosted pool, relay, wallet service, or custody
provider. Each pool instance has its own genesis and its own anonymity set.
