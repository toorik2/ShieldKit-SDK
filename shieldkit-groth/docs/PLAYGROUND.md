# Playground vs your pool

There is no public V2 Direct golden path while final qualification remains open.
The active V2 boundary is [PROHIBITED_TOPOLOGIES.md](./protocol/v2-direct/PROHIBITED_TOPOLOGIES.md).

| Path | Role |
|------|------|
| [`previous-versions/01-learn-about-this-system/`](../../previous-versions/01-learn-about-this-system/) | Static learn site |
| [`previous-versions/02-use-chipnet-demo-pool/`](../../previous-versions/02-use-chipnet-demo-pool/) | Explicit V1 legacy Chipnet research instance (cap 32) |
| [`shieldkit-groth/`](../../shieldkit-groth/) | Product |

```bash
npm ci && npm run fetch-playground-bundle && npm run unlock-builder:setup
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
npm run shieldkit -- playground deposit --protocol v1-legacy --wallets ./wallets.json --broadcast
npm run shieldkit -- playground withdraw --protocol v1-legacy --wallets ./wallets.json --broadcast
```

These commands exercise archived V1 behavior and emit the mandatory
linkability warning. They are not V2 qualification evidence. Fees, tip
discovery, and **chain-as-log tip rebuild** (tip → genesis settlement walk) are
automatic; blank join on a multi-history playground tip does not require a
pre-seeded `tipForest`.
Details: [`previous-versions/02-use-chipnet-demo-pool/README.md`](../../previous-versions/02-use-chipnet-demo-pool/README.md).
