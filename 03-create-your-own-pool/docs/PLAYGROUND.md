# Playground vs your pool

**Full Chipnet golden path (own pool or playground):** [GOLDEN_PATH.md](./GOLDEN_PATH.md)

| Path | Role |
|------|------|
| [`01-learn-about-this-system/`](../../01-learn-about-this-system/) | Static learn site |
| [`02-use-chipnet-demo-pool/`](../../02-use-chipnet-demo-pool/) | Shared Chipnet CLI demo (cap 16) |
| [`03-create-your-own-pool/`](../../03-create-your-own-pool/) | Product |

```bash
npm ci && npm run fetch-playground-bundle && npm run unlock-builder:setup
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
npm run shieldkit -- playground deposit --wallets ./wallets.json --broadcast
npm run shieldkit -- playground withdraw --wallets ./wallets.json --broadcast
```

Fees, tip discovery, and **chain-as-log tip rebuild** (tip → genesis settlement walk) are automatic —
blank join on a multi-history playground tip does not require a pre-seeded `tipForest`.  
Details: [`02-use-chipnet-demo-pool/README.md`](../../02-use-chipnet-demo-pool/README.md).
