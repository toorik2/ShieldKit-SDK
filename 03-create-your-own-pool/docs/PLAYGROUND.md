# Live demo vs your pool

| Path | Purpose |
|------|---------|
| **[`01-learn-about-this-system/`](../../01-learn-about-this-system/)** | Static learn site (no chain) |
| **[`02-use-chipnet-demo-pool/`](../../02-use-chipnet-demo-pool/)** | Optional Chipnet **CLI** demo |
| **[`03-create-your-own-pool/`](../../03-create-your-own-pool/)** | **Primary** product |

```text
loadInstance(ref) → createKit / pool-act
        │
 ./my-pool/              02-use-chipnet-demo-pool/
 (your genesis)          (shared playground · max 1 live note)
```

**Demo is CLI only** — not a browser wallet.

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe    # public Chipnet Fulcrum by default
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
npm run shieldkit -- playground deposit --wallets ./wallets.json --scan-fees --broadcast
```

Details: [`02-use-chipnet-demo-pool/README.md`](../../02-use-chipnet-demo-pool/README.md).
