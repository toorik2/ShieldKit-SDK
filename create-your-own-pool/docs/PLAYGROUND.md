# Live demo vs your pool

| Path | Purpose |
|------|---------|
| **[`create-your-own-pool/`](../../create-your-own-pool/)** | **Primary** product |
| **[`use-chipnet-demo-pool/`](../../use-chipnet-demo-pool/)** | Optional Chipnet **CLI** demo |
| **[`local-explainer-webpage/`](../../local-explainer-webpage/)** | Static learn site (no chain) |

```text
loadInstance(ref) → createKit / pool-act
        │
 ./my-pool/              use-chipnet-demo-pool/
 (your genesis)          (shared playground · max 1 live note)
```

**Demo is CLI only** — not a browser wallet.

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe    # public Chipnet Fulcrum by default
npm run shieldkit -- playground doctor
npm run shieldkit -- playground deposit --wallets ./wallets.json --scan-fees --broadcast
```

RPC fallbacks: `SHIELDKIT_RPC_URL` → `SHIELDKIT_ELECTRUM` → public Fulcrum → lab `layer1-node`.  
Details: [`use-chipnet-demo-pool/README.md`](../../use-chipnet-demo-pool/README.md).
