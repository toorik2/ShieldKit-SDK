# ShieldKit

Create and run your own shielded pool on Bitcoin Cash.

After genesis: **no admin key** — rules and capacity are fixed on-chain. Your keys, your instance.

---

## Pick a path

### 1. Learn about this system
→ [`local-explainer-webpage/learn-about-this-system.html`](./local-explainer-webpage/learn-about-this-system.html)  
Static page only (no wallet / no chain).

### 2. Try the live demo pool (**CLI**, not browser)
→ [`use-chipnet-demo-pool/`](./use-chipnet-demo-pool/)

No bitcoind required — public Chipnet Fulcrum is the default chain access.

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe          # should show electrum · chipnet.bch.ninja
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip    # auto-discover State NFT tip
# full act: wallets.json with funded Chipnet UTXO ≳ 11.5M sats
# see use-chipnet-demo-pool/README.md
```

### 3. Create your own pool
→ [`create-your-own-pool/`](./create-your-own-pool/)

---

Unaudited WIP · Chipnet first · [SECURITY](./SECURITY.md)
