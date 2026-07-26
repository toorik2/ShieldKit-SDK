# ShieldKit — Create and run your own shielded pool on Bitcoin Cash.

### 1 · Learn about this system
→ [`01-learn-about-this-system/learn-about-this-system.html`](./01-learn-about-this-system/learn-about-this-system.html)  
Static page only (no wallet / no chain).

```bash
python3 -m http.server 8765 --directory 01-learn-about-this-system
# open http://127.0.0.1:8765/learn-about-this-system.html
```

### 2 · Try the live demo pool (**CLI**, not browser)
→ [`02-use-chipnet-demo-pool/`](./02-use-chipnet-demo-pool/)

No bitcoind required — public Chipnet Fulcrum is the default chain access.

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
# full act needs wallets.json with funded Chipnet UTXO ≳ 11.5M sats
# see 02-use-chipnet-demo-pool/README.md
```

### 3 · Create your own pool
→ [`03-create-your-own-pool/`](./03-create-your-own-pool/)

```bash
npm run fetch-pin-artifacts
npm run create-pool -- --out ./my-pool --with-genesis --scan-fund --max-notes 16 --broadcast
```

---

Unaudited WIP · Chipnet first · [SECURITY](./SECURITY.md)
