# ShieldKit — Create and run your own shielded pool on Bitcoin Cash

Unaudited WIP · Chipnet first · [SECURITY](./SECURITY.md)

### 1 · Learn
[`01-learn-about-this-system/`](./01-learn-about-this-system/) — static HTML, no wallet/chain.

```bash
python3 -m http.server 8765 --directory 01-learn-about-this-system
# http://127.0.0.1:8765/learn-about-this-system.html
```

### 2 · Playground (CLI)
[`02-use-chipnet-demo-pool/`](./02-use-chipnet-demo-pool/) — shared Chipnet instance (cap 16 live × 0.1 BCH). Not a hosted service.

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
# deposit/withdraw: wallets.json + funded UTXO ≳ 11.5M sats (deposit)
```

### 3 · Your pool
[`03-create-your-own-pool/`](./03-create-your-own-pool/)

```bash
npm run fetch-pin-artifacts
npm run create-pool -- --out ./my-pool --with-genesis --scan-fund --max-notes 16 --broadcast
```
