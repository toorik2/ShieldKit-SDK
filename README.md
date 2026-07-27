# ShieldKit — Create and run your own shielded pool on Bitcoin Cash

Unaudited WIP · **Chipnet first** · [SECURITY](./SECURITY.md)

### 1 · Learn
[`01-learn-about-this-system/`](./01-learn-about-this-system/) — static HTML, no wallet/chain.

```bash
python3 -m http.server 8765 --directory 01-learn-about-this-system
# http://127.0.0.1:8765/learn-about-this-system.html
```

### 2 · Playground (shared Chipnet demo)
[`02-use-chipnet-demo-pool/`](./02-use-chipnet-demo-pool/) — cap 32 live × 0.1 BCH. Not a hosted service.

```bash
npm ci
npm run fetch-playground-bundle
npm run unlock-builder:setup
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
# then: playground deposit|withdraw --wallets ./wallets.json --broadcast
```

### 3 · Your pool
[`03-create-your-own-pool/`](./03-create-your-own-pool/) — product surface (kit · pool · CLI).

Docs: [GOLDEN_PATH](./03-create-your-own-pool/docs/GOLDEN_PATH.md) · [USER_GUIDE](./03-create-your-own-pool/docs/USER_GUIDE.md) · [SHARED_POOL_DESIGN](./03-create-your-own-pool/docs/SHARED_POOL_DESIGN.md)

**Mainnet is not a product claim** in this release (unaudited; see SECURITY and red-team docs).
