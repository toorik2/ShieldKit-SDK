# ShieldKit — Create and run your own shielded pool on Bitcoin Cash

Unaudited WIP · **Chipnet first** · [SECURITY](./SECURITY.md)

### 1 · Learn
[`01-learn-about-this-system/`](./01-learn-about-this-system/) — static HTML, no wallet/chain.

```bash
python3 -m http.server 8765 --directory 01-learn-about-this-system
# http://127.0.0.1:8765/learn-about-this-system.html
```

### 2 · Legacy playground research
[`02-use-chipnet-demo-pool/`](./02-use-chipnet-demo-pool/) is the existing V1
Chipnet research instance, not a V2 Direct fallback or qualification result.
Mutations require explicit `--protocol v1-legacy` and emit a linkability
warning.

```bash
npm ci
npm run fetch-playground-bundle
npm run unlock-builder:setup
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip
# legacy research only:
npm run shieldkit -- playground deposit --protocol v1-legacy --wallets ./wallets.json --broadcast
```

### 3 · Your pool
[`03-create-your-own-pool/`](./03-create-your-own-pool/) — product surface (kit · pool · CLI).

Docs: [USER_GUIDE](./03-create-your-own-pool/docs/USER_GUIDE.md) · [SHARED_POOL_DESIGN](./03-create-your-own-pool/docs/SHARED_POOL_DESIGN.md) · [V2 Direct protocol boundary](./03-create-your-own-pool/docs/protocol/v2-direct/PROHIBITED_TOPOLOGIES.md)

**Mainnet is not a product claim** in this release (unaudited; see SECURITY and red-team docs).
