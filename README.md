# ShieldKit (default) — ShieldKit-Groth Beta

Unaudited · **Chipnet only** · PF10 Groth16 shielded pool CLI · [SECURITY](./SECURITY.md)

This checkout is the **default ShieldKit product** under `ZK-Proofs/shieldkit-sdk/`.  
Earlier mainline trees live in [`../Previous versions/`](../Previous%20versions/).

**Product root:** [`shieldkit-groth/`](./shieldkit-groth/)  
**Executable:** `shieldkit`  
**Version:** see root `package.json` (`0.3.0-beta.1` candidate)

```bash
npm ci
npm run shieldkit -- --help
npm run shieldkit -- pool --help
npm run shieldkit -- pool create --help
npm run check:no-pf7-release
npm run qualification:beta   # local/package beta gate (not live Chipnet)
```

### Learn
[`01-learn-about-this-system/`](./01-learn-about-this-system/) — static HTML, no wallet/chain.

### Legacy research (not beta product)
[`02-use-chipnet-demo-pool/`](./02-use-chipnet-demo-pool/) — V1 playground instance.  
[`legacy-research/v1-seven-carrier/`](./legacy-research/v1-seven-carrier/) — moved seven-carrier research (out of release closure).

### Docs
- [USER_GUIDE](./shieldkit-groth/docs/USER_GUIDE.md)
- [ARCHITECTURE](./shieldkit-groth/docs/ARCHITECTURE.md)
- [V2 Direct protocol](./shieldkit-groth/docs/protocol/v2-direct/)

**Mainnet is not a product claim.** No production, audit, or privacy-qualification claim in this beta.
