# ShieldKit — ShieldKit-Groth Beta

Unaudited · **Chipnet only** · PF10 Groth16 shielded pool CLI · [SECURITY](./shieldkit-groth-94kb/docs/SECURITY.md)

**Product:** [`shieldkit-groth-94kb/`](./shieldkit-groth-94kb/)  
**CLI:** `shieldkit`  
**Version:** `0.3.0-beta.1` (see `package.json`)

```bash
npm ci
npm run shieldkit -- --help
npm run shieldkit -- pool create --help
npm run check:no-pf7-release
npm run qualification:beta
```

### Run the benchmark (any machine)

Two modes only. Requires your own Chipnet **data-home** (no author defaults).

```bash
# Full act tip → mempool (live spend)
npm run bench -- --data-home /absolute/path/to/your/install-or-v2-beta-product

# First-machine install cost + one cold prove
npm run bench:cold-start -- --data-home /absolute/path/to/your/install-or-v2-beta-product
```

Reports include product version, `DIRECT_V2_PF10` verifier, network, and full git commit.  
Details: [`shieldkit-groth-94kb/bench/README.md`](./shieldkit-groth-94kb/bench/README.md) · pool setup: [USER_GUIDE](./shieldkit-groth-94kb/docs/USER_GUIDE.md)

### Docs

- [USER_GUIDE](./shieldkit-groth-94kb/docs/USER_GUIDE.md)
- [ARCHITECTURE](./shieldkit-groth-94kb/docs/ARCHITECTURE.md)
- [SECURITY](./shieldkit-groth-94kb/docs/SECURITY.md)
- [CHANGELOG](./shieldkit-groth-94kb/docs/CHANGELOG.md)
- [V2 Direct protocol](./shieldkit-groth-94kb/docs/protocol/v2-direct/)
- [Bench](./shieldkit-groth-94kb/bench/README.md)

### Archives (not the product surface)

- [`archived-pool-designs/`](./archived-pool-designs/) — learn site, V1 Chipnet playground, seven-carrier research

**Mainnet is not a product claim.** No production, audit, or privacy-qualification claim in this beta.
