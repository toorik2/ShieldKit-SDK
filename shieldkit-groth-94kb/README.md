# ShieldKit-Groth

PF10 Groth16 shielded-pool product CLI (ShieldKit-Groth Beta).

```bash
# from monorepo root
npm run shieldkit -- --version
npm run shieldkit -- pool --help
npm run shieldkit -- pool create --help
npm run shieldkit -- pool deposit --help
npm run shieldkit -- pool withdraw --help
npm run shieldkit -- pool recover --help
npm run shieldkit -- pool doctor

# low-level internals
npm run shieldkit -- dev --help
```

Chipnet-only, unaudited, zero-conf completion. No automatic resend, sponsor, faucet, mining wait, or mainnet claim.

See `docs/protocol/v2-direct/` for protocol boundaries and the requirement matrix.
