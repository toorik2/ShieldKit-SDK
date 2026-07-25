# Examples

> ShieldKit creates shielded pools. The Chipnet playground is a live **example**. Your pool is the same thing with **your** genesis.

| Path | Purpose |
|------|---------|
| **[chipnet-playground/](chipnet-playground/)** | Optional: try flows on our Chipnet demo instance |
| **[create-your-pool/](create-your-pool/)** | Product path: birth and run **your** pool |

We do not offer a hosted pool for apps. The playground is only so you can play before you create yours.

```bash
node scripts/shieldkit.mjs playground doctor   # example instance
node scripts/shieldkit.mjs init --config examples/create-your-pool/init.example.json
```
