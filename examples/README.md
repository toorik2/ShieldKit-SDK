# Examples

> ShieldKit creates shielded pools; the Chipnet playground is our pool; your pool is the same thing with your genesis.

| Path | Audience | Purpose |
|------|----------|---------|
| **[chipnet-playground/](chipnet-playground/)** | **App builders** | Connect to the official Chipnet pool |
| **[create-your-pool/](create-your-pool/)** | **Pool creators** | Init + genesis your own instance |

Both use `loadInstance` → `createKit` — same spine.

```bash
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs init --config examples/create-your-pool/init.example.json
```
