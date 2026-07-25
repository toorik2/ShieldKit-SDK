# Example playground & your pool

**Product story**

> ShieldKit creates shielded pools.  
> The Chipnet playground is a **live example** of a pool built with this kit.  
> Your product use-case is **your own pool** — same toolkit, your genesis.

## What we sell (conceptually)

| We provide | We do **not** provide |
|------------|------------------------|
| SDK/CLI to **create and operate** your pool | A hosted pool for third-party apps to “use as infrastructure” |
| A Chipnet **example instance** to try the flows | Production privacy, mainnet playground, or shared SaaS anonymity |

## How to think about the two paths

| Path | Purpose |
|------|---------|
| **Create your pool** | **Primary** product job: `init` → genesis → operate **your** instance forever |
| **Try the example** | Optional: deposit/transfer/recover against the Chipnet demo |

Both use `loadInstance` → `createKit`. No second product.  
**Start:** `packages/kit` (+ `profile` for init/instance).

```text
loadInstance(ref) → createKit(...)
        │
 ./my-pool/                  chipnet-playground
 (your genesis — primary)    (optional example)
```

## Honesty

- Playground: Chipnet, **development-only**, Unaudited — Work In Progress  
- Not production privacy; not a service you depend on for production  
- After you learn the shape, run **your** pool

## Entry points

- Example: [`examples/chipnet-playground/`](../examples/chipnet-playground/)  
- Create: [`examples/create-your-pool/`](../examples/create-your-pool/)
