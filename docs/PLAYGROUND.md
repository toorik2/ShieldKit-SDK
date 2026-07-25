# Live demo vs your pool

> ShieldKit creates shielded pools.  
> **Primary:** your own pool via `packages/profile` + `packages/kit`.  
> **Optional:** Chipnet live demo at `chipnet-playground-live-pool/`.

## What we provide

| We provide | We do **not** provide |
|------------|------------------------|
| SDK/CLI to **create and operate** your pool | A hosted pool for third-party apps |
| A Chipnet **example instance** to try flows | Production privacy or shared SaaS anonymity |

## Paths

| Path | Purpose |
|------|---------|
| **Create your pool** | `packages/profile` init → genesis → `loadInstance('./my-pool')` → `createKit` |
| **Try live demo** | `loadInstance('chipnet-playground')` / CLI `playground …` |

```text
loadInstance(ref) → createKit(...)
        │
 ./my-pool/                       chipnet-playground-live-pool/
 (your genesis — primary)         (optional demo instance)
```

## Entry

- Product: [`packages/profile/README.md`](../packages/profile/README.md) · [`templates/init.development.json`](../templates/init.development.json)
- Demo: [`chipnet-playground-live-pool/`](../chipnet-playground-live-pool/)

## Honesty

- Playground: Chipnet, **development-only**, Unaudited — Work In Progress  
- Not production privacy; not a service you depend on for production  
