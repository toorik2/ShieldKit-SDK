# Architecture (short)

**Product:** create and run **your own** BCH shielded pool.  
**Example:** optional Chipnet playground (same kit, fixed genesis).

```text
loadInstance(ref) → createKit(config)
        │
 chipnet-playground          ./my-pool/
 (optional example)          (your genesis — primary path)
```

## Packages

| Package | Role |
|---------|------|
| **kit** | App entry: `createKit`, network gates, re-exports `loadInstance` |
| **profile** | `init` · setup (dev \| ceremony) · `loadInstance` · genesis · load |
| **action** | Prep · settlement · witness |
| **prove** | Local Groth16 + PF7 unlocks (`lab/` / `internal/` = not public API) |
| **recover** | Notes from seed + history |

**Start:** `packages/kit` (+ `profile` for init/instance).

## Invariants

- Offline: you hold keys, RPC, broadcast  
- Fee 1 sat/B · unlock ≤10k B · settlement ≤59k B  
- New setup ⇒ new profile + new genesis (no hot-swap)  
- Playground = development-only example, not a hosted service  

## More

- [PLAYGROUND.md](PLAYGROUND.md) · [CHARTER.md](CHARTER.md) · [PRIVACY.md](PRIVACY.md)
