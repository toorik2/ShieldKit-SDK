# Architecture (short)

**Product:** create and run **your own** BCH shielded pool — `packages/kit` + `packages/profile`.  
**Optional demo:** root `chipnet-playground-live-pool/` (fixed Chipnet instance).

```text
loadInstance(ref) → createKit(config)
        │
 ./my-pool/                    chipnet-playground-live-pool/
 (your genesis — primary)      (optional demo)
```

## Packages

| Package | Role |
|---------|------|
| **kit** | App entry: `createKit`, network gates, re-exports `loadInstance` |
| **profile** | **Create-your-pool spine:** `init` · setup · genesis · `loadInstance` |
| **action** | Prep · settlement · witness |
| **prove** | Local Groth16 + PF7 unlocks (`lab/` / `internal/` = not public API) |
| **recover** | Notes from seed + history |

**Start:** `packages/kit` (+ `profile` for init/instance).  
**No `examples/` dir** — demo is the live-pool folder; product is packages.

## Invariants

- Offline: you hold keys, RPC, broadcast  
- Fee 1 sat/B · unlock ≤10k B · settlement ≤59k B  
- New setup ⇒ new profile + new genesis (no hot-swap)  
- Playground = development-only demo, not a hosted service  

## More

- [PLAYGROUND.md](PLAYGROUND.md) · [CHARTER.md](CHARTER.md) · [PRIVACY.md](PRIVACY.md)
