# Architecture (short)

**Root product surface:** two folders.

```text
create-your-own-pool/     product (this tree)
chipnet-playground/       optional live demo instance
```

```text
loadInstance(ref) → createKit(config)
        │
 ./my-pool/                 chipnet-playground/
 (your genesis)             (optional demo)
```

## Inside create-your-own-pool/

| Path | Role |
|------|------|
| **packages/kit** | App entry: `createKit` |
| **packages/profile** | `init` · genesis · `loadInstance` |
| **packages/action** | Prep · settlement · witness |
| **packages/prove** | Local Groth16 + PF7 (`lab/` / `internal/` = not public API) |
| **packages/recover** | Notes from seed + history |
| **scripts/** | CLI · domain tests · fetch-playground-bundle |
| **templates/** | `init.development.json` |

## Invariants

- Offline: you hold keys, RPC, broadcast  
- Fee 1 sat/B · unlock ≤10k B · settlement ≤59k B  
- New setup ⇒ new profile + new genesis  
- Playground = development-only demo, not a hosted service  

## More

- [PLAYGROUND.md](PLAYGROUND.md) · [CHARTER.md](CHARTER.md) · [PRIVACY.md](PRIVACY.md)
