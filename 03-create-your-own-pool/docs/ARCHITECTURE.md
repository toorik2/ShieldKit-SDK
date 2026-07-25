# Architecture (short)

**Root product surface:** two folders.

```text
03-create-your-own-pool/     product (this tree)
02-use-chipnet-demo-pool/    optional Chipnet live demo
```

```text
loadInstance(ref) → createKit(config)
        │
 ./my-pool/                 02-use-chipnet-demo-pool/
 (your genesis)             (optional demo)
```

## Inside 03-create-your-own-pool/

| Path | Role |
|------|------|
| **packages/kit** | App entry: `createKit` |
| **packages/profile** | `init` · genesis · `loadInstance` |
| **packages/action** | Prep · settlement · witness |
| **packages/prove** | Local Groth16 + verifier unlocks (`lab/` / `internal/` = not public API) |
| **packages/recover** | Notes from seed + history |
| **scripts/** | CLI · domain tests · fetch-playground-bundle |
| **templates/** | `init.development.json` |

## Invariants

- Offline: you hold keys, RPC, broadcast  
- Fee 1 sat/B · unlock ≤10k B · settlement ≤59k B  
- New setup ⇒ new profile + new genesis  
- Demo pool = development-only, not a hosted service  

## More

- [PLAYGROUND.md](PLAYGROUND.md) · [CHARTER.md](CHARTER.md) · [PRIVACY.md](PRIVACY.md)
