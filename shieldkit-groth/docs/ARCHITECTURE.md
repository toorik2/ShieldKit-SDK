# Architecture

```text
shieldkit-groth/     product
02-use-chipnet-demo-pool/   optional Chipnet demo
```

| Path | Role |
|------|------|
| `packages/kit` | `createKit` |
| `packages/profile` | init · genesis · `loadInstance` |
| `packages/action` | prep · settlement · witness |
| `packages/prove` | Groth16 · PF10 adapters (`v2/`; legacy seven-carrier research outside product tree) |
| `packages/recover` | notes from seed + history |
| `packages/unlock-builder` | Node PF10 unlock compile |
| `scripts/` | CLI · tests · fetch |

Invariants: offline keys/RPC/broadcast; fee 1 sat/B; unlock ≤10k B; settlement ≤59k B; new setup ⇒ new profile + genesis.
