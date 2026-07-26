# Architecture

```text
03-create-your-own-pool/     product
02-use-chipnet-demo-pool/   optional Chipnet demo
```

| Path | Role |
|------|------|
| `packages/kit` | `createKit` |
| `packages/profile` | init · genesis · `loadInstance` |
| `packages/action` | prep · settlement · witness |
| `packages/prove` | Groth16 · PF7 authority (`lab/` / `internal/` not public API) |
| `packages/recover` | notes from seed + history |
| `packages/unlock-builder` | Node densFuel unlock compile |
| `scripts/` | CLI · tests · fetch |

Invariants: offline keys/RPC/broadcast; fee 1 sat/B; unlock ≤10k B; settlement ≤59k B; new setup ⇒ new profile + genesis.
