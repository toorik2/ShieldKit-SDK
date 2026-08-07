# Lab

PF6 and FRI-STARK are research designs, not alternate product modes.

```bash
npm run shieldkit -- --design pf6 design doctor
npm run shieldkit -- --design fri design doctor
```

The unified catalog deliberately has no exact profile ID for either design.
Every create, deposit, transfer, and withdraw command returns
`CAPABILITY_BLOCKED`; `--allow-lab` cannot replace a frozen profile, destination
binding, durable preparation, whole-transaction validation, single-send
admission, or exact readback.

| Design | Why mutation remains blocked |
| --- | --- |
| [PF6](./pf6.md) | No closed profile package; withdrawal destination binding and the unified durable lifecycle are not qualified |
| [FRI-STARK](./fri.md) | Profile/topology sources and note/key semantics are not frozen; no complete unified lifecycle |

Legacy routers and package-local executables remain only as historical research
source. They are not supported commands, are not part of the package binary,
and must not be used to infer product support.

Repository evidence and story outputs are records, not live instance homes or
mutation authority.
