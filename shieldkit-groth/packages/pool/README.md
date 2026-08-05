# @shieldkit/pool

Shared multi-user pool product layer:

- **Public tip rebuild** (`tip-rebuild.mjs`) — chain-as-log events → tip view → tip NFT check  
- **Private note wallet** (`note-wallet.mjs`) — my notes only + encrypted backup  
- **Act merge** (`product-api.mjs`) — public tip + my notes for witness  

## Tests

```bash
node --test *.test.mjs
node multiuser-sim.e2e.mjs /tmp/report.json
```

See `docs/SHARED_POOL_DESIGN.md`, `docs/USER_GUIDE.md`, `docs/SHARED_POOL_REDTEAM.md`.
