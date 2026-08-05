# V2 STARK — Settlement topology

**Status:** role semantics frozen. **Exact FRI input count and unlock lengths** are filled by track T6 after P0 measurement under production FRI params and recorded in `artifacts/v2-stark/topology/frozen-role-table.json`.

## Input roles (left-to-right)

```text
[ FRI verifier roles: 0 .. N-1 ]  [ binding = N ]  [ state = N+1 ]  [ funding = N+2 ]
```

| Index | Role | Locking class | Unlock source |
|------:|------|---------------|---------------|
| `0 .. N-1` | FRI STARK shards (blob, openers, FRI, composition, …) | P2SH32 per redeem hash in runtime material | Packer from proof+statement |
| `N` | Binding | P2SH32 product binding redeem | Packet + statement equality witnesses |
| `N+1` | State | P2SH32 state covenant | SKS3 preimage continuity / transition witnesses |
| `N+2` | Funding | P2PKH | Wallet signature |

`N ≥ 1` and is exactly `runtimeMaterial.verifierRoles.length`.

### Topology id

```text
topologyId = SHA256(
  "SKTOP1" || RFC8785({
    scheme: "deep-ali-fri-stark",
    friParamId,
    airId,
    verifierRoles: [...],  // ordered names
    binding: "v2-stark-binding-v1",
    state: "v2-stark-state-v1",
    funding: "p2pkh-single-v1"
  })
)
```

## Output layout (deposit / transfer)

Typical shape (exact counts freeze with dust policy):

1. Recreate each FRI verifier carrier UTXO (same redeem locks, rolling values per dust policy).
2. Successor state NFT (mutable, category=instanceId, commitment=postState).
3. Optional change to funding wallet.
4. No sponsor outputs.

Withdrawal adds a transparent payout output locked to `withdrawalLockingBytecode` whose SHA-256 equals packet field.

## Value conservation

```text
sum(input values) = sum(output values) + fee
reserveSats delta matches kind and denomination
state NFT fungible amount = 0
```

State covenant enforces reserve vs transparent pool value rules pinned in profile (same economic intent as V2 Direct).

## Cross-input binding rules

1. Every FRI role is presence-bound from the FS blob role using `OP_UTXOBYTECODE` (spent locking), not unlocking-byte hashes alone — carry 0zkbrewer audit fixes.
2. Binding reads statement/public fields committed by FRI and compares to packet and state NFT.
3. State input index and binding index are constants in redeem (fail closed if layout shifts).
4. Funding cannot substitute for a verifier role.

## Forbidden layouts

- Missing binding or state.
- FRI-only transaction without product roles labeled as a ShieldKit settle.
- Multiple funding inputs required by product (exactly one funding input).
- Prep outputs or second transactions in the product path.

## P0 measurement outputs (required before freeze of N)

Under **production FRI params** + skeleton binding/state:

| Metric | Record |
|--------|--------|
| N (verifier roles) | integer |
| Per-role unlock bytes | array |
| Total serialized tx bytes | integer |
| Op cost | integer |
| Libauth accept | boolean |
| Forge rejects | ≥10 classes |

Write `docs/protocol/v2-stark/P0_SIZE_PROVE_REPORT.md` and `artifacts/v2-stark/topology/frozen-role-table.json`. After that, N is immutable without topologyId change and full re-qualification.
