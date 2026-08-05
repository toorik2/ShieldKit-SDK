# ShieldKit Protocol V2 STARK — Implementation plan

## 1. Product and security contract

Active plan for the **Goldilocks DEEP-ALI FRI-STARK** product profile. Groth16 V2 Direct remains under `docs/protocol/v2-direct/` as a separate non-migrating profile.

### User flow (only)

```text
sync public pool history
→ construct one private witness locally
→ generate one STARK proof locally (production FRI params)
→ sign one wallet-owned transparent funding input
→ broadcast one BCH settlement transaction
```

No batching, batcher, coordinator, sponsor, faucet, fee ticket, remote prover, preparation transaction, recursive proof, or root-history accumulator. See PROHIBITED_TOPOLOGIES.md.

### Goals

- **Secure:** BCH covenants + one STARK proof enforce note authority, nullifier uniqueness, state transitions, value conservation, and transaction construction binding.
- **Private (sole claim):** a passive BCH observer cannot cryptographically determine which qualifying historical note produced a later nullifier from public chain data alone.
- **History-scalable:** proof size and Merkle-path work are fixed-depth (32), not linear in history length.
- **Not throughput-scalable:** single state NFT serial writer; races require re-prove.

### Network

This programme’s production readiness is **Chipnet-fully-qualified** only. Mainnet refuses by default until a separate reviewed decision.

### Proof foundation

- Upstream: https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier
- Vendored under `vendor/bch-fri-stark/` with `VENDORED_COMMIT`
- Production FRI params: FRI_PARAMS.md (≥100-bit class; no golf tips)
- No trusted setup

### Identity

```text
relationId = shieldkit-pool-action-v2-stark
proof.system = deep-ali-fri-stark
proof.field = goldilocks
crypto = poseidon2-ec-free-v1
noteTreeDepth = 32
nullifierTreeDepth = 32
denominationSats = 10_000_000
```

`profileId = SHA256("SKP3" || RFC8785(profileCore))`.

## 2. State, packet, crypto, trees

Normative detail:

- BYTE_LAYOUTS.md — SKS3 / SDA3
- CRYPTO_EC_FREE.md — Poseidon2 EC-free notes/records
- PUBLIC_STATEMENT.md — statement ABI

### State transitions

Identical counter/reserve semantics to V2 Direct, field switched to GDig32 roots:

**Deposit:** sequence+1, noteCount+1, append note leaf, reserve+D, require preLive &lt; max.  
**Transfer:** sequence+1, noteCount+1, nullifierCount+1, append note, insert nf, reserve unchanged.  
**Withdrawal:** sequence+1, nullifierCount+1, insert nf, reserve−D, require preLive ≥ 1.

Overflow/underflow preconditions explicit in AIR and state covenant.

### Trees

- Note: depth 32 append-only Poseidon2 GDig32 nodes.
- Nullifier: depth 32 indexed, full GDig32 keys, sentinels at physical 0/1, predecessor-linked insert only (not global sort of insertion by time).

### Capacities

- Qualified instance: `maximumLiveNotes` up to `floor(MAX_MONEY/D)` (document instance pin).
- Playground: 32 live notes; deposit 33 rejected before prove.

## 3. Settlement topology

See TOPOLOGY.md.

Roles:

1. **FRI verifier inputs** — multi-input P2SH32 STARK check (0zkbrewer packer lineage).
2. **Binding** — packet/statement/tx-context/instance/state equality.
3. **State** — SKS3 NFT transition + value conservation.
4. **Funding** — single user P2PKH fee input.

Exact FRI input counts freeze after P0 measurement under production params; role **semantics** are frozen now.

## 4. Genesis

`pool create`:

1. Build profile + runtime material (redeem hashes, friParamId, airId).
2. Fund FRI verifier carrier UTXOs (one per verifier role locking).
3. Create mutable state NFT category = instanceId, commitment = genesis SKS3.
4. Write instance descriptor + signed manifest (local owner keys for beta; production uses release signing policy in matrix).

## 5. Action lifecycle

Journal states (product):

```text
created → tip_synced → proving → proved → signing → signed → sending → accepted
```

Artifacts at `proved` are immutable for that operation id (proof blob, statement, unlocks). Tip race ⇒ new operation and re-prove. First-try only on prove/send.

## 6. Recovery

- Reconstruct tip from chain history of state NFT transitions under instance descriptor.
- Recover notes with `ivk` / `sk` from encrypted records.
- Explicit rebroadcast with attempt tokens (no automatic resend storms).

## 7. Qualification

REQUIREMENT_MATRIX.md lists product claims only. **All evidence, campaigns, oracles, clean-host/Chipnet qualification, and terminal closure live in [ShieldKit-Assurance](https://github.com/toorik2/ShieldKit-Assurance)** — not in this repository. Ceremony is replaced by param freeze + multi-impl reproduction (D-01) executed under Assurance. External audit D-02. This product tree implements capability and stable subject surfaces only.

## 8. Implementation tracks

Parallel tracks T1–T13 as in the programme plan; code under `packages/*/v2-stark/`, `vendor/bch-fri-stark/`, `crates/shieldkit-v2-stark-codec/`.

## 9. Explicit non-claims until gates pass

Development-only / unqualified. No production marketing. Privacy claim only with evidence. Mainnet not authorized by this document.
