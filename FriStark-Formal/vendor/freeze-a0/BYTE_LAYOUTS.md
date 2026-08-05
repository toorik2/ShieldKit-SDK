# V2 STARK — Binary layouts

**Status:** normative wire layouts for profile `shieldkit-pool-action-v2-stark`.  
Magic **SKS3** / **SDA3** deliberately differ from Groth16 V2 Direct **SKS2** / **SDA2** (BN254). Cross-decoding must fail closed.

## Shared rules

- Network IDs: mainnet `1`, Chipnet `2`. Product programme qualifies Chipnet only.
- `profileId`, `instanceId`: raw 32-byte values (SHA-256 / token category). Display as lowercase hex, no reverse.
- CashToken category = `instanceId` in token-prefix byte order.
- **GDig32:** 32-byte digest = 4× Goldilocks FE, each limb unsigned BE 8 bytes, limb &lt; P. See CRYPTO_EC_FREE.md.
- Unsigned integers marked `le` are fixed-width little-endian.
- Reserved flags encode as zero; nonzero rejected.
- No varints.

## Goldilocks prime

```text
P = 0xFFFFFFFF00000001 = 2^64 - 2^32 + 1
```

## `SKS3`: state NFT commitment (128 bytes)

Complete state commitment (no secondary state hash).

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SKS3` |
| 4 | 32 | `profileId` | raw SHA-256 |
| 36 | 32 | `noteRoot` | GDig32 |
| 68 | 32 | `nullifierRoot` | GDig32 |
| 100 | 4 | `noteCount` | u32le |
| 104 | 4 | `nullifierCount` | u32le |
| 108 | 4 | `maximumLiveNotes` | u32le |
| 112 | 8 | `reserveSats` | u64le |
| 120 | 8 | `actionSequence` | u64le |
| 128 | 0 | end | exact length |

Invariants (codec + AIR + state covenant):

```text
nullifierCount <= noteCount
liveNoteCount = noteCount - nullifierCount
reserveSats = liveNoteCount * denominationSats
1 <= maximumLiveNotes <= floor(MAX_MONEY_SATS / denominationSats)
liveNoteCount <= maximumLiveNotes
max(noteCount, nullifierCount) <= actionSequence <= noteCount + nullifierCount
noteCount <= 0xffffffff
nullifierCount <= 0xfffffffe
actionSequence < 2^33
```

`denominationSats` is profile context, not serialized.  
`liveNoteCount` is derived, never stored.

State commitment digest for optional off-chain indexes:

```text
stateDig = GDig32(Poseidon2(DOM_STATE || SKS3 bytes as FE packing))
```

Consensus state is the raw 128 bytes on the NFT commitment.

## `SDA3`: action packet (552 bytes)

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SDA3` |
| 4 | 1 | `networkId` | 1 or 2 |
| 5 | 1 | kind | deposit=1, transfer=2, withdrawal=3 |
| 6 | 2 | flags | u16le(0) |
| 8 | 32 | `instanceId` | token-prefix category |
| 40 | 128 | `preState` | complete SKS3 |
| 168 | 128 | `postState` | complete SKS3 |
| 296 | 32 | `publicNullifier` | GDig32 (zero if inactive) |
| 328 | 32 | `outputNoteLeaf` | GDig32 (zero if inactive) |
| 360 | 128 | `encryptedRecord` | EC-free record (CRYPTO) |
| 488 | 32 | `withdrawalLockingBytecodeHash` | raw SHA-256 (zero if inactive) |
| 520 | 32 | `transactionContextHash` | raw SHA-256 |
| 552 | 0 | end | exact length |

### Kind-active fields

| Kind | publicNullifier | outputNoteLeaf + record | withdrawal hash |
|------|-----------------|-------------------------|-----------------|
| Deposit | inactive zero | active | inactive zero |
| Transfer | active | active | inactive zero |
| Withdrawal | active | inactive zero | active |

Active fields may be any valid canonical value including zero GDig32 only where CRYPTO permits; inactive fields must be exact zero bytes.

### Packet commitment

```text
packetCommit = GDig32(Poseidon2Sponge(DOM_PACKET || packetToRateElements(SDA3)))
```

`packetToRateElements`: split 552 bytes into 69 groups of 8 bytes; each group is an integer `x`; require `x < P` for limbs that are specified as FE-bearing regions; for opaque byte regions use raw 8-byte int with the packing rule “reject if ≥ P” **or** split into 7-byte chunks (56-bit) with explicit zero high bytes — **freeze implemented in codecs as:**

**Canonical packing (normative):**

1. Interpret the 552-byte packet as bytes `b[0..552)`.
2. Split into **7-byte big-endian limbs** (always `< 2^56 < P`): 78 full limbs covering 546 bytes, then one final limb from the remaining 6 bytes.
3. Sponge absorb `DOM_PACKET` then all limbs in order; squeeze 4 FE → `packetCommit`.

This packing admits arbitrary opaque bytes (SHA-256 fields, LE counters) without non-canonical Goldilocks limbs.

## Encrypted record (128 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | `eskDig` GDig32 |
| 32 | 32 | `c_rho` |
| 64 | 32 | `c_r` |
| 96 | 32 | `tag` GDig32 |

## Address (161 bytes raw)

See CRYPTO_EC_FREE.md.

## Proof artifact (product schema `stark-proof-artifact-v1`)

JSON (JCS-canonical for hashing) + binary proof blob:

```text
{
  "schema": "shieldkit-v2-stark-proof-artifact-v1",
  "relationId": "shieldkit-pool-action-v2-stark",
  "friParamId": "<64 hex>",
  "airId": "<64 hex>",          // hash of constraint system pin
  "statement": { ... },         // PUBLIC_STATEMENT object
  "proofBlobSha256": "<64 hex>",
  "prover": { "id": "...", "version": "...", "codeSha256": "<64 hex>" }
}
```

`proofBlob` is the opaque STARK proof encoding defined by the vendored prover pin (versioned). Length is not fixed a priori; product journals store blob by sha256 and size.

## Runtime material (`stark-runtime-material-v1`)

Pins verifier redeem hashes per role, topology id, friParamId, airId, profileId, instanceId, carrier base values, and genesis outpoints. Exact schema: `contracts/runtime-material.schema.json`.

## Transaction context hash

```text
transactionContextHash = SHA256( contextMessage )
```

`contextMessage` binds version, network, instanceId, input outpoints, output lockings/values/token fields, and role layout id exactly as implemented in `context.mjs` for v2-stark (fail closed; no optional fields). Binding covenant recomputes and compares to packet offset 520.
