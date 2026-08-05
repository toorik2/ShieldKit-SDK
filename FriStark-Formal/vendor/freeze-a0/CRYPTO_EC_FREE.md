# V2 STARK — EC-free Poseidon2 cryptography

**Status:** normative freeze (`crypto = poseidon2-ec-free-v1`).  
No BabyJub, no ECDH, no elliptic curve points on the wire or in the AIR.

## Poseidon2 instance

- Field: Goldilocks.
- Permutation: **KAT-compatible with upstream** `native_poseidon2.py` / constants in the vendored pin (width t=12, same round constants and MDS as 0zkbrewer pin).
- Product implementations (JS, Rust, Python AIR) must pass shared KATs in `artifacts/v2-stark/kat/poseidon2/`.
- Domain separation: every sponge absorb starts with a unique **domain tag** (one Goldilocks FE), listed below. Tags are fixed integers, not strings.

## Digest wire type `GDig32`

Privacy-relevant digests (note leaf, nullifier key, Merkle node, authority, cm, rho, nf, packet commitment, authentication tag) use:

```text
GDig32 = 32 bytes = 4 × Goldilocks FE, each FE as unsigned big-endian 8 bytes
```

Construction:

```text
Poseidon2SpongeAbsorb(domainTag || rate elements…)
→ squeeze 4 field elements
→ encodeGDig32
```

**Rationale:** a single 64-bit field element has only ~32-bit birthday collision resistance and is unusable as a note/nullifier/Merkle digest for a production privacy pool. Four squeezed elements give a 256-bit string with Poseidon2 sponge capacity sized for ≥100-bit class targets used with the FRI param floor.

Canonicality: each FE must be in `[0, P)`. Decoding rejects any 8-byte limb ≥ P.

## Secrets

| Secret | Type | Rules |
|--------|------|-------|
| `sk` | 32-byte seed | Uniform; never zero; never leave owner-private storage |
| `ivk` | 32-byte seed | Uniform; never zero; independent of `sk` |
| `esk` | Goldilocks FE | Fresh per output note; nonzero |
| `rhoBlind` | Goldilocks FE | Fresh; nonzero |
| `r` | Goldilocks FE | Fresh note randomness; nonzero |

HD derivation (product wallet) maps BIP32-style account paths into `sk`/`ivk` seeds; exact path map is product-pinned and included in profile toolchain notes, not in consensus state.

## Public keys (not EC points)

```text
spendPk = GDig32(
  Poseidon2(DOM_SPEND_PK, feFromSeed(sk))
)

viewPk = GDig32(
  Poseidon2(DOM_VIEW_PK, feFromSeed(ivk))
)
```

`feFromSeed` interprets the 32-byte seed as four FE limbs reduced mod P with a fixed, fail-closed reduction (documented in KATs). Implementations must match the KAT, not invent alternate reductions.

## Authority and address

```text
authority = GDig32(
  Poseidon2(
    DOM_ADDRESS,
    profileId_as_4fe,
    instanceId_as_4fe,
    spendPk_as_4fe,
    viewPk_as_4fe
  )
)
```

Address payload (bech32 / product encoding is UI; consensus fields are raw):

| Field | Size |
|-------|-----:|
| networkId | 1 |
| profileId | 32 |
| instanceId | 32 |
| spendPk | 32 |
| viewPk | 32 |
| authority | 32 |
| **Total** | **161** |

Receivers verify `authority` recomputation before accepting an address.

## Note commitment and nullifier

Fixed denomination `D = 10_000_000` sats (profile-pinned).

```text
rho = GDig32(
  Poseidon2(
    DOM_RHO,
    profileId_4fe,
    instanceId_4fe,
    postActionSequence_as_fe,   // u64 actionSequence after transition
    rhoBlind
  )
)

cm = GDig32(
  Poseidon2(
    DOM_NOTE,
    profileId_4fe,
    instanceId_4fe,
    D_as_fe,
    authority_4fe,
    rho_4fe,
    r
  )
)

nf = GDig32(
  Poseidon2(
    DOM_NULLIFIER,
    profileId_4fe,
    instanceId_4fe,
    feFromSeed(sk),
    rho_4fe,
    cm_4fe
  )
)
```

Nullifiers are **full 32-byte GDig32 keys** in the indexed nullifier tree (no 128-bit truncation).

## Encrypted record (128 bytes, EC-free)

For each deposit/transfer output, the packet carries a 128-byte record:

```text
Offset  Size  Field
0       32    eskDig     = GDig32(Poseidon2(DOM_ESK_COMMIT, esk))
32      32    c_rho      = rho XOR keystream0
64      32    c_r        = encodeFE(r)||zero-pad XOR keystream1   (see encoding)
96      32    tag        = GDig32(Poseidon2(DOM_RECORD_TAG, …))
```

Key schedule (recipient can open with `ivk`; sender knows `esk` and `viewPk`):

```text
shared = GDig32(
  Poseidon2(DOM_SHARED, esk, viewPk_4fe, profileId_4fe, instanceId_4fe)
)
keystream0 = GDig32(Poseidon2(DOM_KS0, shared_4fe, cm_4fe, 0))
keystream1 = GDig32(Poseidon2(DOM_KS1, shared_4fe, cm_4fe, 1))
tag = GDig32(
  Poseidon2(
    DOM_RECORD_TAG,
    shared_4fe,
    profileId_4fe,
    instanceId_4fe,
    cm_4fe,
    eskDig_4fe,
    c_rho_4fe,
    c_r_4fe
  )
)
```

`c_r` encoding: 8-byte BE canonical FE for `r`, followed by 24 zero bytes, then XOR with keystream1 (full 32). Decoding after XOR requires trailing 24 bytes zero and FE canonical.

**AIR proves:**

- `esk ≠ 0`, `rhoBlind ≠ 0`, `r ≠ 0`
- `eskDig`, `shared`, keystreams, `tag` recomputed as above
- Packet record bytes equal the proven ciphertext and tag
- `viewPk` matches the addressed recipient for transfers/deposits

**Spend side proves** knowledge of `sk` such that `spendPk` matches the note’s authority path and `nf` recomputes.

### Faerie-gold resistance

- `rho` binds `postActionSequence` and instance → no silent cross-action reuse under the same pool without a different sequence.
- `cm` binds authority, rho, r, denomination, profile, instance.
- Leaf binds `cm` and `tag` (below).
- Empty/min/max nullifier sentinels and predecessor-linked inserts prevent double-spend of `nf`.

## Note leaf

```text
outputNoteLeaf = GDig32(
  Poseidon2(DOM_NOTE_LEAF, cm_4fe, tag_4fe)
)
```

No separate RECORD domain beyond `DOM_RECORD_TAG`. The leaf formula is profile-pinned; pools must not import roots from another leaf formula.

## Merkle trees

- **Note tree:** depth **32**, append-only, binary, node = `GDig32(Poseidon2(DOM_NOTE_MERKLE, left_4fe, right_4fe, level_fe))` with domain including level to block depth confusion.
- **Nullifier tree:** depth **32**, indexed (predecessor-linked), leaf types empty / min sentinel / normal / max sentinel as in V2 Direct semantics, keys are GDig32 ordered as unsigned 256-bit big-endian integers for conceptual order `MIN < normal < MAX`.

Empty leaf digests and sentinel digests are domain-separated constants fixed in KATs.

## Domain tags (Goldilocks FE)

| Name | FE value (decimal) |
|------|-------------------:|
| DOM_SPEND_PK | 1 |
| DOM_VIEW_PK | 2 |
| DOM_ADDRESS | 3 |
| DOM_RHO | 4 |
| DOM_NOTE | 5 |
| DOM_NULLIFIER | 6 |
| DOM_ESK_COMMIT | 7 |
| DOM_SHARED | 8 |
| DOM_KS0 | 9 |
| DOM_KS1 | 10 |
| DOM_RECORD_TAG | 11 |
| DOM_NOTE_LEAF | 12 |
| DOM_NOTE_MERKLE | 13 |
| DOM_NF_MERKLE | 14 |
| DOM_NF_LEAF | 15 |
| DOM_PACKET | 16 |
| DOM_STATE | 17 |
| DOM_TX_CONTEXT | 18 |

New domains require an A0 revision and new `profileId`.

## Packet commitment (public statement input)

**Chosen path (sole):** Poseidon2-native packet commitment — **not** SHA-256 limbs as the STARK public statement.

```text
packetCommit = GDig32(
  Poseidon2Sponge(DOM_PACKET || packet[552 bytes] as fixed FE packing)
)
```

Exact FE packing of the 552-byte packet is defined in BYTE_LAYOUTS.md (`packetToRateElements`). Binding covenant and AIR both recompute `packetCommit` from the full packet bytes.

SHA-256 may be used only for non-consensus UI digests or profile hashing (`profileId = SHA256("SKP3" || JCS(profileCore))`), not as the STARK statement.

## Profile hashing

```text
profileId = SHA256( "SKP3" || RFC8785(profileCore) )
```

`profileCore` includes: network, denomination, tree depths, Poseidon2 pin hashes, domain tag table hash, FRI param id, relation id, public statement schema hash, base verifier artifact hashes, encodings versions, toolchain versions. It excludes instance-specific scripts containing `profileId`/`instanceId` (no hash cycle).
