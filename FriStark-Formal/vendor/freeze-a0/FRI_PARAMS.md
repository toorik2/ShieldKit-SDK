# V2 STARK — Production FRI parameters

**Status:** normative freeze. Product eligibility `final` and all Q/B/D evidence must use a config that meets every floor below.

## Source

Production parameter class is taken from upstream 0zkbrewer `native_ct_air_config.py` (Goldilocks DEEP-ALI FRI, GF(p²) challenges). Vendored pin path: `vendor/bch-fri-stark/` with `VENDORED_COMMIT`.

Golf / measure tips (e.g. `nq=1`, `blowup=8`, research score tables under goldilocks-onetx) are **not** product configs. They may appear only in packer unit tests labeled `eligibility: development-only`.

## Field

| Symbol | Value |
|--------|-------|
| Base field | Goldilocks `P = 2^64 - 2^32 + 1` |
| Extension | GF(P²) = F_P[u]/(u² − 7), `7` quadratic non-residue |
| Base ops | S-box, MDS, SHA-256 Merkle node materialization |
| Extension ops | Fiat–Shamir challenges, FRI fold β, DEEP/ALI α |

## Production floor (minimum)

| Param | Floor | Notes |
|-------|------:|-------|
| `BLOWUP` | **2048** | Reed–Solomon blowup |
| `QUERIES` (`nq`) | **8** | Must remain a power of two for topology slot partition |
| `GRIND_BITS` | **24** | Prover PoW; exponential in grind |
| `FOLD` / `fold_step` | **8** (or pin-equal upstream production) | Must match on-chain shard |
| `MASK_DEG` | **≥ 4 × QUERIES** | ZK mask floor |
| `MERKLE_HASH_BYTES` | **32** | Full SHA-256 nodes until a measured CR-preserving cut is frozen in a later A0 revision |
| `SECURITY_TARGET_BITS` | **100** | Fail closed below |

### Headline soundness (conjectural, corrected rate)

Composition degree ~2T is FRI’d directly → tested rate ρ = 2/BLOWUP:

```text
SECURITY_BITS = QUERIES * (log2(BLOWUP) - 1) + GRIND_BITS
require SECURITY_BITS >= 100
```

At the floor: `8 * (log2(2048) - 1) + 24 = 8*10 + 24 = 104` bits.

Import-time assert in product code **must** reject any weaker config when building release runtime material.

## Product param identifier

```text
friParamId = SHA256(
  "SKFRI1" ||
  canonical JSON {
    blowup, queries, grindBits, fold, maskDeg, merkleHashBytes,
    extNonres, field: "goldilocks", scheme: "deep-ali-fri-stark",
    securityTargetBits: 100
  }
)
```

`friParamId` is pinned inside `profileCore` and inside every proof artifact and runtime material blob.

## Forbidden product configs

- Any `SECURITY_BITS < 100`
- `MERKLE_HASH_BYTES < 25` (or any width with birthday CR &lt; target)
- `MASK_DEG < 4 * QUERIES`
- Base-field-only FRI challenges (must use GF(p²) for fold/DEEP)
- Demo/soundness-unwired packers labeled as product
- Low-bit M31 Circle-STARK (`fri_stark*`) as product foundation

## Performance budgets (hard product gates)

| Metric | Budget |
|--------|--------|
| Settlement serialized size | ≤ **100_000** bytes |
| Each unlocking bytecode | ≤ **10_000** bytes |
| VM resource usage | ≤ **100%** of BCH-2026 limits |
| Prove p95 (published machine) | ≤ **60** s |
| Prove RSS | ≤ **4** GiB |

Multi-minute prove work **must** use multi-core (ProcessPool / worker pool). No single-thread prove loops while cores idle.

## Prove policy

- **First-try only.** On prove or densFuel-analogue bind failure: stop and fix root cause. No multi-retry with the same public statement.
- Development may use smaller params only under `eligibility: development-only` and never for Chipnet qualification evidence.

## Strengthening

Raising blowup/queries/grind above the floor is allowed if:

1. `friParamId` is re-frozen,
2. all artifacts and runtime materials are regenerated,
3. size and prove budgets still hold,
4. REQUIREMENT_MATRIX gates are re-run.
