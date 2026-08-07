# Lane: `goldilocks-98k`

**Banked shippable** Goldilocks DEEP-ALI FRI-STARK tip on BCH-2026.

| Field | Value |
|-------|--------|
| Tip score | **98776** |
| FRI profile | nq=7, B=2048, g=30, depth=4 |
| SECURITY_BITS | **100** (`q*(log2(B)-1)+g`) |
| Label | **shippable** |
| Measure | `./lanes/goldilocks-98k/measure/measure.sh sound-secure --nq 7 --grind-b 30 --depth 4` |
| Baseline | `notes/BASELINE.md` |
| Active size campaign | `lanes/goldilocks-target-80k` (toward &lt;80k under the same ship bar) |

## Rules

- This lane holds the **honest ≥100-bit** tip. Do not re-introduce demo-param (nq=1/B=8/g=2) tips as ship claims.
- Historical research-golf **28564** may appear in BASELINE notes only; it is **not** the lane identity.
- Size golf under the ship bar happens in **`goldilocks-target-80k`**, not by renaming this band early.

## Quick commands

```bash
./lanes/goldilocks-98k/measure/measure.sh sound-secure --nq 7 --grind-b 30 --depth 4
node --test lanes/goldilocks-98k/test/*.test.mjs
```
