# Consensus op-cost differential (vs libauth 3.1.0-next.8)

A reproducible, **build-gating** cross-check of LeanBCH's BCH-2026 op-cost model against the pinned
reference implementation `@bitauth/libauth` 3.1.0-next.8.

## What it does

`gen.mjs` runs each locking script in `battery.txt` (hex, executed P2S from an empty stack) through
libauth's BCH-2026 virtual machine (`createVirtualMachineBch2026`) and records the five raw
consensus cost metrics from `result.metrics`:

| metric | field |
|---|---|
| arithmeticCost | `arithmeticCost` |
| hashDigestIterations | `hashDigestIterations` |
| signatureCheckCount | `signatureCheckCount` |
| stackPushedBytes | `stackPushedBytes` |
| evaluatedInstructionCount | `evaluatedInstructionCount` |

These are the exact five terms the op-cost formula sums:
`opCost = 100·ops + 26000·sigChecks + H·hashIters + arithmeticCost + stackPushedBytes`.

It writes two committed artifacts:
- `vectors.txt` — human-readable `hex a h s p e` per script.
- `vectors.lean.txt` — the **machine-generated** Lean literal (never hand-typed) embedded in
  `LeanBCH/Validation/CostDifferential.lean`.

`LeanBCH.Validation.CostDifferential.costDifferentialGuard` (a build-time `#eval`) runs each script
through LeanBCH's metered VM (`runScript`) and throws — **failing
`lake build LeanBCHValidation`** — on any metric mismatch.
So a cost-constant transcription slip in the model is caught at build time against libauth's own
output, closing the "self-consistent witness" gap.

## Coverage (26 vectors)

Arith (ADD/SUB/MUL/DIV/MOD/1ADD/1SUB/ABS/NOT, small + multi-byte operands), all five hash ops
(SHA1/SHA256/RIPEMD160/HASH160/HASH256 over 1-byte and 40-byte inputs), NUM2BIN/BIN2NUM, CAT,
DUP/2DUP/3DUP/OVER, DEPTH. **All match libauth exactly.**

Not covered here: signature-cost behavior. All 26 vectors have
`signatureCheckCount = 0`; a CHECKSIG/CHECKMULTISIG differential needs live secp256k1 signatures,
which are outside this mathlib-free core. Therefore nonzero sigcheck counting, the
`26000·signatureCheckCount` rate, and signature serialization hash charges are **not numerically
validated** by this differential. The stub-oracle witnesses in `LeanBCH/VM/Extended.lean` exercise
signature control flow and digest handoff, not a numeric libauth cost comparison (see
`../RESULTS.md`). libauth's `metrics.operationCost` uses the STANDARD hash factor H=192; the CONSENSUS
factor H=64 is the epoch choice in `Epoch.operationCost`, so the differential compares raw metrics
rather than libauth's aggregate operation-cost value.

## Regenerate

```
node conformance/cost/gen.mjs
```

Needs `@bitauth/libauth` 3.1.0-next.8 reachable at the relative path in `gen.mjs` (adjust the import
if your checkout differs). After regenerating, paste `vectors.lean.txt` into the `costVectors` list in
`LeanBCH/Validation/CostDifferential.lean` and run `lake build LeanBCHValidation`; the guard re-pins
the model to the fresh ground truth.
