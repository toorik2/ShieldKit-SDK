# LeanBCH

**A formalized, differentially-validated model of the Bitcoin Cash (BCH-2026) script VM and its consensus op-cost model — in Lean 4 core, no mathlib.**

LeanBCH is a faithful, *executable* model of the BCH VM: a total small-step machine over parsed bytecode with **inline control flow**, the five-metric consensus **cost model**, a byte-exact **transaction/sighash** encoder, and a conformance harness for the official libauth `vmb_test` corpus.

## Honest scope

LeanBCH is a **model validated against reality**, not the authoritative consensus spec (BCHN is canonical) and not proven-equivalent to it. Its trust story is layered and disclosed:

- **Modeled + executable in Lean:** the VM semantics, cost formulas, sighash serialization, native SHA-256 / RIPEMD-160 / SHA-1 hashing, and the BCH-2026 consensus verifier.
- **Validated, not proven:** the 26-vector libauth differential pins the non-signature raw cost metrics; the harness exercises the non-oracle VM surface against `vmb_test`. Neither establishes equivalence to BCHN.
- **Explicit oracle:** secp256k1 verification is a parameter that determines signature accept/reject. It is deliberately outside the mathlib-free core; **no cost metric depends on the oracle result**.
- **Execution / proof boundary:** the frozen theorem-bearing `stepInstr` core covers the pure stack / number / arithmetic / flow-control surface (including BEGIN/UNTIL) and the optimizer's straight-line bridge. The `runExt` interpreter implements the later BCH-2026 extensions: INVERT/shifts, DEFINE/INVOKE functions, full transaction introspection (including `OP_ACTIVEBYTECODE`), CashToken introspection, CLTV/CSV, REVERSEBYTES, CODESEPARATOR, and signature opcode plumbing. The extensions are KAT- and conformance-tested; that is validation, not a proof of BCHN equivalence.
- **Signature boundary:** hashes execute natively, but the signature corpus needs real secp256k1 signatures and cannot be scored with the reject oracle. Schnorr-multisig checkbits and strict DER/public-key encoding gates remain deliberate deferrals.

The claim to make is *"an executable formalization of the BCH VM semantics, validated against the reference implementation and the official test vectors"* — the KEVM / EVMYulLean register — never *"the verified VM."*

## Trust & audit

The trust base is meant to be read off the tree, not taken on faith:

- **[`TRUST_MANIFEST.md`](TRUST_MANIFEST.md)** — *generated* from the kernel (`tools/manifest/gen.mjs`): the three tiers — PROVEN (headline theorems + their computed axiom footprints) / VALIDATED (the libauth differential + `vmb_test` corpus + build-time KATs) / ASSUMED (the secp256k1 oracle). Do not hand-edit.
- **[`RED_TEAM_AUDIT.md`](RED_TEAM_AUDIT.md)** — the adversarial audit record: what held under attack, the findings that were fixed, and the honest residual.

A skeptic can re-check everything with `bash tools/opt-ci/verify.sh` (builds all targets, 0 `sorry`, axiom-clean, fold-table reproducible, necessity closure stable, KAT-conserved).

## Layout

```
LeanBCH.Core         -- Bytes := List UInt8 (kernel-reducible; the proof-facing value type)
LeanBCH.Epoch        -- the consensus pins + limits (BCH_2026_05); every signature carries an Epoch
LeanBCH.Number       -- VM-number encoding (bigIntToVmNumber width) + the width lattice
LeanBCH.Opcode       -- opcode-byte classifiers (arith/hash/sig kinds, families)
LeanBCH.Crypto       -- native SHA-256 / RIPEMD-160 + the Secp256k1 oracle
LeanBCH.Cost         -- the five-metric operationCost model over the Epoch
LeanBCH.Tx           -- the transaction/UTXO context + byte-exact sighash
LeanBCH.VM           -- parse, State, step/run (inline control), the straight-line seam
LeanBCH.VM.Extended  -- BCH-2026 extensions and the metered consensus run
LeanBCH.VM.Standard  -- optional relay-policy classification over consensus
LeanBCH.Validation   -- build-time KATs and the separate libauth cost differential
LeanBCH.Conformance  -- the official vmb_test runner
```

Dependency arrows point one way. LeanBCH never imports its consumers; the private `stackcert` cost-reasoning engine (floors / optimize / certificates) imports *this*.

## Build

```
lake build
```

Lean `leanprover/lean4:v4.31.0`, no dependencies.

## License

Apache-2.0. The vendored `vmb_test` vectors retain their upstream MIT notice (see `Conformance/` provenance).
