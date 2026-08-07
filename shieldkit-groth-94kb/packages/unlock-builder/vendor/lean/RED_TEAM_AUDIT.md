# LeanBCH — adversarial red-team audit (2026-07-07)

Method: five independent hostile agents, each tasked to BREAK (not praise) one dimension, produce
falsifiable findings with file:line evidence + a reproduction, and attempt to REFUTE their own finding.
Everything below was reproduced against the real repo; fixes landed green-per-commit (`b3dca14`,
`fcb7821`, + this). This is a companion to `TRUST_MANIFEST.md` — the manifest states the trust tiers;
this states how hard they were attacked and what moved.

## What held under attack (could NOT be broken)
- **Axiom base is genuinely `{propext, Quot.sound, Classical.choice}`.** `#print axioms` on all 22
  headlines (independent of the analyzer) — no `sorryAx`/`native_decide`/`ofReduceBool`; zero real
  `axiom`/`unsafe` in the tree. The one `partial def` (`conformance/Runner.hexToBytes`) is exe-only,
  not in any headline closure.
- **The oracle→cost wall is TYPE-LEVEL, not a convention.** The per-op cost fold is `kappa : State →
  Metrics` — `crypto` is not in scope, so a cost metric is *type-incapable* of reading the secp256k1
  verdict. Every `stepMeterExt` correction reads only pre-state / `p` / covered-bytecode, never a
  verdict Bool. Every cost/limit headline is `∀ crypto`. This is the strongest part of the design.
- **`@[implemented_by magBytesImpl]`** (the one thing `#print axioms` can't see) is closed by a
  kernel-checked equivalence `magBytesImpl_eq` (`Number.lean:266`), axiom-clean.
- **Conformance is wired + passing** (3066/3066, 0 false-accepts on the sampled families) and the
  libauth cost differential is genuinely machine-generated + reproducible.
- **Optimizer capstones are non-vacuous** (fire on a concrete block, 6+2→8 verified on the real
  `stepInstr`), the acceptance-threading is a sound forward simulation (not circular), and
  `emit_ops_typed` is complete (no `True` escape; never-emitted ops map to `False`).

## Findings fixed
| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | HIGH | Necessity closure gate is **blind to a numeric-literal edit** — `maxMemorySlots`/`maxCtrlDepth`/… could be weakened 10000× with `necessity.json` byte-identical + build green. | `LeanBCH/Validation/VM/Limits.lean`: `by decide` pins on all six bare consensus limits (verified they bite). verify.sh header corrected: the closure gate is over the name-set, NOT literal values. |
| 2 | HIGH (latent) | Analyzer axioms **under-reported vs `#print axioms`** — `constDeps` skipped the `inductInfo→ctors` edge the kernel follows. | Added `++ v.ctors.toArray`; closure 2188→2195; still axiom-consistent. |
| 3 | MED | **3 sole-witness bare-print `#eval`s** asserted nothing (OP_RETURN classify; OP_TXINPUTCOUNT/OUTPUTCOUNT). | Converted to a throwing runtime `#eval` + two `by decide` KATs. |
| 4 | MED | `Epoch` docstring "nothing bakes a consensus literal" was **false**. | Corrected; documents the bare decoupled limits + their pins. |
| 5 | MED | KAT conservation gate is count-only; `#check` was a **padding vector**. | `katcount` no longer counts `#check`. (In-place tautologizing of an `example` remains an insider-only residual — see below.) |
| 6 | MED | Manifest/RESULTS **overclaims**: corpus "vendored" (it's an external path arg, not pinned/copied); sig op-cost tier "exercised end-to-end" (it NULLFAILs under the reject-oracle, so it's UNVALIDATED); C1 "real-VM capstones" (4/8 are on the abstract machine). | Reworded to state each precisely; a stale `VM.CostDifferential` path fixed. |

## Honest residual (accepted, documented — not defects)
- **KAT integrity vs an insider.** The conservation gate defends against *deletion* (count drop); it is
  structurally blind to *in-place* neutering of an `example` by someone editing the source. Real defense
  is code review + the closure gate; the count gate is not claimed to catch semantic gutting.
- **Signature op-cost tier is unvalidated** (soundness-safe — over-billing never wrong-accepts). Needs a
  live-secp256k1 differential to validate the `26000·sigChecks` numbers. Now stated plainly.
- **`verifyInput_cost_within_budget` is near-definitional** (it extracts `verifyInput`'s own budget
  conjunct); the deep content is in `runScript_fuel_suffices_final` + the Tier-2 differential. Honest.
- **push-only enforced on all unlocking scripts** — stricter than BCHN block-consensus (matches libauth's
  VM). Disclosed in-code; LeanBCH is not claimed proven-equivalent to BCHN.
- **Disclosed model gaps** (in-tree + RESULTS.md): strict-DER/pubkey-encoding gates owned by the oracle;
  Schnorr-multisig checkbits `.unimplemented`; deep code-separator-before-INVOKE edges; token-bitfield
  prefix rules lost at decode. The optimizer size-FLOOR headline's real-world reach depends on
  `MoveArrange`'s deferred obligations (stated as hypotheses, not `sorry`).

## Verdict
LeanBCH is **sound and honest for its stated scope**: a differential-validated executable model with a
kernel-proven self-hardening/cost core and a verified optimizer, with a single opaque oracle and a
libauth/vmb validation seam. The audit found no unsoundness — the real findings were *gates that
over-promised* and *docs that overclaimed*, both now corrected. It is ready for real-world use as a
formal reference/optimization toolkit (NOT as a drop-in consensus replacement for BCHN, which it never
claimed to be).
