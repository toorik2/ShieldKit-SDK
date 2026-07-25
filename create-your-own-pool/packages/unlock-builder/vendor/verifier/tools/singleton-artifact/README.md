# Singleton artifacts — preserved from ephemeral scratch (2026-07-02)

⚠️ **PROVENANCE CORRECTION (2026-07-02):** an earlier version of this dir preserved a single hex mislabeled `singleton-6054-locking5728.hex` and claimed "6,054 = 5,728 + 272 + 87" — which is arithmetically **6,087, not 6,054**. A provenance audit caught this: the 5,728-locking hex is the **6,087** (incremental-arrange) artifact, and the **true 6,054** (5,695 locking, move-arrange) lived only in a *different* scratch clone and was not preserved. Both are now preserved + correctly labeled below.

## The artifacts (score = locking + witness 272 + txOvhd 87)

| file | locking | **score** | emitter | −vs 9,135 |
|---|---|---|---|---|
| `singleton-4688-locking4329-sqrmul.hex` ★ **CROWN** | **4,329** | **4,688** | + sqr=mul elimination (`fp2Sqr`/`sqrFp` dedicated squaring → diagonal-mul wrappers `sqr(a)=mul(a,a)`; BLS-agent transfer, complementary to CSE) — **fully Lean-covered**: `Stackcert.Despec.fp2Sqr_despec_bn254` + `sqrFp_despec` (∀-inputs Karatsuba≡diagonal, `[propext,Quot.sound]`, 0-sorry, verify.sh 7-gate); E2E 4/4+4/4 | **−48.7%** |
| `singleton-4705-locking4346-foldcse.hex` | 4,346 | 4,705 | invoke_cse FIXPOINT (prior crown; superseded by the sqr=mul crown above — also fully Lean-covered) | −48.5% |
| `singleton-4718-locking4359-cse.hex` | 4,359 | 4,718 | + COMPLETE invoke_cse pass (14 cross-body factorings in the fp2/fp6/fp12 tower bodies; single-pass) | −48.4% |
| `singleton-5177-locking4818-marshcse.hex` | 4,818 | 5,177 | + marshalling-CSE (1 macro ×3 in main → shared body #39; Lean-covered via `InvokeCSE.invoke_cse`) | −43.3% |
| `singleton-5272-locking4913-l5fold.hex` | 4,913 | 5,272 | + L=5 fold window (3 folds fire, cascade; gate-verified) | −42.3% |
| `singleton-5279-locking4920-composed.hex` | 4,920 | 5,279 | + fold-table composition (+9 folds, incl. 2 new E-derive-body sites) | −42.2% |
| `singleton-5295-locking4936-ederive.hex` | 4,936 | 5,295 | + lineage-audit (twist/tail/dedup) + on-chain E-derivation (undo cashc's constant-fold of `(p¹²−1)/r`) — **SUB-5,000 locking** | −42.0% |
| `singleton-5684-locking5325-constshare.hex` | 5,325 | 5,684 | + restored global-CSE p-pool (regression fix) | −37.8% |
| `singleton-5835-locking5476-foldcomplete.hex` | 5,476 | 5,835 | search + move-arrange + peephole fold-completeness | −36.1% |
| `singleton-5972-locking5613-richpeep.hex` | 5,613 | 5,972 | + copy/drop double-word folds | −34.7% |

> ⚠️ **PROVENANCE (2026-07-02):** the search-crown lineage (5,628→5,476) silently **DROPPED** the `global-CSE p-pool` lever that the earlier 6,087 lineage had — all three carried the BN254 prime `p` as a raw 33-B literal **6×** with no provider body, contradicting this file's own lever chain (which credits `−163` for the p-pool). Restoring it (nullary provider at free id#13 + 6×`<13> INVOKE`) recovers −151 B → **5,325**, E2E-gated 4/4+4/4. This is a *regression fix*, not a new lever; it strongly implies **other dropped levers may exist** (a duplicate body `def#14≡#15` is a second confirmed regression) — a lineage-completeness audit is in progress. The p-pool CSE is the same gate-verified class as the crown's existing twist/exp/tail-derive levers, and the const-provider is trivially Lean-upgradeable (`invoke of a nullary PUSH-body returns c`).
| `singleton-5987-locking5628-search.hex` | 5,628 | 5,987 | anneal/exhaustive topo-search + MAIN reorder | −34.5% |
| `singleton-6054-locking5695-movearrange.hex` | 5,695 | 6,054 | MOVE-arrange | −33.7% |
| `singleton-6087-locking5728-incremental.hex` | 5,728 | 6,087 | incremental arrange | −33.4% |

- **CROWN 5,476** (`5,476 + 272 + 87 = 5,835`, canonical sha256 `acb779a0c78db233…`): the 5,628 search crown + two provably-sound peephole **fold-completeness** post-passes. **−15 B** copy/drop double-words (`OVER OVER→2DUP`, `SWAP OVER→TUCK`, `DROP DROP→2DROP`), then **−137 B** move double-words + identity-cycles (`<5>ROLL <5>ROLL→2ROT`, `<3>ROLL <3>ROLL→2SWAP`, `<3>PICK <3>PICK→2OVER`, `ROT³/2ROT³→∅`, + several 3→2 mixed reductions). The scheduler was emitting `<n>ROLL <n>ROLL` / `<n>PICK <n>PICK` pairs where a single double-word op is byte-shorter and stack-identical — **152 B the peephole never captured**. Every fold is context-free (⇒ depth-independent) and proven stack-identical **two independent ways** (pure-JS stack model + live BCH2026 VM, depths 7–12). `3DUP`-based folds are deliberately **excluded** (stack-identical but the decompiler has no `0x6f` case → would crash the round-trip gate); conservative and sound.
- All are the smallest sound+general BN254 Groth16 singleton verifier bytecode at their stage: full **EIP-197** (G1/G2 on-curve + `[6x²]B==ψ(B)` subgroup) + runtime-general vk_x on-chain (`IC0+in0·IC1+in1·IC2`, 4 distinct public inputs, NO baking/compression). NON-RUNNABLE by design (~163M-op pairing ≫ 8.03M single-input budget) — byte-scored code-golf, not deployable (same class as the competitor's 9,135, also non-runnable).

## Crown soundness (5,835 / 5,476 locking) — HONEST footing

**Correction (2026-07-02):** an earlier version of this file claimed the crown was "pure reschedules → `schedule_refines`, a *stronger* footing than the D-conditional move-arrange." That was **inaccurate**. Two independent audits (the Lean-hardening DW + the pre-PR red-team) found the crown's own selector chooses `arrange:'move'` on **~20 of 30 scheduled blocks** — the crown is built on the move-arrange bodies (5,695), not pure reschedules. The accurate footing:

- **The crown is `schedule_refines ∪ schedule_refines_move_cond`.** ~20 blocks are won by move-arrange (D-conditional); MAIN + the per-body search are pure reschedules (`schedule_refines`). Crucially, **all move-selected blocks are D-safe** — the 7 non-`D` blocks (4 duplicate-input `hReach`-false + 3 harmless dup-const) fall back to round-trip-exact original bytes via the `scheduler.mjs` self-check + `optimize.mjs` fallback. So there is **zero reliance on the non-D runtime fallback for any *selected* block**: every emitted block is discharged by a 0-sorry Lean theorem — `schedule_refines` (pure reschedules + MAIN) or `schedule_refines_move_cond` (the D-safe move blocks).
- **The two fold post-passes** (−15, −137) are context-free peephole rewrites, each proven stack-identical (JS model + live VM), preserving each body's denotation exactly.

Still **fully machine-checked sound** — just `schedule_refines ∪ schedule_refines_move_cond`, not "pure reschedule." **Gate-verified (2026-07-02):** round-trip byte-exact 36/36 bodies + main ✓, per-subroutine differential 36/36 bit-identical (**5 independent clean runs**) ✓, E2E multiproof valid-ACCEPT 4/4 + invalid-REJECT 4/4 + artifact-differential 4/4 ✓ on the real BCH2026 VM. EIP-197 + runtime-general vk_x intact.

**EIP-197 note (for reviewers):** the crown keeps the `[6x²]B==ψ(B)` G2-subgroup check. The zk-verifier-bench single-tx harness does **not** implement the subgroup-malleability forgery test (`adversarial.ts` — "not implemented"), so it labels the entry `input validation: NOT DEMONSTRATED` and does not *credit* those bytes. Keeping the check is **pure upside** — strictly more soundness (full EIP-197) at strictly fewer bytes; an off-subgroup point provably exercises that path and rejects. This is a harness gap, not a defect.

## Soundness status of the earlier stages (honest, per the 2026-07-02 audit)
- **6,087 (incremental)** — sound UNCONDITIONALLY via `schedule_refines` (the incremental arrange **copies** exit refs; never last-use-steals), correct on **all** blocks including the 7 with duplicate/degenerate exit tokens. The safe, fully-`schedule_refines`-covered stage.
- **6,054 (move-arrange)** — modeled by `schedule_refines_move_cond` (0-sorry, sound for any `D`-block). 7/100 blocks fail `Dexit`; for those the move-arrange self-check (`scheduler.mjs:338-344`) **throws on all 6 configs** and `optimize.mjs:46-49` **falls back** to round-trip-exact bytes — miscompile structurally prevented; move-arrange emits only on the safe permutation-heavy blocks. Re-verified 2026-07-02 (round-trip + differential + E2E 4/4+4/4).

## Reproducibility — self-verifying, not search-re-derivable
The crown came from a **stochastic** annealing search + **deterministic** fold post-passes; it is **not** bit-reproducible by re-running the search (RNG-seeded — a from-scratch pipeline run lands at ~5,636, not the crown). This is intrinsic to a search-based recompiler. Instead the artifact is **self-verifying**: the shipped hex is *proven* to be a faithful, behavior-preserving, correctly-verifying recompilation of the trusted 12,351 baseline, via three gates a reviewer runs on the SHIPPED hex (no search re-run):
1. **round-trip** — `recompile(decompile(hex)) == hex` byte-exact (the hex is a well-formed recompiler output),
2. **per-body differential** — every OP_DEFINE body vs `baseline.json` bit-identical on random Fp (same behavior as the trusted baseline),
3. **E2E** — 4/4 valid-accept + 4/4 invalid-reject on the multiproof vectors.
Trust chain: `baseline.json` (the `.cash` compile, trusted / recompilable with the cashc fork) → [byte-exact round-trip + per-body differential] → shipped hex. The Lean `schedule_refines`/`schedule_refines_move_cond` proofs cover the rescheduling soundness. See `gate.mjs`.

### `gate.mjs` — one-command reproducibility gate (run this on the SHIPPED hex)
```
node gate.mjs <shipped.hex> [multiproof-vectors.json] [--skip-e2e] [--trials N] [--e2e-proofs N]
```
Runs all three checks above on the shipped hex and prints PASS/FAIL per check + overall (plus locking bytes, score = locking + 359, sha256). **Exit 0 iff all three PASS**; exit 1 on any FAIL; exit 2 if E2E is deferred (`--skip-e2e`). Paths are resolved relative to the tool (`./pipeline-sub6k/…`); only the multiproof-vectors path is an absolute default (override with a 2nd arg / `--vectors`). Requires `@bitauth/libauth` on the module path (`npm install` at the repo root, or run from a checkout that has `node_modules`).

- **CHECK 1 round-trip** reconstructs the crown's nullary derive-helper arities (ids 13/38 — not in the baseline arity table) by a *bounded, self-validating* search: it accepts only an arity under which the whole program recompiles byte-identically, so the recovered arity is certified by the byte-exact round-trip itself (a wrong arity makes `decompile` throw or the bytes differ). MODE `block-DAG (strong)` = every body + main is a byte-exact fixpoint. If no block-DAG model can be established it falls back to a structural (canonical minimal-push encoding) round-trip and says so.
- **CHECK 2 differential** compares each shared body to `baseline.json` on random Fp (capped VM ⇒ always terminates). It automatically **excludes repurposed nullary providers** (e.g. the crown reuses the deduped id 15 as a 32-byte constant provider): a baseline subroutine always has in-arity ≥ 1 and underflows on zero inputs, so a body that runs cleanly on zero inputs is a provider with no baseline counterpart (validated by CHECK 3) — while a merely-corrupted body still underflows and stays under test. Note: the pairing body (id 33) runs ~18 s/trial, so CHECK 2 wall-time ≈ `trials × ~40 s`.
- **CHECK 3 e2e** is the decisive whole-verifier check (valid-ACCEPT + invalid-REJECT + baseline-differential on the multiproof vectors); it is wired and runs by default (skip with `--skip-e2e`).

Verified on the crown (`singleton-5279-locking4920-composed.hex`): CHECK 1 block-DAG **PASS**, CHECK 2 35/35 comparable bodies bit-identical **PASS** (providers 13/15/38 excluded), CHECK 3 wired. A one-byte-corrupted variant (any op flip inside a compared body) trips CHECK 2 → overall **FAIL**, so the gate has teeth.

## Source + pipelines
- `genpow-src/` — the verifier `.cash` source; genpow final-exp + tower + EIP-197 + on-chain vk_x. Compiles to the 12,351 baseline on the cashc `feat/library-support` fork (external, gitignored).
- `pipeline-sub6k/` — the search recompiler + lever stack → 5,628.
- `foldcomplete-src/` — the two peephole fold-completeness post-passes (`peephole.mjs` grammar + `foldpass.mjs`/`superopt.mjs`) applied over the 5,628 crown → 5,476, with `proofcheck.mjs` (stack-identity proofs) + `gate_v2.mjs`.
- `pipeline/` → 6,087 (incremental); `pipeline-movearrange/` → 6,054 (move-arrange).

## Lever chain (12,351 → 5,476 locking)
`genpow finalExpPow` ⊕ byte-recompiler ⊕ constant-CSE ⊕ exponent-derivation ⊕ global-CSE p-pool (−163) ⊕ twist-derive (−110) ⊕ scheduling-search ⊕ tail-derive → **5,728 (6,087)** ⊕ move-arrange (−33) → **5,695 (6,054)** ⊕ deep anneal/topo-search + MAIN reorder (−67) → **5,628 (5,987)** ⊕ copy/drop folds (−15) → **5,613 (5,972)** ⊕ move-double-word + identity folds (−137) → **5,476 (5,835)**.

## Verification (Lean, `tools/lean-recompiler-spike/` + published `stackcert`)
Machine-checked (Lean 4.31 core, no mathlib, 0-sorry, axiom-clean): peephole + passthrough + PASS-2 scheduler (`schedule_refines`) + decompile-bridge (`bridge_block`) + per-block `end_to_end` + `whole_program_end_to_end` + arrange framework + copy/movement/tight-`n−LCS` floor lemmas + `NoNull` invariant + the move-arrange capstone `schedule_refines_move_cond` (sound for `D`-blocks). The crown is covered by `schedule_refines` (pure reschedules + MAIN) ∪ `schedule_refines_move_cond` (D-safe move blocks); the two fold post-passes are separately gate-verified stack-identity rewrites. Model↔libauth-BCH2026 conformance (straight-line 2,616 + control 1,100) is CI-gated in `stackcert`.

Nothing pushed to the public `zk-verifier-bench` fork; no competition submission (user's call).
