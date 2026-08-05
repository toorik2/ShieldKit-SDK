# Lean ↔ libauth conformance harness

Differential test that the **actual Lean `step` semantics** (`Recompiler/Basic.lean`, the 17
stack-manipulation opcodes) match the **real libauth BCH2026 VM**, on randomized stack states.
Closes the model↔VM gap: the hand-authored Lean opcode semantics are now *directly
differential-tested at scale*, not just cross-checked indirectly by the end-to-end gates.

## Result (2026-07-02, independently reproduced)
- **2616 cases, 0 mismatches, CONFORMANCE PASS.** All 17 ops (DUP DROP OVER SWAP ROT NIP TUCK
  PICK ROLL TOALT FROMALT 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP), incl. PICK/ROLL 0-index-from-top,
  out-of-range, and underflow (510 shared FAIL cases where Lean `none` ⇔ libauth abort).
- **Mutation test (non-vacuity):** `lean_eval_mut.lean` corrupts SWAP→no-op → the differ flags
  exactly the SWAP cases and nothing else ⇒ the harness has teeth.

## Scope
- Covers the 17 straight-line stack opcodes. `PUSH`-const is trivial; the abstract `CALL` DAG
  node is uninterpreted by design (out of scope). **Control opcodes (IF/ELSE/ENDIF/BEGIN/UNTIL)
  are NOT yet conformance-tested** — a natural follow-on.

## Run (needs libauth in node_modules; reuse a gate dir's, e.g. the recompiler pipeline)
```
node gen.mjs                                    # -> cases.json (deterministic, 2616 cases)
(cd ../ && lake env lean --run conformance/lean_eval.lean cases.json lean_results.json)
node libauth_eval.mjs                            # -> libauth_results.json (real BCH2026 vm.debug)
node diff.mjs                                    # -> per-op PASS/FAIL
node diff.mjs lean_results_mut.json              # mutation test: must FAIL on SWAP
```
Paths resolve relative to this dir (`CONF`); run Lean from the project root so `lake` sets LEAN_PATH.
