-- LeanBCH.Opt — a verified size-optimizing recompiler for BCH-2026 stack bytecode.
--
-- A separate build target from the LeanBCH VM (the core stays fast; this drags the
-- 8,890-line generated FoldTable). Organized along a CORE ⟂ TARGET seam:
--   • LeanBCH.Opt.Core           — reusable α-generic stack-VM proof framework
--     (schedule_refines, the window-complete fold table, the movement/floor lower bounds).
--   • LeanBCH.Opt.Targets.CashVM — the concrete BCH-2026 instantiation (decompile bridge,
--     structured control, INVOKE/const-provider soundness).
--   • LeanBCH.Opt.Adapter / OpFaithful / CondBridge / ComputeBridge / AcceptBridge / EmitBridge —
--     the bridge grounding the optimizer in LeanBCH's proven `stepInstr`. The SEMANTIC bridge is
--     CLOSED: `OpFaithful` proves per-op faithfulness for the WHOLE compute surface (shuffles +
--     PUSH/PICK/ROLL + arith/unary/comparison/hash) against the real VM — compute ops CONDITIONAL on
--     their operands being canonical numbers (`stepInstr` is partial where the abstract machine is
--     total). `AcceptBridge` discharges that precondition by ACCEPTANCE (a clean run ⟹ every op's
--     precondition held; `rewrite_sound_accept`), and `EmitBridge.emit_sound_under_VM` composes it
--     with `schedule_refines`: the scheduler's `emit b` bytes, run clean on the real VM, compute
--     exactly `denote b`. `AcceptExample` witnesses the full chain on a real rewrite (`[SWAP,ADD]⇒
--     [ADD]`). All parameterized by an encoder `enc` + its per-op faithfulness (the compute table
--     supplies these).
--   • LeanBCH.Opt.EmitConcrete — increment 4d: a CONCRETE `enc` (opcode identity by PROBING the
--     opaque `Op.CALL` semantics — apply it to canonical operands and read the opcode off the result)
--     that makes `emit_sound_under_VM` FIRE on genuine scheduler output (`emit_bA_sound`: the whole
--     arith class incl. partial div/mod; `emit_bDup_sound`: a reuse block with a real OP_DUP).
--   • LeanBCH.Opt.DecompileWF — discharges `decompileBlock ⟹ WellFormed` (6/7 conjuncts unconditional;
--     the 7th, semArity, under a minimal `OpUniform` premise), making `bridge_block`/`end_to_end`
--     premise-free: `decompile_end_to_end` proves `run(emit b) = run(rawOps)` from just "it decompiled".
--     So abstract "optimized = original" is CLOSED; the real-VM capstone chains it with EmitConcrete.
--   • LeanBCH.Opt.EmitTyped — `emit_ops_typed`/`emit_op_cases`: EVERY op the scheduler emits for ANY
--     block is a shuffle | PICK/ROLL | PUSH-of-a-block-const | CALL-from-a-node (block-generality axis
--     CLOSED; `[propext, Quot.sound]`, cleaner than baseline).
--   • LeanBCH.Opt.EmitConcreteExt — `encFull`: ONE probe-based encoder covering arith + MIN/MAX + the
--     8 comparisons + unary-numeric + unary-bool, with per-class real-VM witnesses (class-coverage
--     axis; HASH deferred — probing it forces the kernel to compute SHA-256, and native_decide is
--     forbidden).
--   • LeanBCH.Opt.PushButtonBytes — `push_button_arith_bytes`: the arith capstone at the BYTE level —
--     the optimizer's actual emitted BYTECODE, parsed and run on the real `VM.run`, ≡ the original
--     program (via `Codec.parse_encode` ∘ `run_straightline` ∘ `emit_bA_sound`).
--   OPEN: assemble the fully-general byte-level push-button (glue: `rcases emit_op_cases` + per-shape
--     faithfulness over arbitrary `b`, + a `const-encodable` side-condition); the HASH probe; and
--     original-BYTECODE (byte-level parse of the raw program) decode faithfulness.
-- See LeanBCH/Opt/MANIFEST.md.
import LeanBCH.Opt.Targets.CashVM
import LeanBCH.Opt.EmitConcrete
import LeanBCH.Opt.EmitConcreteExt
import LeanBCH.Opt.EmitConcreteHash
import LeanBCH.Opt.DecompileWF
import LeanBCH.Opt.PushButton
import LeanBCH.Opt.EmitTyped
import LeanBCH.Opt.PushButtonBytes
import LeanBCH.Opt.PushButtonFull
import LeanBCH.Opt.OriginalBytes
-- The OP-COST FLOOR-PROVER (additive; see Opt/OpCostFloor_SCOPE.md). Machine-checked LOWER BOUNDS on
-- the op-cost of computing a fixed function on the BCH-2026 VM, so "this op is at-floor" is a KERNEL
-- theorem, not an agent's non-existence claim. Piece A (per-OP_MUL cost), Piece B (Fp2 bilinear rank),
-- Piece C (composition into an Fp2 op-cost floor), + the value-producing movement floor (extends
-- NlcsFloor from a permutation-only to a computing body).
import LeanBCH.Opt.OpMulFloor
import LeanBCH.Opt.BilinearRankFloor
import LeanBCH.Opt.Fp12OpCostFloor
import LeanBCH.Opt.MovementFloorDag
-- Tower extension of the op-cost floor-prover (additive; see Opt/OpCostFloor_SCOPE.md). Target A:
-- Fp12/Fp6 degree-2 rank ≥ 3 (DegreeExtRank). Target B: Fp6/Fp2 degree-3 de-Groote rank ≥ 5
-- (Fp6RankFloor). Target C: the parametric tower-model composition (#Fp-mults ≥ r12·r6·r2)
-- (TowerRankCompose). Fp12TowerFloor: composes the three proven ranks (3,5,3) into the fp12Mul
-- essential-Fp-mult floor (≥45) + op-cost floor (≥50580 @ BCH_2026_05, k=32).
import LeanBCH.Opt.DegreeExtRank
import LeanBCH.Opt.Fp6RankFloor
import LeanBCH.Opt.TowerRankCompose
import LeanBCH.Opt.Fp12TowerFloor
-- BLS12-381 (k=48) instantiation of the same 2-3-2 tower floor.  Keep this in the
-- optimizer barrel so it is built by the normal LeanBCHOpt target and not a dead side file.
import LeanBCH.Opt.Fp12TowerFloorBLS
