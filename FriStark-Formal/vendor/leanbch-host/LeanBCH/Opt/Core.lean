-- LeanBCH.Opt.Core — the reusable, value-generic (α-opaque) stack-VM proof CORE.
--
-- This umbrella re-exports every module that carries NO byte-level BCH wire
-- encoding and NO structured-control opcode semantics: the abstract stack-VM
-- model (run/denote, StepOk), the peephole/passthrough rewrite calculus, the
-- DAG scheduler + simulation refinement (`schedule_refines`), the move-arrange
-- rearrangement bridge (`schedule_refines_move_cond`), and the movement/floor
-- lower-bound subtree (`movement_lower_bound_nlcs`). A downstream project targets
-- its own VM by importing THIS module and instantiating the model.
--
-- RESIDUAL TARGET COUPLING (documented, deliberately not extracted): Basic's
-- concrete `Op` inductive + `step` semantics is BCH-shaped, but it is the shared
-- value-opaque VM MODEL every module transitively needs (Basic is the DAG root).
-- Extracting it would require parameterizing `step` over the op set — a deep
-- typeclass refactor touching every constructor-matching proof — so it stays in
-- Core, flagged here as the single Core-resident coupling a port would re-model.
-- See LeanBCH.Opt/MANIFEST.md for the full Core-vs-Target classification.
import LeanBCH.Opt.Basic
import LeanBCH.Opt.Peephole
import LeanBCH.Opt.FoldTable
import LeanBCH.Opt.Passthrough
import LeanBCH.Opt.Dag
import LeanBCH.Opt.Scheduler
import LeanBCH.Opt.Simulation
import LeanBCH.Opt.StepLemmas
import LeanBCH.Opt.Compose
import LeanBCH.Opt.MoveArrange
import LeanBCH.Opt.NoNullHome
import LeanBCH.Opt.Floor
import LeanBCH.Opt.MovementFloor
import LeanBCH.Opt.NlcsFloor
