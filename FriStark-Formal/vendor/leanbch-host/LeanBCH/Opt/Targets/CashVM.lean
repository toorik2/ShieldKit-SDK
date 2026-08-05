-- LeanBCH.Opt.Targets.CashVM — the concrete BCH-2026 TARGET instantiation.
--
-- Pairs the generic LeanBCH.Opt.Core with the BCH-specific, REUSABLE leaves of the
-- module DAG. Nothing verifier-specific lives here — BN254/BLS/circuit work belongs in
-- the application (verifier.cash), which `require`s LeanBCH and imports this.
--   • LeanBCH.Opt.Decompile — byte-level wire ENCODING (opcode <-> byte 0x76..,
--     parse, <n> OP_PICK folding) + the decompile bridge theorem.
--   • LeanBCH.Opt.Control   — structured control (IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL/
--     VERIFY) with libauth BCH-2026 branch semantics (incl. the OP_NOTIF-on-falsy
--     fidelity fix) + `whole_program_end_to_end`.
--   • LeanBCH.Opt.Providers — const-provider (global-CSE) soundness: `invoke_const_provider`
--     (invoke of a nullary PUSH-body returns c) — reusable by ANY verifier.
--   • LeanBCH.Opt.InvokeCSE — OP_INVOKE stack-transparency (`invoke_transparent`/`invoke_cse`):
--     factoring a repeated op-subsequence into a shared invoke body preserves execution.
-- See LeanBCH/Opt/MANIFEST.md.
import LeanBCH.Opt.Core
import LeanBCH.Opt.Decompile
import LeanBCH.Opt.Control
import LeanBCH.Opt.Providers
import LeanBCH.Opt.InvokeCSE
import LeanBCH.Opt.Adapter
import LeanBCH.Opt.Codec
import LeanBCH.Opt.OpFaithful
import LeanBCH.Opt.CondBridge
import LeanBCH.Opt.ComputeBridge
import LeanBCH.Opt.AcceptBridge
import LeanBCH.Opt.AcceptExample
import LeanBCH.Opt.EmitBridge
