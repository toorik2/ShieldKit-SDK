/-
  Const-provider soundness (global-CSE) — BN254 crown.

  The crown shrinks by sharing repeated constants behind nullary subroutine "providers":
  the global-CSE p-pool (def#13 = a body that pushes the 32-byte prime p, INVOKE'd 6×
  instead of 6 inline literals, −151 B) and the twist/tail providers. Each replaces an
  inline `PUSH c` with an INVOKE of a body whose sole effect is to push c.

  `INVOKE` of a value-body is modeled (Dag/Decompile) as `CALL nin sem`; a nullary
  PUSH-provider is `CALL 0 (fun _ => [c])`. Soundness = "invoking the provider is
  behavior-identical to the inline push," for every stack — proven polymorphically here,
  so it covers ALL const-providers (any α, any c) at once and composes via `Correct.congr`.
-/
import LeanBCH.Opt.Basic

namespace LeanBCH.Opt.Providers
open LeanBCH.Opt LeanBCH.Opt.Op
set_option linter.unusedSimpArgs false

/-- A nullary CONST-PROVIDER: a subroutine body whose only effect is to push the fixed
    constant `c`, as the decompiler models its INVOKE (`CALL 0 (fun _ => [c])`). -/
def provider {α : Type} (c : α) : Op α := CALL 0 (fun _ => [c])

/-- **Const-provider soundness (the global-CSE lever)**: replacing an inline `PUSH c` with
    an invoke of the provider preserves behavior on ANY stack — "invoke of a nullary
    PUSH-body returns c." Polymorphic over `α` and `c`, so a single theorem discharges the
    crown's p-pool (c = p, ×6), twist and tail providers. Via `Correct.congr` it splices in
    anywhere, exactly like a fold or the E-derivation rewrite. -/
theorem invoke_const_provider {α : Type} (c : α) :
    Correct ([PUSH c] : List (Op α)) [provider c] := by
  intro ⟨s, a⟩
  simp [run, step, provider, List.take_zero, List.drop_zero, Nat.zero_le]

end LeanBCH.Opt.Providers
