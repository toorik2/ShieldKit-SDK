/-
  PASS-1 ALTSTACK PARK/RESTORE ELIMINATION — the real test (a rewrite with a PRECONDITION).

  cashc emits, per subroutine, a TOALT/FROMALT "park/restore" churn: entry-alt values are
  drained to main and later re-parked. The recompiler's PASS-1 passthrough recognises that
  when NO consumer reads a drained alt slot (`ain`) and the alt exits as the identity carry
  of its entry, the whole drain→…→repark bracket nets to the IDENTITY on the alt stack, so it
  can be DELETED (alt left physically untouched).

  The mathematical core of that optimisation — proven here for ALL inputs — is that
  `FROMALT^k` followed by `TOALT^k` (drain then repark, nothing consuming the values between)
  is the identity on state whenever the alt stack has ≥ k entries. This is the precondition
  ("no consumer reads {ain}") discharged as a theorem.
-/
import Recompiler.Basic

namespace Recompiler
open Op

/-- Draining `k` alt entries to main: the top-`k` of alt land reversed on top of main,
    the rest of alt remains. (top-of-alt becomes deepest of the moved block on main.) -/
theorem fromAltN_spec {α} (k : Nat) (m a : List α) (h : k ≤ a.length) :
    run (List.replicate k FROMALT) (m, a)
      = some ((a.take k).reverse ++ m, a.drop k) := by
  induction k generalizing m a with
  | zero => simp [run]
  | succ k ih =>
      cases a with
      | nil => simp at h
      | cons x a' =>
          have h' : k ≤ a'.length := by
            simp only [List.length_cons] at h; omega
          simp only [List.replicate, run, step]
          rw [ih (x :: m) a' h']
          simp [List.take_succ_cons, List.drop_succ_cons, List.reverse_cons,
                List.append_assoc]

/-- Re-parking: `TOALT^{|b|}` pops the top block `b` off main and lays it (reversed) on alt. -/
theorem toAltN_spec {α} (b m a : List α) :
    run (List.replicate b.length TOALT) (b ++ m, a)
      = some (m, b.reverse ++ a) := by
  induction b generalizing a with
  | nil => simp [run]
  | cons c b' ih =>
      simp only [List.length_cons, List.replicate, List.cons_append, run, step]
      rw [ih (c :: a)]
      simp [List.reverse_cons, List.append_assoc]

/-- ★ DRAIN–REPARK IS THE IDENTITY (PASS-1 passthrough core, ALL inputs).
    When the alt stack has ≥ k entries, `FROMALT^k ++ TOALT^k` leaves (main, alt) untouched,
    so the recompiler may DELETE the entire churn bracket. -/
theorem drain_repark_id {α} (k : Nat) (m a : List α) (h : k ≤ a.length) :
    run (List.replicate k FROMALT ++ List.replicate k TOALT) (m, a) = some (m, a) := by
  rw [run_append, fromAltN_spec k m a h]
  have hlen : ((a.take k).reverse).length = k := by
    rw [List.length_reverse, List.length_take]; omega
  simp only [Option.bind]
  have := toAltN_spec (a.take k).reverse m (a.drop k)
  rw [hlen] at this
  rw [this, List.reverse_reverse, List.take_append_drop]

/-- Stated as a `Correct` rewrite: the churn bracket ⇒ nothing, on the (physically realistic)
    class of states whose alt stack is deep enough for the drain. The recompiler establishes
    `k ≤ entryAlt` structurally at decompile time, so this precondition always holds where the
    pass fires. -/
theorem passthrough_correct {α} (k : Nat) :
    ∀ st : State α, k ≤ st.2.length →
      run (List.replicate k FROMALT ++ List.replicate k TOALT) st = run [] st := by
  intro ⟨m, a⟩ h
  simpa [run] using drain_repark_id k m a h

/-- Dual single-step sanity: park-one then restore-one is the identity on any state with a
    nonempty main (the everyday `TOALT FROMALT = id`). Underflow-honest: it is NOT valid on an
    empty main (TOALT aborts there while `[]` succeeds), so the nonempty precondition is real. -/
theorem park_restore_id {α} :
    ∀ st : State α, st.1 ≠ [] → run ([TOALT, FROMALT] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h; cases m with
  | nil => exact absurd rfl h
  | cons x s => rfl

end Recompiler
