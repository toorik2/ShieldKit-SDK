// cost.mjs — verifier.cash re-export of the LeanBCH op-cost measurement toolkit.
//
// C2 (TOOLKIT-BRIEF): cost.mjs physically lives in the LeanBCH repo
// (L/optimizer/cost.mjs). verifier.cash scripts used to reach it via a hard-coded
// absolute path pasted into every file. This module is the SINGLE point that knows
// where LeanBCH sits, so verifier.cash code imports it cleanly and cwd-independently:
//
//   import { measureRun, measureBody, classifyBound }
//     from '<V>/harness/src/harness/cost.mjs';
//
// The specifier below is the ABSOLUTE path to the pinned LeanBCH sibling repo. It is
// absolute (not relative) ON PURPOSE: verifier.cash build/measure work runs from
// floating git worktrees under scratchpad, so a relative `..`-chain out of this file
// would resolve against the worktree location, not the real Projects/ layout, and
// break. The two repos are pinned at fixed absolute roots (see reference-build-env),
// so this is the ONE place that hard-codes LeanBCH's location — every verifier.cash
// script now imports the in-repo wrapper instead of pasting this path. If LeanBCH is
// ever relocated, edit ONLY this line.
export {
  measureRun,      // (locking, unlocking?) -> { ok, error, opCost, arith, base, push, hashIters, sigChecks, instr, lockBytes, unlockBytes, bytes }
  measureBody,     // (dissection, arity, id, field?) -> per-subroutine op-cost at full-width inputs
  measureAllBodies,// (dissection, arity) -> { rows (sorted desc by opCost), total }
  classifyBound,   // (unlockBytes, opCost, padSlack?) -> { minUnlock, slack, bound, lever }
  decompose,       // (measureRun-result) -> { arithPct, basePct, pushPct }
} from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
