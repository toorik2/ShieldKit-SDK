// cost.mjs — op-cost measurement + bound-type classification (the floor metric).
//
// On the BCH-2026 VM the on-chain byte cost of a heavy script is set by its OP-COST, not its
// code size: an op-cost-bound input pads its unlocking to buy budget, so bytes ≈ op-cost / 800.
// So "lower the floor" == "lower executed op-cost" for the op-pad-bound mass. This module runs a
// program on the loosened VM (all ceilings lifted, so even an oversized verifier evaluates) and
// reports the five consensus metrics + a bound-type classification.
//
// Uses the SAME loosened VM the optimizer's gates use (core/program.mjs), so measurements are
// consistent with the round-trip / differential harness.
import { looseVm, makeLooseVm, runSubroutine } from './core/program.mjs';
import { createTestAuthenticationProgramBch, hexToBin } from '@bitauth/libauth';

const OP_COST_PER_BYTE = 800;                 // BCH-2026 density: 1 byte buys 800 op-cost of budget
const P_BN254 = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const MEASURE_CAP = 400_000_000;              // op-cost cap for per-body measurement (>4x a chunk's
                                              // budget) so a full-width final-exp/inverse errors fast
const boundedVm = makeLooseVm(MEASURE_CAP);
const toBin = (x) => (typeof x === 'string' ? hexToBin(x.trim()) : x);
const metricsOf = (m = {}) => {
  const instr = m.evaluatedInstructionCount ?? 0;
  return { opCost: m.operationCost ?? 0, arith: m.arithmeticCost ?? 0, base: instr * 100,
           push: m.stackPushedBytes ?? 0, hashIters: m.hashDigestIterations ?? 0,
           sigChecks: m.signatureCheckCount ?? 0, instr };
};

/** Run ONE subroutine in isolation with FULL-WIDTH field inputs and read its op-cost. This is the
 *  context-free, optimization-relevant metric: modmul op-cost depends on operand width, so we feed
 *  near-P values (not tiny probe values). Whole-verifier op-cost needs the tx/covenant context and
 *  is not re-measurable here — for a deployed chunk, trust the harness-provided operationCost. */
export function measureBody(d, arity, id, field = P_BN254) {
  const a = arity[id]; if (!a) throw new Error(`no arity for id ${id}`);
  const inputs = Array.from({ length: a.in }, (_, i) => (field - BigInt(1 + i * 7)));  // distinct full-width
  const r = runSubroutine(d, id, inputs, undefined, boundedVm);   // bounded so it can't hang
  const capped = r.error && /operation cost|maximum operation/i.test(String(r.error));
  return { id, ...metricsOf(r.metrics), inArity: a.in, outArity: a.out, capped: !!capped,
           error: r.error && !capped ? String(r.error) : undefined };
}

/** Per-body op-cost table for a whole dissected program — shows WHERE the op-cost mass is. */
export function measureAllBodies(d, arity) {
  const rows = d.order.map((id) => measureBody(d, arity, id));
  const total = rows.reduce((s, r) => s + r.opCost, 0);
  return { rows: rows.sort((a, b) => b.opCost - a.opCost), total };
}

/** Run `locking` (optionally with `unlocking` witness) on the loosened VM and read its metrics.
 *  Returns { ok, error, opCost, arith, base, push, hashIters, sigChecks, instr, lockBytes,
 *  unlockBytes, bytes }. `base` = evaluatedInstructionCount * 100 (the base-cost term). */
export function measureRun(locking, unlocking = new Uint8Array()) {
  const lb = toBin(locking), ub = toBin(unlocking);
  const state = looseVm.evaluate(createTestAuthenticationProgramBch({
    lockingBytecode: lb, unlockingBytecode: ub, valueSatoshis: 1000n,
  }));
  const m = state.metrics || {};
  const instr = m.evaluatedInstructionCount ?? 0;
  return {
    ok: !state.error,
    error: state.error ? String(state.error) : undefined,
    opCost: m.operationCost ?? 0,
    arith: m.arithmeticCost ?? 0,
    base: instr * 100,
    push: m.stackPushedBytes ?? 0,
    hashIters: m.hashDigestIterations ?? 0,
    sigChecks: m.signatureCheckCount ?? 0,
    instr,
    lockBytes: lb.length,
    unlockBytes: ub.length,
    bytes: lb.length + ub.length,
  };
}

/** Classify how a chunk's on-chain bytes are bounded, given its unlocking size + op-cost.
 *  op-pad-bound: unlocking ≈ ceil(opCost/800) (a small +slack) ⇒ op-cost sets the bytes, so an
 *  op-cost cut pays ~1:1 in bytes. code/witness-bound: unlocking exceeds the op-pad by a real
 *  margin ⇒ the bytes are set by code/witness size, so byte-golf (fold/cse) pays there instead. */
export function classifyBound(unlockBytes, opCost, padSlack = 250) {
  // budget = (41 + ulen)*800 must cover opCost ⇒ minimum unlock to buy the budget = ceil(op/800) - 41.
  const minUnlock = Math.max(0, Math.ceil(opCost / OP_COST_PER_BYTE) - 41);
  const over = unlockBytes - minUnlock;              // how far above the op-cost minimum this chunk sits
  const opPadBound = over >= -2 && over <= padSlack;  // unlock ≈ the op-cost minimum ⇒ op-cost sets bytes
  return {
    minUnlock,
    slack: over,
    bound: opPadBound ? 'op-pad' : (over > padSlack ? 'code/witness' : 'under-budget'),
    // the lever that pays for THIS chunk:
    lever: opPadBound
      ? 'op-cost (move-arrange / fewer-cheaper ops — cuts pay ~1:1 in bytes here)'
      : (over > padSlack ? 'bytes (fold/cse — the unlocking is code/witness-bound, not op-pad)' : 'n/a (under budget)'),
  };
}

/** Decompose an op-cost into % arith / % base / % push (the A2 attribution). */
export function decompose(r) {
  const t = r.opCost || 1;
  return { arithPct: +(100 * r.arith / t).toFixed(1), basePct: +(100 * r.base / t).toFixed(1), pushPct: +(100 * r.push / t).toFixed(1) };
}
