// _a1_magnitude_attack.mjs — ADVERSARIAL a1-undercount probe.
// The fixed tool's REAL gate is measureDeployed(lo,hi).op10000 at the COMMITTED instance. Its A1
// soundness rests on the claim "miller op is magnitude-INDEPENDENT, so the committed instance IS the
// worst case." This probe ATTACKS that: for a tool-FEASIBLE chunk, it re-measures op10000 with the
// input state limbs replaced by adversarial "all-bits-set" magnitudes (p-1, 2^256-1, and over-wide),
// with a MATCHING input-commitment so the full miller schedule executes. If any run's real op exceeds
// OP_BUDGET while the committed run is under, the tool would emit an A1-UNSOUND chunk.
import { writeFileSync } from 'node:fs';
import { genChunk, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

const N = inState.length ? 0 : 0; // placeholder (N via ops handled below)
const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

// Build ctx for [lo,hi) but with a CUSTOM input-limb vector (overrides the committed inState(lo)).
// covIn commitment is set to commitBin(customIn) so the contract's input-commitment require PASSES and
// the full miller schedule runs on the adversarial magnitudes. Output token = committed outState (its
// commitment will mismatch at the very end, but op is fully accrued by then).
function buildCtxCustom(lo, hi, customIn) {
  const isFinal = false, reloc = lo === 0;
  const PROBE = '/tmp/_a1_mag_probe.cash';
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = customIn.map(BigInt);
  const outLimbs = outState(hi).map(BigInt);
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const inCommit = commitBin(inLimbs), outCommit = commitBin(outLimbs);
  const mk = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  return { redeem: redeem.length, tail, argBytes: argb.length, locking, inCommit, outCommit, mk };
}
function evalAt(ctx, target) {
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.inCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: ctx.mk(target) }],
      outputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1,
           op: st.metrics.operationCost, completed: st.error === undefined, error: st.error ? String(st.error).slice(0, 90) : null };
}

// measure op at max pad (worst-case pad) for a given input-limb vector
function measureOp(lo, hi, customIn) {
  const ctx = buildCtxCustom(lo, hi, customIn);
  // pad room: argb+tail must leave >=2 for pad at TARGET_UNLOCK
  const room = TARGET_UNLOCK - ctx.argBytes - ctx.tail;
  const target = room >= 2 ? TARGET_UNLOCK : (ctx.argBytes + ctx.tail + 2);
  const r = evalAt(ctx, target);
  return { op: r.op, completed: r.completed, accepted: r.accepted, error: r.error, argBytes: ctx.argBytes, tail: ctx.tail, padTarget: target };
}

const CHUNK = [52, 71];
const [lo, hi] = CHUNK;
const committed = inState(lo).map(BigInt);
const n = committed.length;

// adversarial input vectors, all length n:
const vecs = {
  committed,
  'p_minus_1 (all-bits-set in-field)': committed.map(() => P - 1n),
  'two256_minus_1 (32B 0xFF, over-field)': committed.map(() => (1n << 256n) - 1n),
  'two312_minus_1 (39B over-wide)': committed.map(() => (1n << 312n) - 1n),
  'two319 (40B, max toPaddedBytes width)': committed.map(() => (1n << 319n)),
  // mixed: keep points (indices 18..27) committed-valid but blow up f/R0/c/cInv to p-1
  'field_pminus1_points_committed': committed.map((v, i) => (i >= 18 && i < 28) ? v : (P - 1n)),
};

const out = { chunk: CHUNK, opBudget: OP_BUDGET, committedOp: null, results: [] };
for (const [name, v] of Object.entries(vecs)) {
  let row;
  try { row = { name, ...measureOp(lo, hi, v) }; }
  catch (e) { row = { name, error: 'THROW: ' + String(e?.message ?? e).slice(0, 120) }; }
  if (name === 'committed') out.committedOp = row.op;
  row.overBudget = Number.isFinite(row.op) ? row.op > OP_BUDGET : null;
  row.deltaVsCommitted = (Number.isFinite(row.op) && out.committedOp != null) ? row.op - out.committedOp : null;
  out.results.push(row);
  console.log(JSON.stringify(row));
}
// A1-undercount verdict: any input vector whose op > OP_BUDGET while committed op <= OP_BUDGET
const committedFeasible = out.committedOp <= OP_BUDGET;
const busters = out.results.filter((r) => r.overBudget === true);
out.committedFeasible = committedFeasible;
out.A1_BUSTED = committedFeasible && busters.length > 0;
out.busters = busters.map((b) => ({ name: b.name, op: b.op, over: b.op - OP_BUDGET }));
console.log('\n=== A1 magnitude attack on chunk [' + lo + ',' + hi + ') ===');
console.log('committed op10000 =', out.committedOp, ' (<= budget:', committedFeasible, ')  budget =', OP_BUDGET);
console.log('A1_BUSTED =', out.A1_BUSTED, ' busters:', JSON.stringify(out.busters));
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_a1_magnitude_attack_report.json', JSON.stringify(out, null, 2));
