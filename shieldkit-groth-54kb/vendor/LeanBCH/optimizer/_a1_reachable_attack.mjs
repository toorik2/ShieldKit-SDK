// _a1_reachable_attack.mjs — probe REACHABLE worst-case op.
// A covenant-reachable boundary state limb may be an UNREDUCED lazy value  v + m*p  (== committed mod p,
// but wider). This tests whether such a maximally-unreduced reachable input busts the op budget on a
// tool-FEASIBLE chunk. It also scans every boundary state for the max limb byte-width (the reachability
// bound the tool implicitly relies on).
import { genChunk, inState, outState, states } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';
import { writeFileSync } from 'node:fs';

const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
const bytelen = (v) => { let h = (v < 0n ? -v : v).toString(16); if (h.length % 2) h = '0' + h; return h.length / 2; };

// ---- boundary-state reachability scan: max limb byte-width over ALL committed boundary states ----
let maxLimbBytes = 0, maxLoc = null, hist = {};
for (let cut = 0; cut < states.length; cut++) {
  const limbs = inState(cut).map(BigInt);
  for (let i = 0; i < limbs.length; i++) { const b = bytelen(limbs[i]); hist[b] = (hist[b] || 0) + 1; if (b > maxLimbBytes) { maxLimbBytes = b; maxLoc = [cut, i]; } }
}
console.log('boundary-state limb byte-width histogram:', JSON.stringify(hist), ' max=', maxLimbBytes, '@', JSON.stringify(maxLoc));

// ---- reachable-width attack on tool-feasible chunk [52,71) ----
const [lo, hi] = [52, 71];
const committed = inState(lo).map(BigInt);
const n = committed.length;

function measure(customIn) {
  const PROBE = '/tmp/_a1_reach_probe.cash';
  writeFileSync(PROBE, gen(lo, hi, false, false));
  const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = customIn.map(BigInt), outLimbs = outState(hi).map(BigInt);
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const inCommit = commitBin(inLimbs), outCommit = commitBin(outLimbs);
  const room = TARGET_UNLOCK - argb.length - tail;
  const target = room >= 2 ? TARGET_UNLOCK : (argb.length + tail + 2);
  const mk = Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: mk }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { op: st.metrics.operationCost, completed: st.error === undefined,
           accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1,
           argBytes: argb.length, error: st.error ? String(st.error).slice(0, 80) : null };
}

const out = { chunk: [lo, hi], opBudget: OP_BUDGET, maxBoundaryLimbBytes: maxLimbBytes, results: [] };
// committed + m*p : same value mod p (reachable as an unreduced lazy boundary state), increasingly wide.
for (const m of [0n, 1n, 2n, 3n, 4n]) {
  const v = committed.map((c) => c + m * P);
  const r = measure(v);
  r.name = `committed + ${m}*p`;
  r.limbBytesSample = bytelen(v[0]);
  r.overBudget = r.op > OP_BUDGET;
  out.results.push(r);
  console.log(JSON.stringify(r));
}
out.committedOp = out.results[0].op;
out.busters = out.results.filter((r) => r.overBudget && r.completed);   // must COMPLETE to be a real bust
out.bustersAnyCompletion = out.results.filter((r) => r.overBudget);
out.A1_BUSTED_reachable_completing = out.busters.length > 0;
console.log('\ncommitted op =', out.committedOp, ' budget =', OP_BUDGET);
console.log('reachable (committed+m*p) over-budget AND completing:', JSON.stringify(out.busters.map((b) => ({ name: b.name, op: b.op }))));
console.log('reachable over-budget (any completion):', JSON.stringify(out.bustersAnyCompletion.map((b) => ({ name: b.name, op: b.op, completed: b.completed, err: b.error }))));
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_a1_reachable_attack_report.json', JSON.stringify(out, null, 2));
