// _dp_vs_greedy_minimal.mjs — measure the DP-optimal SELF-PINNED miller partition with the EXACT
// unified_fullverifier byte convention (minimal-accepting binary-search, self-pin present), so the
// comparison to the greedy 191,475 miller is apples-to-apples (same convention, same self-pin).
// Reads the DP cuts from bn254_faithful_plan_selfpin_report.json.
import { readFileSync } from 'node:fs';
import { writeFileSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026, binToHex } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

const N = ops.length;
const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = '/tmp/_dpmin_probe.cash';
const PLAN_SPK_BIN = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]);
const PLAN_SPK = binToHex(PLAN_SPK_BIN);
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc, PLAN_SPK).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

function evalCov(locking, unlocking, inCommit, outCommit) {
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: PLAN_SPK_BIN, valueSatoshis: 1000n, token: tok(outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, op: st.metrics.operationCost };
}
// minimal-accepting binary search, EXACTLY unified_fullverifier.measureChunk
function measureMinimal(lo, hi) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const inCommit = commitBin(covIn), outCommit = commitBin(outLimbs);
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const mk = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  const minU = argb.length + tail + 2;
  const hiProbe = evalCov(locking, mk(TARGET_UNLOCK), inCommit, outCommit);
  if (!hiProbe.accepted) return { feasible: false, opMax: hiProbe.op };
  let loU = minU, hiU = TARGET_UNLOCK;
  while (loU < hiU) { const mid = (loU + hiU) >> 1; const r = evalCov(locking, mk(mid), inCommit, outCommit); if (r.accepted) hiU = mid; else loU = mid + 1; }
  const target = hiU, r = evalCov(locking, mk(target), inCommit, outCommit);
  return { feasible: r.accepted, unlock: target, bytes: 35 + target, opAtMin: r.op, opMax: hiProbe.op, redeem: redeem.length };
}

const cuts = JSON.parse(readFileSync(process.argv[2], 'utf8')).plan.cuts;
console.log('DP cuts:', JSON.stringify(cuts), 'chunks', cuts.length - 1);
let total = 0, maxOpMax = 0;
const rows = [];
for (let i = 0; i + 1 < cuts.length; i++) {
  const lo = cuts[i], hi = cuts[i + 1];
  const m = measureMinimal(lo, hi);
  if (!m.feasible) { console.log(`[${lo},${hi}) INFEASIBLE opMax=${m.opMax}`); continue; }
  total += m.bytes; maxOpMax = Math.max(maxOpMax, m.opMax);
  rows.push({ lo, hi, w: hi - lo, bytes: m.bytes, unlock: m.unlock, opAtMin: m.opAtMin, opMax: m.opMax });
  console.log(`[${String(lo).padStart(3)},${String(hi).padStart(3)}) w=${String(hi - lo).padStart(2)} bytes=${String(m.bytes).padStart(5)} unlock=${String(m.unlock).padStart(5)} opMinPad=${String(m.opAtMin).padStart(9)} opMaxPad=${String(m.opMax).padStart(9)}`);
}
console.log(`\nDP-miller MINIMAL-ACCEPTING (self-pinned, unified convention) = ${total} B over ${rows.length} chunks`);
console.log(`greedy-miller (unified) = 191475 B over 21 chunks`);
console.log(`delta (DP - greedy) = ${total - 191475} B ; maxOpMaxPad = ${maxOpMax} (budget 8032800, slack ${8032800 - maxOpMax})`);
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_dp_vs_greedy_minimal_report.json', JSON.stringify({ cuts, dpMillerMinimalBytes: total, dpChunks: rows.length, greedyMillerBytes: 191475, greedyChunks: 21, delta: total - 191475, maxOpMaxPad: maxOpMax, rows }, null, 2));
