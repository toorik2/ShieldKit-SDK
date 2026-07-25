// TRUE whole-verifier byte total with the FULL V3 libraries — SELF-CONTAINED re-chunk + measure.
// Re-chunks the c^-(6x+2)-fused residue Miller loop under the SAME deployed byte-counter that
// produced 274,607 (build_vectors.mjs::buildCovStep: P2SH redeem-in-scriptSig + state-arg pushes
// + tuned zero pad, RESCHEDULED cashc compile) used AS the planning fitness oracle, so the chunk
// windows respect the real 10,000-B unlocking limit AND the op ceiling. Carries the non-Miller
// chunks (g2check/vk_x/residue-tail) at their exact deployed byte counts from /tmp/rv.json.
// The lib the Miller chunks import is chosen by env LIB_IMPORT (V3 vs deployed-eager).
//   LIB_IMPORT='../variants/V3_millerres_lib.cash' node v3_fullverifier.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET,
} from './_millermath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import {
  binToHex, bigIntToVmNumber, hash256,
  encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_v3full.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const MODE = process.env.LIB_IMPORT?.includes('V3') ? 'V3' : 'EAGER';

// ---- buildCovStep byte-counter, copied byte-for-byte from build_vectors.mjs -----------------
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL (35 B)
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
// measure a window [lo,hi): write genChunk src to a probe .cash (so its relative lib import
// resolves), rescheduled-compile it as the P2SH redeem, drive the covenant tx, tune the pad.
function measureWindow(lo, hi) {
  const isFinal = hi === ops.length;
  const src = genChunk(lo, hi, isFinal);
  writeFileSync(PROBE, src);
  let contract;
  try { contract = compileFileBytecode(PROBE); }
  catch (e) { return { fits: false, error: String(e?.message ?? e), unlockingBytes: Infinity, operationCost: Infinity, accepted: false }; }
  const redeem = Uint8Array.from([...contract]);
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const inCommit = commitBin(inLimbs), outCommit = commitBin(outLimbs);
  // covIn checks the incoming state; the unlocking pushes exactly the committed incoming limbs (decl order, reversed)
  const pushArgs = inLimbs;
  const argb = Uint8Array.from([...pushArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const mkUnlock = (target) => { const pad = padBytes(target - argb.length - tail); return Uint8Array.from([...pad, ...argb, ...rpush]); };
  // DEPLOYED-EXACT tight tuning: minimal accepting unlocking length. Acceptance is monotonic in
  // the pad (each pad byte adds +1 op-cost but +800 to the (41+ulen)*800 budget), so binary-search
  // the smallest length that still accepts (== ceil(op/800)-41 for op-pad-bound chunks, == the
  // redeem+args floor for witness-bound chunks) — the identical convention the deployed 274,607 uses.
  const minU = argb.length + tail + 2;
  const hiUnlock = mkUnlock(TARGET_UNLOCK);
  const topProbe = evalCov(locking, hiUnlock, inCommit, outCommit);
  let target, real;
  if (!topProbe.accepted || hiUnlock.length > TARGET_UNLOCK) { target = TARGET_UNLOCK; real = topProbe; }
  else {
    let loU = minU, hiU = TARGET_UNLOCK;
    while (loU < hiU) { const mid = (loU + hiU) >> 1; const r = evalCov(locking, mkUnlock(mid), inCommit, outCommit); if (r.accepted) hiU = mid; else loU = mid + 1; }
    target = hiU; real = evalCov(locking, mkUnlock(target), inCommit, outCommit);
  }
  let unlocking = mkUnlock(target);
  const fits = real.accepted && unlocking.length <= TARGET_UNLOCK && real.operationCost <= OP_TARGET;
  return { fits, lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost, accepted: real.accepted, inCommit: binToHex(inCommit), outCommit: binToHex(outCommit), src };
}

// ---- greedy re-chunk: grow the window while it fits the deployed constraint --------------------
console.log(`MODE=${MODE}  LIB=${process.env.LIB_IMPORT ?? '(eager default)'}  OP_TARGET=${OP_TARGET.toLocaleString()}  ops=${ops.length}`);
const chunks = [];
let lo = 0;
let prevWidth = null;
while (lo < ops.length) {
  // seed guess from previous chunk width, then grow/shrink to the largest fitting boundary
  let last = null;
  const guess = Math.min(ops.length, prevWidth ? lo + prevWidth : lo + 1);
  const gm = measureWindow(lo, guess);
  if (gm.fits) {
    last = { hi: guess, ...gm };
    for (let hi = guess + 1; hi <= ops.length; hi++) { const mm = measureWindow(lo, hi); if (mm.fits) last = { hi, ...mm }; else break; }
  } else {
    for (let hi = guess - 1; hi > lo; hi--) { const mm = measureWindow(lo, hi); if (mm.fits) { last = { hi, ...mm }; break; } }
  }
  if (!last) {
    const m = measureWindow(lo, lo + 1);
    throw new Error(`op ${lo} single-op window infeasible: unlock=${m.unlockingBytes} op=${m.operationCost} err=${m.error ?? ''}`);
  }
  prevWidth = last.hi - lo;
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), last.src);
  chunks.push({ idx, opLo: lo, opHi: last.hi, lockingBytes: last.lockingBytes, unlockingBytes: last.unlockingBytes, operationCost: last.operationCost, accepted: last.accepted, inCommit: last.inCommit, outCommit: last.outCommit });
  console.log(`chunk ${String(idx).padStart(2)}: ops[${String(lo).padStart(3)},${String(last.hi).padStart(3)}) lock=${last.lockingBytes} unlock=${String(last.unlockingBytes).padStart(5)} op=${String(last.operationCost).padStart(9)} acc=${last.accepted ? 'Y' : 'N'}`);
  lo = last.hi;
}

// ---- chain continuity + seams vs deployed -----------------------------------------------------
let chainOk = true, allAcc = true;
for (let i = 0; i < chunks.length; i++) {
  allAcc = allAcc && chunks[i].accepted;
  if (i > 0 && chunks[i - 1].outCommit !== chunks[i].inCommit) chainOk = false;
}
const rv = JSON.parse(readFileSync('/tmp/rv.json', 'utf8'));
const dep = rv.steps;
const sumB = (a, b) => { let s = 0; for (let i = a; i <= b; i++) s += dep[i].lockingBytes + dep[i].unlockingBytes; return s; };
const CARRIED_G2 = sumB(0, 3), CARRIED_VKX = sumB(4, 11), CARRIED_TAIL = sumB(35, 35);
const CARRIED_NONMILLER = CARRIED_G2 + CARRIED_VKX + CARRIED_TAIL;
const startSeam = chunks[0].inCommit === dep[12].covenant.inCommitment;
const endSeam = chunks[chunks.length - 1].outCommit === dep[35].covenant.inCommitment;
let depChainOk = true;
for (let i = 1; i <= 35; i++) if (dep[i - 1].covenant.outCommitment !== dep[i].covenant.inCommitment) depChainOk = false;

const tLock = chunks.reduce((s, c) => s + c.lockingBytes, 0);
const tUnlock = chunks.reduce((s, c) => s + c.unlockingBytes, 0);
const tOp = chunks.reduce((s, c) => s + c.operationCost, 0);
const millerMass = tLock + tUnlock;
const total = millerMass + CARRIED_NONMILLER;
const wholeChunks = chunks.length + 4 + 8 + 1;
console.log('');
console.log(`Miller/residue: ${chunks.length} chunks (deployed 23), mass ${millerMass} B (lock ${tLock} + unlock ${tUnlock}), op ${tOp.toLocaleString()}`);
console.log(`CARRIED non-Miller from /tmp/rv.json: g2check ${CARRIED_G2} + vk_x ${CARRIED_VKX} + residue-tail ${CARRIED_TAIL} = ${CARRIED_NONMILLER} B`);
console.log(`WHOLE-VERIFIER TOTAL = ${total} B   deltaVs274607 = ${total - 274607}   crownCrossed(<241518) = ${total < 241518}`);
console.log(`allChunksAccept(Miller)=${allAcc}  internalChainOk=${chainOk}  startSeam(vkx->miller)=${startSeam}  endSeam(miller->tail)=${endSeam}  depChainOk=${depChainOk}`);
console.log(`newChunkCount(whole verifier) = ${wholeChunks} (${chunks.length} miller + 4 g2check + 8 vkx + 1 tail; deployed 36)`);
console.log('JSON ' + JSON.stringify({
  mode: MODE, millerChunks: chunks.length, millerOps: ops.length, millerMass, millerLock: tLock, millerUnlock: tUnlock, millerOp: tOp,
  carriedNonMiller: CARRIED_NONMILLER, carriedG2: CARRIED_G2, carriedVkx: CARRIED_VKX, carriedTail: CARRIED_TAIL,
  total, deltaVs274607: total - 274607, crownCrossed: total < 241518,
  allChunksAccept: allAcc, internalChainOk: chainOk, startSeam, endSeam, depChainOk, wholeChunkCount: wholeChunks,
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, lockingBytes: c.lockingBytes, unlockingBytes: c.unlockingBytes, operationCost: c.operationCost })),
}));
