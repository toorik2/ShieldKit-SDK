// T4-KP SEMANTICS-NULL A/B (real build modules). For several interior miller windows, compile the
// SAME window (A) with the original runtime-k*P lib and (B) with the k-baked specialized lib +
// rewriteChunk, drive BOTH through the real BCH-2026 VM with identical committed input + witnesses,
// and assert: both ACCEPT and the output commitment is BIT-IDENTICAL (same intermediate f). Also
// asserts B costs strictly fewer ops (the k-plumbing really was deleted). Any divergence => NOT
// semantics-null (A1-fatal) and this exits non-zero.
import { writeFileSync } from 'node:fs';
import { specializeLib, rewriteChunk } from '../../../intel/validation/T4-KP/t4kp_specialize.mjs';
import {
  genChunk as millerGenChunk, ops as millerOps, inState as millerInState,
  outState as millerOutState, chunkLambdas as millerLambdas,
} from './gen_miller_affine.mjs';
import { compileFileBytecode, commitBin, CATEGORY } from './_millermath.mjs';
import {
  encodeDataPush, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32,
  createVirtualMachineBch2026, binToHex,
} from '@bitauth/libauth';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const TARGET_UNLOCK = 10_000;
const ORIG_IMPORT = 'import "../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash";';
const KSPEC_IMPORT = 'import "../../../singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash";';
const KSPEC_PATH = join(here, '../../singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash');

{ const { libText } = specializeLib(); writeFileSync(KSPEC_PATH, libText); }

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const SUCC_SPK = encodeLockingBytecodeP2sh32(hash256(Uint8Array.from([0x51])));
const SUCC_HEX = binToHex(SUCC_SPK);
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });

function evalCov(locking, unlocking, inCommit, outCommit, outLock) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
function measure(tag, src, committedIn, pushedArgs, outLimbs) {
  const probe = join(GEN, `_semnull_${tag}.cash`);
  writeFileSync(probe, src);
  const redeem = Uint8Array.from([...compileFileBytecode(probe)]);
  const rpush = encodeDataPush(redeem);
  const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
  const inCommit = commitBin(committedIn.map(BigInt));
  const outCommit = commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushedArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const pad = padBytes(TARGET_UNLOCK - argb.length - rpush.length);
  const unlocking = Uint8Array.from([...pad, ...argb, ...rpush]);
  const r = evalCov(locking, unlocking, inCommit, outCommit, SUCC_SPK);
  return { op: r.operationCost, accepted: r.accepted, error: r.error, outCommitHex: binToHex(outCommit) };
}

const LEN = millerOps.length;
// interior windows spread across the miller ladder (non-genesis, non-final), width 19
const WINDOWS = [[20, 39], [83, 102], [167, 186], [293, 312], [335, 347]];
let allOk = true;
for (const [lo, hi] of WINDOWS) {
  const committedIn = millerInState(lo).map(red);
  const outLimbs = millerOutState(hi).map(red);
  const pushed = [...millerInState(lo).map(BigInt), ...millerLambdas(lo, hi).map(BigInt)];
  const srcOrig = millerGenChunk(lo, hi, false, false, SUCC_HEX);
  const A = measure(`orig_${lo}`, srcOrig, committedIn, pushed, outLimbs);
  const srcSpec = rewriteChunk(srcOrig.replace(ORIG_IMPORT, KSPEC_IMPORT));
  const B = measure(`spec_${lo}`, srcSpec, committedIn, pushed, outLimbs);
  const semNull = A.accepted && B.accepted && A.outCommitHex === B.outCommitHex;
  const cheaper = B.op < A.op;
  const ok = semNull && cheaper;
  allOk = allOk && ok;
  console.log(`win[${lo},${hi})  A:acc=${A.accepted} op=${A.op}  B:acc=${B.accepted} op=${B.op}  Δop=${A.op - B.op}  outCommitIdentical=${A.outCommitHex === B.outCommitHex}  => ${ok ? 'SEM-NULL OK' : 'FAIL'}${A.error ? ' Aerr=' + A.error : ''}${B.error ? ' Berr=' + B.error : ''}`);
}
console.log(allOk ? '\nRESULT: ALL WINDOWS SEMANTICS-NULL (both accept, outCommit bit-identical, spec cheaper)' : '\nRESULT: FAIL — divergence detected');
process.exit(allOk ? 0 : 1);
