// ADVERSARIAL SPLICE-CROSS-STAGE FORGERY (surface: splice-cross-stage)
// Goal: run vkx honestly on REAL (A,B,C) [seam covOut = 8a088b52...], then feed the
// miller reloc-genesis FORGED points (a different, fully self-consistent instance whose
// vk_x differs). Does the reloc-genesis covIn (which binds ONLY the 10 runtime point
// limbs [negA,B,vk_x,C]) FORCE the miller to use exactly the vkx-final-committed points?
//
// TEST 1 CONTROL  : real witness + input token = REAL vkx covOut  -> expect ACCEPT
// TEST 2 SPLICE   : FORGED witness + input token = REAL vkx covOut -> expect REJECT (covIn)
// TEST 3 ISOLATION: FORGED witness + input token = commitBin(FORGED) -> expect ACCEPT
//                   (proves covIn is a PURE hash-equality; the ONLY barrier to the splice
//                    is that the miller input token is pinned to the honest vkx output)
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw,
  Fp2, f12limbs, r6limbs, pairsFor, ptLimbs, vec, proof, millerBatchOps, vkxPoint,
} from './_millermath.mjs';
import { residueWitness, millerFusedOps } from './_residuemath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import {
  createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE,
  binToHex, encodeTransaction, encodeTransactionOutputs,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_splice.cash');
const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush = (argLen, target) => Uint8Array.from([0x4d, ...numberToBinUint16LE(target - argLen - 3), ...new Uint8Array(target - argLen - 3)]);
const tok = (cm) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: cm } });

const N = Number(process.env.N ?? 8);

// --- REAL instance (from gen_miller_residue module state) ---
const realIn = inState(0).map(BigInt);
const realOut = outState(N).map(BigInt);
const realPtL = realIn.slice(18, 28).map(red);          // [negA,B,vk_x,C] reduced
const realInCommit = commitBin(realPtL);                 // == vkx-final covOut (SEAM2)
const realOutCommit = commitBin(realOut.map(red));

// --- FORGED, fully self-consistent instance (different public input -> different vk_x) ---
const realInputs = vec.publicInputs.map(BigInt);
const forgedInputs = [realInputs[0] + 1n, realInputs[1]]; // a DIFFERENT statement
// same real negA,B,C ; only vk_x = MSM(forgedInputs) changes (pair2's P)
const forgedPairs = pairsFor(forgedInputs, proof);
const forgedFRaw = millerBatchOps(forgedPairs).boundary;
const { c: cF, cInv: ciF } = residueWitness(forgedFRaw);
const fStates = millerFusedOps(forgedPairs, cF, ciF).states;
const ptLF = forgedPairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptLF, ...rest]; };
const forgedIn = withPts(stateLimbs(fStates[0])).map(BigInt);
const forgedOut = withPts(stateLimbs(fStates[N])).map(BigInt);
const forgedPtL = forgedIn.slice(18, 28).map(red);
const forgedInCommit = commitBin(forgedPtL);
const forgedOutCommit = commitBin(forgedOut.map(red));

// sanity: the forged vk_x really differs from the real vk_x
const realVkx = vkxPoint(realInputs).toAffine();
const forgedVkx = vkxPoint(forgedInputs).toAffine();

// --- build the reloc-genesis chunk (relocGenesis = true) ---
const src = genChunk(0, N, false, true);
writeFileSync(PROBE, src);
const locking = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]);

function run(witnessLimbs, inCommit, outCommit, target = TARGET_UNLOCK) {
  const argBytes = Uint8Array.from([...witnessLimbs].reverse().flatMap((v) => [...pushInt(v)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, target), ...argBytes]);
  const transaction = {
    version: 2,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
    outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
    locktime: 0,
  };
  const sourceOutputs = [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }];
  const st = realVm.evaluate({ inputIndex: 0, sourceOutputs, transaction });
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
  return { accepted, op: st.metrics.operationCost, err: st.error ?? null, transaction, sourceOutputs };
}

console.log('=== SPLICE-CROSS-STAGE FORGERY (N =', N, ') ===');
console.log('real   vk_x =', realVkx.x.toString().slice(0, 20), '...');
console.log('forged vk_x =', forgedVkx.x.toString().slice(0, 20), '... (DIFFERENT statement)');
console.log('real   inCommit (= vkx-final SEAM2 covOut) =', binToHex(realInCommit));
console.log('forged inCommit (forged 10-limb hash)      =', binToHex(forgedInCommit));
console.log('collision realInCommit == forgedInCommit ? ', binToHex(realInCommit) === binToHex(forgedInCommit));
console.log();

const t1 = run(realIn, realInCommit, realOutCommit);
console.log('TEST1 CONTROL  (real witness, input token = REAL vkx covOut):   accepted=', t1.accepted, 'op=', t1.op.toLocaleString(), t1.err ? ('err=' + t1.err) : '');

const t2 = run(forgedIn, realInCommit, realOutCommit);
console.log('TEST2 SPLICE   (FORGED witness, input token = REAL vkx covOut): accepted=', t2.accepted, 'op=', t2.op.toLocaleString(), t2.err ? ('err=' + t2.err) : '');

const t3 = run(forgedIn, forgedInCommit, forgedOutCommit);
console.log('TEST3 ISOLATION(FORGED witness, input token = commitBin(FORGED)): accepted=', t3.accepted, 'op=', t3.op.toLocaleString(), t3.err ? ('err=' + t3.err) : '');

// export the SPLICE (test2, reject) and CONTROL (test1, accept) txs to wire hex for LeanBCH
function exportWire(tag, r) {
  const txHex = binToHex(encodeTransaction(r.transaction));
  const soHex = binToHex(encodeTransactionOutputs(r.sourceOutputs));
  writeFileSync(`/tmp/splice_${tag}_tx.hex`, txHex);
  writeFileSync(`/tmp/splice_${tag}_so.hex`, soHex);
  console.log(`wrote /tmp/splice_${tag}_{tx,so}.hex  (libauth accepted=${r.accepted}, op=${r.op.toLocaleString()})`);
}
exportWire('splice', t2);   // the forgery: expect BOTH VMs REJECT
exportWire('control', t1);  // the honest control: expect BOTH VMs ACCEPT
exportWire('isolation', t3);// forged self-consistent: covIn pure-equality proof
