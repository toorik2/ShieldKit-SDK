// ADVERSARIAL: miller reloc-genesis is the ONLY point where c/cInv enter UNBOUND by covIn
// (covIn binds only the 10 runtime points). f is pinned == cInv. Attack: feed NON-CANONICAL
// cInv (residue-equivalent cInv + k*p, and residue-changing) to try to (a) drive a subFp/tower
// intermediate negative so covOut commits a NON-CANONICAL limb while ACCEPTING, or (b) corrupt
// the residue. covOut re-reduces every limb via `% Pmod`. We target the HONEST canonical covOut:
// accept  <=> script reproduced the honest canonical state (residue preserved, all reps >=0);
// reject  <=> non-canonical input perturbed a committed rep (=> chain cannot continue: safe).
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK } from './_millermath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_forge_genesis.cash');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;

// reloc-genesis window [0,17) (matches unified ml_0[0,17)G)
const [LO, HI] = [0, 17];
const src = genChunk(LO, HI, HI === ops.length, /*relocGenesis*/ true);
writeFileSync(PROBE, src);
const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const tailLen = rpush.length;
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });

// full 52-limb pushed state (decl order): f(12) R0(6) points(10) c(12) cInv(12)
// covIn (reloc) binds ONLY the 10 runtime points => inCommit = commitBin(points10).
const inFull = inState(LO).map(BigInt);      // honest full 52-limb pushed args
const points10 = inFull.slice(18, 28).map(red);
const honestOut = outState(HI).map(red);     // honest canonical covOut (52 limbs)
const inCommitPoints = commitBin(points10);

// indices in the 52-limb decl order:
//   f: 0..11, R0: 12..17, points: 18..27, c: 28..39, cInv: 40..51
function mkProgram(pushed52, outCommit, unlocking) {
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommitPoints) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
}
function evalGen(pushed52, outLimbs) {
  const outCommit = commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushed52].reverse().flatMap((c) => [...pushInt(c)]));
  const u = Uint8Array.from([...padBytes(TARGET_UNLOCK - argb.length - tailLen), ...argb, ...rpush]);
  const st = realVm.evaluate(mkProgram(pushed52, outCommit, u));
  const t = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1;
  return { accepted, error: st.error ?? null, op: st.metrics.operationCost };
}
function exportGen(name, pushed52, outLimbs) {
  const outCommit = commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushed52].reverse().flatMap((c) => [...pushInt(c)]));
  const u = Uint8Array.from([...padBytes(TARGET_UNLOCK - argb.length - tailLen), ...argb, ...rpush]);
  const prog = mkProgram(pushed52, outCommit, u);
  writeFileSync(`/tmp/forge_${name}_tx.hex`, binToHex(encodeTransaction(prog.transaction)));
  writeFileSync(`/tmp/forge_${name}_srcouts.hex`, binToHex(encodeTransactionOutputs(prog.sourceOutputs)));
  const st = realVm.evaluate(prog); const t = st.stack[st.stack.length - 1];
  const acc = st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1;
  console.log(`  exported /tmp/forge_${name}_{tx,srcouts}.hex libauthAccept=${acc} op=${st.metrics.operationCost}`);
}

// build a pushed-state variant: cInv (and pinned f) offset by delta on limb `li` (0..11)
function variant(deltaFn) {
  const p = inFull.slice();
  for (let i = 0; i < 12; i++) {
    const d = deltaFn(i);
    p[40 + i] = BigInt(p[40 + i]) + d;   // cInv limb
    p[0 + i]  = BigInt(p[0 + i])  + d;   // f pinned == cInv  (require f_j == ci_j)
  }
  return p;
}

console.log('=== MILLER RELOC-GENESIS FORGERY (cInv unbound; f pinned==cInv) ===');
console.log(`window [${LO},${HI}) redeem=${redeem.length}B`);

// G0 honest -> honest covOut
console.log(`G0 honest cInv, honest covOut         : accept=${JSON.stringify(evalGen(inFull, honestOut))}`);

// G1 cInv += p (residue-equiv, non-canonical) -> honest covOut
{ const p = variant(() => P); console.log(`G1 cInv+=p    -> honest covOut         : ${JSON.stringify(evalGen(p, honestOut))}`); }
// G2 cInv += 64p -> honest covOut
{ const p = variant(() => 64n * P); console.log(`G2 cInv+=64p  -> honest covOut         : ${JSON.stringify(evalGen(p, honestOut))}`); }
// G3 cInv += 1000p -> honest covOut
{ const p = variant(() => 1000n * P); console.log(`G3 cInv+=1000p-> honest covOut         : ${JSON.stringify(evalGen(p, honestOut))}`); }
// G4 cInv += 500000p on limb0 only -> honest covOut (target where sqr/mul limb0 dominates)
{ const p = inFull.slice(); p[40] = BigInt(p[40]) + 500000n * P; p[0] = BigInt(p[0]) + 500000n * P;
  console.log(`G4 cInv0+=500000p -> honest covOut     : ${JSON.stringify(evalGen(p, honestOut))}`); }
// G5 residue-CHANGING cInv (cInv0 += 1) -> honest covOut  (must reject: wrong residue)
{ const p = inFull.slice(); p[40] = BigInt(p[40]) + 1n; p[0] = BigInt(p[0]) + 1n;
  console.log(`G5 cInv0+=1 (wrong residue)->honestOut : ${JSON.stringify(evalGen(p, honestOut))} (EXPECT reject)`); }
// G6 f NOT pinned to cInv (break the pin) -> honest covOut (must reject: require f==cInv)
{ const p = inFull.slice(); p[0] = BigInt(p[0]) + 1n;  // f0 != cInv0
  console.log(`G6 f0 != cInv0 (break pin)            : ${JSON.stringify(evalGen(p, honestOut))} (EXPECT reject)`); }

// export G0 honest + G2 (cInv+=64p) for LeanBCH
console.log('=== exports for LeanBCH ===');
exportGen('gen_honest', inFull, honestOut);
{ const p = variant(() => 64n * P); exportGen('gen_cInv64p', p, honestOut); }
