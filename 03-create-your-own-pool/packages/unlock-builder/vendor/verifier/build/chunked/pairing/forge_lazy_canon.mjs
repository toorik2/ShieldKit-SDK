// ADVERSARIAL forgery battery for surface: lazy-canonicity-finalexp.
// Attacks the DEPLOYED residue tail (unified_fullverifier tailSrc) + exports crafted txs for
// the LeanBCH second oracle. Tests: (T0) honest accept; (T1) FALSE statement fF' (wrong residue)
// must reject; (T2) non-canonical c (>=p) must reject (c_j<P gate); (T3) non-canonical c negative
// rep (same field elt); (T4) search over coset w + false fF; plus toPaddedBytes(negative) encoding.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, vec, proof, commitBin, CATEGORY, TARGET_UNLOCK, decl, covIn, covOut,
  compileFileBytecode, pairsFor, millerBatchOps,
} from './_millermath.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf, COSET27, mk12, ROOT27 } from './_residuemath.mjs';
import {
  binToHex, bigIntToVmNumber, encodeDataPush, hash256,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
  encodeTransaction, encodeTransactionOutputs,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
const red = (x) => ((BigInt(x) % P) + P) % P;
const TAIL_LIB = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';

// ---------- tail source (byte-identical to unified_fullverifier tailSrc) ----------
const fFn = Array.from({ length: 12 }, (_, i) => `fF${i}`), cN = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciN = Array.from({ length: 12 }, (_, i) => `ci${i}`), wN = Array.from({ length: 12 }, (_, i) => `w${i}`);
const COMMIT = [...fFn, ...cN, ...ciN];
const ROOT27L = fp12limbsOf(COSET27[1]).map(String);
const ROOT27_2L = fp12limbsOf(COSET27[2]).map(String);
const ONE_L = ['1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'];
const matchVec = (names, lits) => '(' + names.map((n, i) => `${n} == ${lits[i]}`).join(' && ') + ')';
function tailSrc() {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${TAIL_LIB}";`);
  L.push('contract ResidueTailU() {');
  L.push(`    function spend(${decl([...COMMIT, ...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT));
  L.push(`        int P = ${Pstr};`);
  L.push('        ' + cN.map((n) => `require(${n} < P);`).join(' '));
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `p${i}`))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(p${i} % P == ${ONE_L[i]});`).join(' '));
  L.push(`        require(${matchVec(wN, ONE_L)} || ${matchVec(wN, ROOT27L)} || ${matchVec(wN, ROOT27_2L)});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cq${i}`))}) = fp12Frob1(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqq${i}`))}) = fp12Frob2(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqqq${i}`))}) = fp12Frob3(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `t${i}`))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `lhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `t${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqq${i}`).join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `rhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `cq${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqqq${i}`).join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---------- P2SH tail eval (mirrors measureChunk, tail = terminal: output has NO token) ----------
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
const probe = join(GEN, '_forge_tail.cash');
writeFileSync(probe, tailSrc());
const redeem = Uint8Array.from([...compileFileBytecode(probe)]);
const rpush = encodeDataPush(redeem);
const locking = p2shSpk(redeem);
const tailLen = rpush.length;

function mkProgram(inCommit, unlocking) {
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }], // OP_RETURN, no token (terminal)
      locktime: 0,
    },
  };
}
// committed36 = the 36 limbs bound by covIn (fF,c,cInv); pushed = committed36 + w (12); note c may be
// NON-canonical for attacks, so commitBin is computed over the SAME pushed raw values.
function evalTail(committed36, w12) {
  const inCommit = commitBin(committed36.map(BigInt));
  const pushed = [...committed36, ...w12];
  const argb = Uint8Array.from([...pushed].reverse().flatMap((c) => [...pushInt(c)]));
  const mkUnlock = (target) => Uint8Array.from([...padBytes(target - argb.length - tailLen), ...argb, ...rpush]);
  const accepts = (u) => { const st = realVm.evaluate(mkProgram(inCommit, u)); const t = st.stack[st.stack.length - 1]; return st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1; };
  // try full-size unlock first
  let u = mkUnlock(TARGET_UNLOCK);
  let st = realVm.evaluate(mkProgram(inCommit, u));
  let t = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1;
  return { accepted, error: st.error ?? null, op: st.metrics.operationCost, program: mkProgram(inCommit, u) };
}
function exportTx(name, committed36, w12) {
  const inCommit = commitBin(committed36.map(BigInt));
  const pushed = [...committed36, ...w12];
  const argb = Uint8Array.from([...pushed].reverse().flatMap((c) => [...pushInt(c)]));
  const u = Uint8Array.from([...padBytes(TARGET_UNLOCK - argb.length - tailLen), ...argb, ...rpush]);
  const prog = mkProgram(inCommit, u);
  writeFileSync(`/tmp/forge_${name}_tx.hex`, binToHex(encodeTransaction(prog.transaction)));
  writeFileSync(`/tmp/forge_${name}_srcouts.hex`, binToHex(encodeTransactionOutputs(prog.sourceOutputs)));
  const st = realVm.evaluate(prog); const t = st.stack[st.stack.length - 1];
  const acc = st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1;
  console.log(`  exported /tmp/forge_${name}_{tx,srcouts}.hex  libauthAccept=${acc} op=${st.metrics.operationCost}`);
}

// ---------- honest witness ----------
const inputs = vec.publicInputs.map(BigInt);
const pairs = pairsFor(inputs);
const { boundary: fRaw } = millerBatchOps(pairs);
const { c: cWit, cInv: ciWit, w: wWit } = residueWitness(fRaw);
const fused = millerFusedOps(pairs, cWit, ciWit);
const fFlimbs = fp12limbsOf(fused.boundary).map(red);
const cLimbs = fp12limbsOf(cWit).map(red);
const ciLimbs = fp12limbsOf(ciWit).map(red);
const wLimbs = fp12limbsOf(wWit).map(red);
const honest36 = [...fFlimbs, ...cLimbs, ...ciLimbs];

console.log('=== TAIL FORGERY BATTERY (surface: lazy-canonicity-finalexp) ===');
// T0 honest
let r0 = evalTail(honest36, wLimbs);
console.log(`T0 honest                       : accept=${r0.accepted} op=${r0.op} err=${r0.error}`);

// T1 FALSE statement: perturb fF to a DIFFERENT residue (fF0 += 1). Pairing no longer 1.
{
  const bad = honest36.slice(); bad[0] = red(BigInt(bad[0]) + 1n);
  const r = evalTail(bad, wLimbs);
  console.log(`T1 false fF (fF0+1) honest w    : accept=${r.accepted} (EXPECT false) err=${r.error}`);
}
// T1b false fF, search ALL 3 coset w values (in case w must change)
{
  const bad = honest36.slice(); bad[0] = red(BigInt(bad[0]) + 1n);
  const cosetW = [COSET27[0], COSET27[1], COSET27[2]].map((x) => fp12limbsOf(x).map(red));
  let anyAcc = false;
  for (let k = 0; k < 3; k++) { const r = evalTail(bad, cosetW[k]); anyAcc = anyAcc || r.accepted; }
  console.log(`T1b false fF, all 3 coset w     : anyAccept=${anyAcc} (EXPECT false)`);
}
// T2 non-canonical c >= p (c0 += p): c_j < P gate must reject
{
  const bad = honest36.slice(); bad[12] = (BigInt(bad[12]) + P).toString(); // c0 += p  (>= p)
  const r = evalTail(bad, wLimbs);
  console.log(`T2 c0 += p (>= p)               : accept=${r.accepted} (EXPECT false: c_j<P gate)`);
}
// T3 non-canonical c NEGATIVE rep (c0 -= p): same field elt; cInv unchanged (still inverse mod p)
{
  const bad = honest36.slice(); bad[12] = (BigInt(bad[12]) - P).toString(); // c0 -= p  (< 0)
  const r = evalTail(bad, wLimbs);
  console.log(`T3 c0 -= p (negative rep)       : accept=${r.accepted}  (same field elt; documents lazy-canon handling)`);
}
// T4 THE forgery: false fF (wrong residue) but try to rescue with a DIFFERENT c that still
//     satisfies c*cInv==1. Set c' = c*g for a random g, cInv' = cInv*g^-1 (still inverses), and
//     see if any coset w makes verdict pass for the false fF. Residue soundness => must fail.
{
  const g = mk12([2n,3n,5n,7n,11n,13n],[17n,19n,23n,29n,31n,37n]); // arbitrary Fp12 elt
  const cP = bn254.fields.Fp12.mul(cWit, g);
  const ciP = bn254.fields.Fp12.mul(ciWit, bn254.fields.Fp12.inv(g));
  const badFF = honest36.slice(); badFF[0] = red(BigInt(badFF[0]) + 1n);
  const c2 = fp12limbsOf(cP).map(red), ci2 = fp12limbsOf(ciP).map(red);
  const state = [badFF.slice(0,12), c2, ci2].flat();
  const cosetW = [COSET27[0], COSET27[1], COSET27[2]].map((x) => fp12limbsOf(x).map(red));
  let anyAcc = false;
  for (let k = 0; k < 3; k++) { const r = evalTail(state, cosetW[k]); anyAcc = anyAcc || r.accepted; }
  console.log(`T4 false fF + scaled (c,cInv)   : anyAccept=${anyAcc} (EXPECT false)`);
}
// T5 sanity: honest c but with EVERY limb pushed as negative rep (c_j - p). Field elt identical.
{
  const bad = honest36.slice();
  for (let i = 12; i < 24; i++) bad[i] = (BigInt(bad[i]) - P).toString();
  // cInv unchanged. c*cInv still == 1 mod p; verdict uses c mod p. c_j<P holds (negatives < P).
  const r = evalTail(bad, wLimbs);
  console.log(`T5 all c limbs negative rep     : accept=${r.accepted}  (documents lazy-canon handling)`);
}

// ---------- export honest + T1 false for LeanBCH cross-check ----------
console.log('=== exports for LeanBCH second oracle ===');
exportTx('tail_honest', honest36, wLimbs);
{ const bad = honest36.slice(); bad[0] = red(BigInt(bad[0]) + 1n); exportTx('tail_falseFF', bad, wLimbs); }
{ const bad = honest36.slice(); bad[12] = (BigInt(bad[12]) - P).toString(); exportTx('tail_cneg', bad, wLimbs); }
