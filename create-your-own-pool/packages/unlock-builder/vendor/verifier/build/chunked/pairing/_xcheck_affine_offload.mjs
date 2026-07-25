// A1 SECOND-ORACLE cross-check for the S3 AFFINE point-trajectory offload (crown 214,175 B, 2df5835).
// Exports TWO real BCH-2026 affine covenant chunks — one AFFINE-MILLER chunk and one G2-AFFINE
// (endo) chunk — byte-identically to unified_affine.mjs (the driver that produces the crown), each
// as a token-carrying covenant tx. For each we emit wire hex (tx + source outputs) for LeanBCH's
// independent VM (xcheck_arg.lean) and record libauth's accept/op-cost. A FORGE variant (one
// witnessed slope lambda corrupted +1) is emitted for each; both VMs must REJECT it.
//
// Chunk builders reuse the EXACT crown code paths:
//   affine-miller: gen_miller_affine.mjs genChunk/inState/outState/chunkLambdas (imported)
//   g2-affine:     unified_affine.mjs's g2 machinery (g2Chunk/g2StateA/g2LambdasA/g2Trace), copied verbatim
// Compile = RESCHED (compileFileBytecode), token/tx convention = unified_affine.evalCov, all identical.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, vec, proof, commitBin, CATEGORY, TARGET_UNLOCK, decl, covIn, covOut,
  compileFileBytecode,
} from './_millermath.mjs';
import {
  genChunk as millerGenChunk, ops as millerOps, inState as millerInState,
  outState as millerOutState, chunkLambdas as millerLambdas,
} from './gen_miller_affine.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
import {
  binToHex, bigIntToVmNumber, encodeDataPush, hash256,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
  encodeTransaction, encodeTransactionOutputs,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;

// ---- crown covenant-tx machinery (byte-identical to unified_affine.mjs) -------------------------
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function buildProgram(locking, unlocking, inCommit, outCommit, outLocking) {
  const outHasTok = outCommit !== null;
  const outLock = outLocking ?? locking;
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, ...(outHasTok ? { token: tok(outCommit) } : {}) }],
      locktime: 0,
    },
  };
}
function evalCov(locking, unlocking, inCommit, outCommit, outLocking) {
  const st = realVm.evaluate(buildProgram(locking, unlocking, inCommit, outCommit, outLocking));
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
// 35-byte P2SH32-shaped successor spk (VALUE irrelevant to size/op-cost), as in unified_affine PLAN pass
const PLAN_SPK_BIN = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]);
const PLAN_SPK = binToHex(PLAN_SPK_BIN);

// Build a covenant chunk + binary-search the minimal accepting unlocking, then emit wire hex.
// pushedArgs = full decl-order push list (committedIn state + witnessed slopes). Returns metrics + hex.
function exportChunk(fname, src, committedIn, pushedArgs, outLimbs, succSpkBin) {
  const probe = join(GEN, `_xc_${fname}.cash`);
  writeFileSync(probe, src);
  const redeem = Uint8Array.from([...compileFileBytecode(probe)]);
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const outLock = succSpkBin ?? locking;
  const tail = rpush.length;
  const inCommit = commitBin(committedIn.map(BigInt));
  const outCommit = outLimbs === null ? null : commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushedArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const mkUnlock = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  // binary-search the minimal accepting unlocking length (crown convention)
  let loU = argb.length + tail + 2, hiU = TARGET_UNLOCK;
  const topProbe = evalCov(locking, mkUnlock(TARGET_UNLOCK), inCommit, outCommit, outLock);
  let target;
  if (!topProbe.accepted) { target = TARGET_UNLOCK; }
  else { while (loU < hiU) { const mid = (loU + hiU) >> 1; if (evalCov(locking, mkUnlock(mid), inCommit, outCommit, outLock).accepted) hiU = mid; else loU = mid + 1; } target = hiU; }
  const unlocking = mkUnlock(target);
  const real = evalCov(locking, mkUnlock(target), inCommit, outCommit, outLock);
  const prog = buildProgram(locking, unlocking, inCommit, outCommit, outLock);
  return {
    accepted: real.accepted, operationCost: real.operationCost, error: real.error,
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    txHex: binToHex(encodeTransaction(prog.transaction)),
    srcOutsHex: binToHex(encodeTransactionOutputs(prog.sourceOutputs)),
    // forge: re-emit the SAME chunk at the same unlock target with pushedArgs mutated (caller supplies)
    _fixed: { locking, inCommit, outCommit, outLock, tail, target, mkUnlockFrom: (args) => Uint8Array.from([...padBytes(target - Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)])).length - tail), ...Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)])), ...rpush]) },
  };
}
function evalForge(fixed, pushedArgs) {
  const unlocking = fixed.mkUnlockFrom(pushedArgs);
  const real = evalCov(fixed.locking, unlocking, fixed.inCommit, fixed.outCommit, fixed.outLock);
  const prog = buildProgram(fixed.locking, unlocking, fixed.inCommit, fixed.outCommit, fixed.outLock);
  return { accepted: real.accepted, operationCost: real.operationCost, error: real.error,
    txHex: binToHex(encodeTransaction(prog.transaction)), srcOutsHex: binToHex(encodeTransactionOutputs(prog.sourceOutputs)) };
}
const writeHex = (pfx, txHex, srcOutsHex) => { writeFileSync(`${pfx}_tx.hex`, txHex); writeFileSync(`${pfx}_srcouts.hex`, srcOutsHex); };

// ================================================================================================
// CHUNK 1: AFFINE-MILLER interior chunk [4,8) — ops sqr, cf, affDbl(pair0), affAdd(pair0) + line folds
//   witnessed slopes: 4 (dl@0 -> lam.c0,c1 ; al@0 -> lam.c0,c1). Forge: corrupt first slope limb (+1).
// ================================================================================================
{
  const [lo, hi] = [4, 8];
  const src = millerGenChunk(lo, hi, false, false, PLAN_SPK);         // interior, non-reloc, plan-spk successor
  const inFull = millerInState(lo).map(BigInt);
  const committedIn = inFull.map(red);
  const outLimbs = millerOutState(hi).map(red);
  const lambdas = millerLambdas(lo, hi).map(BigInt);
  const pushed = [...inFull, ...lambdas];
  const m = exportChunk('ml_4_8', src, committedIn, pushed, outLimbs, PLAN_SPK_BIN);
  writeHex('/tmp/xaff_ml', m.txHex, m.srcOutsHex);
  console.log(`AFFINE-MILLER [4,8) honest : libauthAccepted=${m.accepted} opCost=${m.operationCost} lock=${m.lockingBytes} unlock=${m.unlockingBytes} err=${m.error ?? 'none'} lambdas=${lambdas.length}`);
  // FORGE: corrupt the FIRST witnessed slope limb (affDbl slope lam.c0) by +1 -> slope require must fail
  const forged = [...inFull, ...lambdas]; forged[inFull.length] = red(lambdas[0] + 1n);
  const f = evalForge(m._fixed, forged);
  writeHex('/tmp/xaff_mlf', f.txHex, f.srcOutsHex);
  console.log(`AFFINE-MILLER [4,8) FORGE  : libauthAccepted=${f.accepted} (must be false) err=${f.error ?? 'none'}`);
}

// ================================================================================================
// CHUNK 2: G2-AFFINE final ladder chunk [50,63) — [x0]B affine ladder tail + endo subgroup relation.
//   Copied VERBATIM from unified_affine.mjs (g2 machinery). Witnessed slopes: ladder dbl/add + 4 endo.
//   Forge: corrupt first witnessed ladder slope limb (+1) -> g2AffDbl slope require must fail.
// ================================================================================================
{
  const BN_X = 4965661367192848881n, NBITS = 63;
  const g2bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n;
  const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
              266929791119991161246907387137283842545076965332900288569378510910307636690n];
  const G2LIBA = '../../../singleton/bn254/lib/Miller_aff.cash';
  const RN4 = ['RXa', 'RXb', 'RYa', 'RYb'];
  const BNM = ['Bxa', 'Bxb', 'Bya', 'Byb'];
  const PASS = ['nAx', 'nAy', 'Cx', 'Cy', 'input0', 'input1'];
  const G2STA = [...RN4, ...BNM, ...PASS];
  const SEAM1 = ['nAx', 'nAy', ...BNM, 'Cx', 'Cy', 'input0', 'input1'];
  const negA = proof.a.negate().toAffine(), Baf = proof.b.toAffine(), Caf = proof.c.toAffine();
  const nAx = red(negA.x), nAy = red(negA.y);
  const Bxa = red(Baf.x.c0), Bxb = red(Baf.x.c1), Bya = red(Baf.y.c0), Byb = red(Baf.y.c1);
  const Cx = red(Caf.x), Cy = red(Caf.y);
  const inputs = vec.publicInputs.map(BigInt);
  const in0 = inputs[0], in1 = inputs[1];
  const Fp2A = bn254.fields.Fp2;
  const conjFp2 = (x) => Fp2A.fromBigTuple([x.c0, (bn254.fields.Fp.ORDER - x.c1) % bn254.fields.Fp.ORDER]);
  const PSI_Xg = Fp2A.pow(Fp2A.NONRESIDUE, (bn254.fields.Fp.ORDER - 1n) / 3n);
  const PSI_Yg = Fp2A.pow(Fp2A.NONRESIDUE, (bn254.fields.Fp.ORDER - 1n) / 2n);
  const psiJS = (x, y) => [Fp2A.mul(conjFp2(x), PSI_Xg), Fp2A.mul(conjFp2(y), PSI_Yg)];
  const Baff = { x: Fp2A.fromBigTuple([Bxa, Bxb]), y: Fp2A.fromBigTuple([Bya, Byb]) };
  const g2Trace = (() => {
    const Rafter = new Array(NBITS), lamDbl = {}, lamAdd = {};
    let R = { x: Baff.x, y: Baff.y }; Rafter[0] = { x: Baff.x, y: Baff.y };
    for (let k = 1; k < NBITS; k++) {
      const d = affDoubleJS(R.x, R.y); lamDbl[k] = d.lam; R = d.R;
      if (g2bit(k)) { const a = affAddJS(R.x, R.y, Baff.x, Baff.y); lamAdd[k] = a.lam; R = a.R; }
      Rafter[k] = { x: R.x, y: R.y };
    }
    const a0 = Rafter[NBITS - 1];
    const b = psiJS(a0.x, a0.y), c = psiJS(b[0], b[1]), d = psiJS(c[0], c[1]);
    const l1 = affAddJS(a0.x, a0.y, Baff.x, Baff.y);
    const l2 = affAddJS(l1.R.x, l1.R.y, b[0], b[1]);
    const l3 = affAddJS(l2.R.x, l2.R.y, c[0], c[1]);
    const rr = affDoubleJS(d[0], d[1]);
    return { Rafter, lamDbl, lamAdd, endoLams: [l1.lam, l2.lam, l3.lam, rr.lam] };
  })();
  const r4 = (R) => [red(R.x.c0), red(R.x.c1), red(R.y.c0), red(R.y.c1)];
  const g2StateA = (loo) => [...(loo === 0 ? [Bxa, Bxb, Bya, Byb] : r4(g2Trace.Rafter[loo - 1])), Bxa, Bxb, Bya, Byb, nAx, nAy, Cx, Cy, in0, in1];
  function g2LambdasA(loo, hii, isLast) {
    const out = [];
    for (let k = Math.max(loo, 1); k < hii; k++) { const d = g2Trace.lamDbl[k]; out.push(red(d.c0), red(d.c1)); if (g2bit(k)) { const a = g2Trace.lamAdd[k]; out.push(red(a.c0), red(a.c1)); } }
    if (isLast) for (const lm of g2Trace.endoLams) out.push(red(lm.c0), red(lm.c1));
    return out;
  }
  function g2Chunk(loo, hii, isFirst, isLast, succSpk) {
    const lamP = [];
    for (let k = Math.max(loo, 1); k < hii; k++) { lamP.push(`ld${k}a`, `ld${k}b`); if (g2bit(k)) lamP.push(`la${k}a`, `la${k}b`); }
    if (isLast) lamP.push('le1a', 'le1b', 'le2a', 'le2b', 'le3a', 'le3b', 'lera', 'lerb');
    const L = [];
    L.push('pragma cashscript ^0.14.0;');
    L.push(`import "${G2LIBA}";`);
    L.push('contract G2CheckAff() {');
    L.push(`    function spend(${decl([...G2STA, ...lamP])}, bytes unused zeroPadding) {`);
    L.push(covIn(G2STA));
    if (isFirst) {
      L.push('        require(RXa == Bxa); require(RXb == Bxb); require(RYa == Bya); require(RYb == Byb);');
      L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));');
      L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');
      L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);');
      L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
      L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
      L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
      L.push('        require(oba == ora); require(obb == orb);');
    }
    let r = RN4.slice(), uid = 0;
    const fresh = () => Array.from({ length: 4 }, () => `v${uid++}`);
    for (let k = Math.max(loo, 1); k < hii; k++) {
      const d = fresh(); L.push(`        (${decl(d)}) = g2AffDbl(${r.join(',')}, ld${k}a, ld${k}b);`); r = d;
      if (g2bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AffAdd(${r.join(',')}, ${BNM.join(',')}, la${k}a, la${k}b);`); r = a; }
    }
    if (isLast) {
      const [Rxa, Rxb, Rya, Ryb] = r;
      L.push(`        (int bxa,int bxb,int bya,int byb) = psi(${Rxa}, ${Rxb}, ${Rya}, ${Ryb});`);
      L.push('        (int cxa,int cxb,int cya,int cyb) = psi(bxa, bxb, bya, byb);');
      L.push('        (int dxa,int dxb,int dya,int dyb) = psi(cxa, cxb, cya, cyb);');
      L.push(`        (int l1xa,int l1xb,int l1ya,int l1yb) = g2AffAdd(${Rxa}, ${Rxb}, ${Rya}, ${Ryb}, Bxa, Bxb, Bya, Byb, le1a, le1b);`);
      L.push('        (int l2xa,int l2xb,int l2ya,int l2yb) = g2AffAdd(l1xa, l1xb, l1ya, l1yb, bxa, bxb, bya, byb, le2a, le2b);');
      L.push('        (int l3xa,int l3xb,int l3ya,int l3yb) = g2AffAdd(l2xa, l2xb, l2ya, l2yb, cxa, cxb, cya, cyb, le3a, le3b);');
      L.push('        (int rxa,int rxb,int rya,int ryb) = g2AffDbl(dxa, dxb, dya, dyb, lera, lerb);');
      L.push('        require(l3xa == rxa); require(l3xb == rxb); require(l3ya == rya); require(l3yb == ryb);');
      L.push(covOut(SEAM1, succSpk));
    } else {
      L.push(covOut([...r, ...BNM, ...PASS], succSpk));
    }
    L.push('    }');
    L.push('}');
    return L.join('\n') + '\n';
  }

  const [lo, hi] = [50, 63];
  const src = g2Chunk(lo, hi, false, true, PLAN_SPK);                 // final ladder chunk (endo), plan-spk successor
  const committedIn = g2StateA(lo);
  const lambdas = g2LambdasA(lo, hi, true);
  const pushed = [...committedIn, ...lambdas];
  const outLimbs = [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1]; // SEAM1
  const m = exportChunk('g2_50_63', src, committedIn, pushed, outLimbs, PLAN_SPK_BIN);
  writeHex('/tmp/xaff_g2', m.txHex, m.srcOutsHex);
  console.log(`G2-AFFINE     [50,63) honest: libauthAccepted=${m.accepted} opCost=${m.operationCost} lock=${m.lockingBytes} unlock=${m.unlockingBytes} err=${m.error ?? 'none'} lambdas=${lambdas.length}`);
  // FORGE: corrupt the FIRST witnessed ladder slope limb (+1) -> g2AffDbl slope require must fail
  const forged = [...committedIn, ...lambdas]; forged[committedIn.length] = red(lambdas[0] + 1n);
  const f = evalForge(m._fixed, forged);
  writeHex('/tmp/xaff_g2f', f.txHex, f.srcOutsHex);
  console.log(`G2-AFFINE     [50,63) FORGE : libauthAccepted=${f.accepted} (must be false) err=${f.error ?? 'none'}`);
}
