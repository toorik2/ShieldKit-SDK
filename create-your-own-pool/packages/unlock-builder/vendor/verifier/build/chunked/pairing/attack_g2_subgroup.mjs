// ADVERSARIAL: g2check G2-subgroup forgery. Craft a non-G2 (small/wrong-subgroup) B on the
// twist, run the FULL 4-chunk g2check covenant chain on the real libauth VM. Accept => forgery.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, proof, commitBin, CATEGORY, TARGET_UNLOCK, decl, covIn, covOut, compileFileBytecode,
} from './_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from './gen_g2check.mjs';
import {
  bigIntToVmNumber, encodeDataPush, hash256, encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;

// ---- twist arithmetic over Fp2 (raw, no subgroup enforcement) ----
const { Fp2 } = bn254.fields;
const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n]);
const eqA = (A, B) => A === null || B === null ? A === B : Fp2.eql(A.x, B.x) && Fp2.eql(A.y, B.y);
const dbl = (Pt) => { if (Pt === null) return null; if (Fp2.is0(Pt.y)) return null;
  const l = Fp2.div(Fp2.mul(Fp2.sqr(Pt.x), 3n), Fp2.mul(Pt.y, 2n));
  const nx = Fp2.sub(Fp2.sqr(l), Fp2.mul(Pt.x, 2n)); return { x: nx, y: Fp2.sub(Fp2.mul(l, Fp2.sub(Pt.x, nx)), Pt.y) }; };
const addA = (A, B) => { if (A === null) return B; if (B === null) return A;
  if (Fp2.eql(A.x, B.x)) return Fp2.eql(A.y, B.y) ? dbl(A) : null;
  const l = Fp2.div(Fp2.sub(B.y, A.y), Fp2.sub(B.x, A.x));
  const nx = Fp2.sub(Fp2.sub(Fp2.sqr(l), A.x), B.x); return { x: nx, y: Fp2.sub(Fp2.mul(l, Fp2.sub(A.x, nx)), A.y) }; };
const negA = (Pt) => Pt === null ? null : { x: Pt.x, y: Fp2.neg(Pt.y) };
const mulA = (k, Pt) => { if (k < 0n) return mulA(-k, negA(Pt)); let R = null, Q = Pt; while (k > 0n) { if (k & 1n) R = addA(R, Q); Q = dbl(Q); k >>= 1n; } return R; };
const onc = (Pt) => Pt === null ? true : Fp2.eql(Fp2.sqr(Pt.y), Fp2.add(Fp2.mul(Fp2.sqr(Pt.x), Pt.x), Fp2B));
const randPt = () => { for (;;) { const x = Fp2.fromBigTuple([(BigInt(Date.now()) * 1000003n + BigInt(Math.floor(Math.random()*1e15))) % P, (BigInt(Math.floor(Math.random()*1e15)) * 7919n) % P]);
  const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), Fp2B); let y; try { y = Fp2.sqrt(rhs); } catch (e) { continue; } if (y && Fp2.eql(Fp2.sqr(y), rhs)) return { x, y }; } };

const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const Na = 479095176016622842441988045216678740799252316531100822436447802254070093686356349204969212544220033486413271283566945264650845755880805213916963058350733n;

// ---- exact copy of unified_fullverifier g2Chunk generator ----
const BN_X = 4965661367192848881n, NBITS = 63;
const g2bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n;
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n];
const G2LIB = '../../../singleton/bn254/lib/Miller.cash';
const RN = ['RXa', 'RXb', 'RYa', 'RYb', 'RZa', 'RZb'], BNM = ['Bxa', 'Bxb', 'Bya', 'Byb'];
const PASS = ['nAx', 'nAy', 'Cx', 'Cy', 'input0', 'input1'];
const G2ST = [...RN, ...BNM, ...PASS];
const SEAM1 = ['nAx', 'nAy', ...BNM, 'Cx', 'Cy', 'input0', 'input1'];
function g2Chunk(lo, hi, isFirst, isLast) {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${G2LIB}";`);
  L.push('contract G2CheckU() {');
  L.push(`    function spend(${decl(G2ST)}${isLast ? ', int zinvA, int zinvB' : ''}, bytes unused zeroPadding) {`);
  L.push(covIn(G2ST));
  if (isFirst) {
    L.push('        require(RXa == 0); require(RXb == 0); require(RYa == 1); require(RYb == 0); require(RZa == 0); require(RZb == 0);');
    L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));');
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');
    L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);');
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  let rr = RN.slice(), uid = 0;
  const fresh = () => Array.from({ length: 6 }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    const d = fresh(); L.push(`        (${decl(d)}) = g2Double(${rr.join(',')});`); rr = d;
    if (g2bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AddAffine(${rr.join(',')}, ${BNM.join(',')});`); rr = a; }
  }
  if (isLast) {
    const [Rxa, Rxb, Rya, Ryb, Rza, Rzb] = rr;
    L.push(`        (int gza,int gzb) = fp2Mul(${Rza}, ${Rzb}, zinvA, zinvB);`);
    L.push('        require(gza == 1); require(gzb == 0);');
    L.push('        (int zi2a,int zi2b) = fp2Sqr(zinvA, zinvB);');
    L.push('        (int zi3a,int zi3b) = fp2Mul(zi2a, zi2b, zinvA, zinvB);');
    L.push(`        (int a0xa,int a0xb) = fp2Mul(${Rxa}, ${Rxb}, zi2a, zi2b);`);
    L.push(`        (int a0ya,int a0yb) = fp2Mul(${Rya}, ${Ryb}, zi3a, zi3b);`);
    L.push('        (int bxa,int bxb,int bya,int byb) = psi(a0xa, a0xb, a0ya, a0yb);');
    L.push('        (int cxa,int cxb,int cya,int cyb) = psi(bxa, bxb, bya, byb);');
    L.push('        (int dxa,int dxb,int dya,int dyb) = psi(cxa, cxb, cya, cyb);');
    L.push('        (int l1xa,int l1xb,int l1ya,int l1yb,int l1za,int l1zb) = g2AddAffine(a0xa, a0xb, a0ya, a0yb, 1, 0, Bxa, Bxb, Bya, Byb);');
    L.push('        (int l2xa,int l2xb,int l2ya,int l2yb,int l2za,int l2zb) = g2AddAffine(l1xa, l1xb, l1ya, l1yb, l1za, l1zb, bxa, bxb, bya, byb);');
    L.push('        (int lxa,int lxb,int lya,int lyb,int lza,int lzb) = g2AddAffine(l2xa, l2xb, l2ya, l2yb, l2za, l2zb, cxa, cxb, cya, cyb);');
    L.push('        (int rxa,int rxb,int rya,int ryb,int rza,int rzb) = g2Double(dxa, dxb, dya, dyb, 1, 0);');
    L.push('        (int lz2a,int lz2b) = fp2Sqr(lza, lzb); (int lz3a,int lz3b) = fp2Mul(lz2a, lz2b, lza, lzb);');
    L.push('        (int rz2a,int rz2b) = fp2Sqr(rza, rzb); (int rz3a,int rz3b) = fp2Mul(rz2a, rz2b, rza, rzb);');
    L.push('        (int xl_a,int xl_b) = fp2Mul(lxa, lxb, rz2a, rz2b); (int xr_a,int xr_b) = fp2Mul(rxa, rxb, lz2a, lz2b);');
    L.push('        require(xl_a == xr_a); require(xl_b == xr_b);');
    L.push('        (int yl_a,int yl_b) = fp2Mul(lya, lyb, rz3a, rz3b); (int yr_a,int yr_b) = fp2Mul(rya, ryb, lz3a, lz3b);');
    L.push('        require(yl_a == yr_a); require(yl_b == yr_b);');
    L.push(covOut(SEAM1));
  } else {
    L.push(covOut([...rr, ...BNM, ...PASS]));
  }
  L.push('    }'); L.push('}');
  return L.join('\n') + '\n';
}

// ---- P2SH eval (byte convention from unified) ----
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit) {
  const outHasTok = outCommit !== null;
  const program = { inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: { version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, ...(outHasTok ? { token: tok(outCommit) } : {}) }],
      locktime: 0 } };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
function runChunk(name, src, committedIn, pushedArgs, outLimbs) {
  const probe = join(GEN, `_atk_${name}.cash`);
  writeFileSync(probe, src);
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecode(probe)]); }
  catch (e) { return { accepted: false, error: 'compile:' + String(e?.message ?? e) }; }
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const inCommit = commitBin(committedIn.map(BigInt));
  const outCommit = outLimbs === null ? null : commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushedArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const pad = padBytes(TARGET_UNLOCK - argb.length - rpush.length);
  const unlocking = Uint8Array.from([...pad, ...argb, ...rpush]);
  return { ...evalCov(locking, unlocking, inCommit, outCommit), redeem, locking, unlocking, inCommit, outCommit };
}

// ---- run the 4-chunk chain for a given affine B = {x:Fp2, y:Fp2} ----
const G2_WINS = [[0, 21], [21, 41], [41, 62], [62, 63]];
function runChain(label, Baff, nAx, nAy, Cx, Cy, in0, in1) {
  const B = [[Baff.x.c0, Baff.x.c1], [Baff.y.c0, Baff.y.c1]];
  const Bxa = red(B[0][0]), Bxb = red(B[0][1]), Bya = red(B[1][0]), Byb = red(B[1][1]);
  const g2State = (upto) => { const [X, Y, Z] = g2checkAccAt(B, upto).map((c) => c.map(red)); return [X[0], X[1], Y[0], Y[1], Z[0], Z[1], Bxa, Bxb, Bya, Byb, nAx, nAy, Cx, Cy, in0, in1]; };
  const zinv = g2checkFastZinv(B).map(red);
  console.log(`\n=== ${label} ===  B on twist: ${onc(Baff)}  in G2 ([r]B==O): ${eqA(mulA(r, Baff), null)}`);
  let allAccept = true, rejectedAt = null;
  for (let ci = 0; ci < G2_WINS.length; ci++) {
    const [lo, hi] = G2_WINS[ci];
    const isFirst = ci === 0, isLast = ci === G2_WINS.length - 1;
    const src = g2Chunk(lo, hi, isFirst, isLast);
    const committedIn = g2State(lo);
    const pushedArgs = isLast ? [...committedIn, ...zinv] : committedIn;
    const outLimbs = isLast ? [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1] : g2State(hi);
    const m = runChunk(`${label}_g2_${ci}`, src, committedIn, pushedArgs, outLimbs);
    console.log(`  chunk ${ci} [${lo},${hi}) first=${isFirst} last=${isLast}: accepted=${m.accepted} op=${m.operationCost ?? '-'} err=${m.error ?? ''}`);
    if (!m.accepted) { allAccept = false; if (rejectedAt === null) rejectedAt = ci; }
    // export the last chunk artifacts for LeanBCH cross-check
    if (isLast) {
      writeFileSync(join(GEN, `_atk_${label}_final_artifacts.json`), JSON.stringify({
        redeemHex: Buffer.from(m.redeem).toString('hex'),
        lockingHex: Buffer.from(m.locking).toString('hex'),
        unlockingHex: Buffer.from(m.unlocking).toString('hex'),
        inCommitHex: Buffer.from(m.inCommit).toString('hex'),
        outCommitHex: m.outCommit ? Buffer.from(m.outCommit).toString('hex') : null,
        categoryHex: Buffer.from(CATEGORY).toString('hex'),
        accepted: m.accepted,
      }, null, 2));
    }
  }
  console.log(`  RESULT ${label}: allAccept=${allAccept} rejectedAtChunk=${rejectedAt}`);
  return { allAccept, rejectedAt };
}

// ---- instance passthrough values (genuine negA,C,inputs from committed proof) ----
const negAaf = proof.a.negate().toAffine(), Caf = proof.c.toAffine();
const nAx = red(negAaf.x), nAy = red(negAaf.y), Cx = red(Caf.x), Cy = red(Caf.y);
const in0 = 5n, in1 = 7n; // arbitrary public inputs (subgroup surface independent of them)

// 1) GENUINE B (proof.b) — must ACCEPT all 4
runChain('genuine', proof.b.toAffine(), nAx, nAy, Cx, Cy, in0, in1);

// 2) SMALL-SUBGROUP B: order-10069 cofactor point (classic small-subgroup forgery)
let p0 = randPt();
const B_small = mulA(Na / 10069n, p0);
console.log('\n[B_small] order-10069 check [10069]B==O:', eqA(mulA(10069n, B_small), null), ' nonzero:', !eqA(B_small, null));
runChain('small10069', B_small, nAx, nAy, Cx, Cy, in0, in1);

// 3) GENERIC cofactor B: [r]*p0 (order | h2, not in G2)
const B_cof = mulA(r, p0);
console.log('\n[B_cof] generic cofactor [h2]B==O check via [r]B nonzero:', !eqA(B_cof, null), ' [r]B_cof==O?', eqA(mulA(r, B_cof), null));
runChain('cofactor', B_cof, nAx, nAy, Cx, Cy, in0, in1);

// 4) G2 + cofactor mix: B = genuineB + cofactor (on curve, NOT in G2)
const Bmix = addA(proof.b.toAffine(), B_cof);
console.log('\n[Bmix] genuineB + cofactor; in G2?', eqA(mulA(r, Bmix), null));
runChain('mix', Bmix, nAx, nAy, Cx, Cy, in0, in1);
