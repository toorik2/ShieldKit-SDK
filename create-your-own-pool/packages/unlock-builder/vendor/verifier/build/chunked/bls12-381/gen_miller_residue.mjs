// Generator for the c^-|x|-FUSED batched BLS12-381 Miller loop (residue method) — L10 AFFINE
// offload of pair-0's on-chain G2 trajectory. Only the runtime pair 0 = e(-A,B) runs on-chain G2
// arithmetic; pairs 2,3 have BAKED line coeffs (fixed VK G2 point); pair 1 = e(alpha,beta) is
// skipped and its UNCONJUGATED single-pair Miller value fAB is multiplied in once via 'cmul1'.
//
// L10: pair-0 rides AFFINE (R = 4 limbs) and each pointDouble/pointAdd is replaced by affDbl/affAdd
// with a WITNESSED slope lam (2 limbs / point-op, pushed UNCOMMITTED in the unlocking). The slope is
// VERIFIED on-chain (lam*2y==3x^2 / lam*(Rx-Qx)==Ry-Qy) so lam is uniquely forced (2y!=0 / Rx!=Qx
// guarded) and the DERIVED next affine point equals 2R / R+Q; that point is pinned forward as
// committed covenant state so a cheating prover cannot substitute. Line coeffs equal the projective
// pointDouble/pointAdd at Z=1, so the folded f differs from the all-projective f only by an Fp*
// factor (dies under ^h in finalExp); the residue witness (c,cInv,w) is recomputed from THIS affine
// boundary by the build driver (residueWitness VERIFIES c^lambda == g_aff*w, so a malformed boundary
// fails loudly at build time).
//
// state = f(12) + R_B(4, AFFINE) + runtime points(10) + c(12) + cInv(12) = 50 limbs; the FINAL chunk
// hands off only [fF, c, cInv] (36 limbs) to the residue tail. Slopes are per-window UNCOMMITTED
// witnesses (declared in spend() but excluded from covIn), supplied as build-vector `extras`.
//   node gen_miller_residue.mjs        plan + emit millerres_NN.cash + manifest_millerres.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp, Fp2, f12limbs, pairsFor, PT_CFG, ptLimbs, proof, proofFromLimbs,
} from './_pairingmath.mjs';
import { commit, measureCovenantFile, planChunk, covIn, covOut, PUBLIC_INPUTS } from './_vkxmath.mjs';
import { residueWitness, fp12limbsOf } from './_residuemath.mjs';
import { millerFusedOpsAffine, millerBatchOpsAffine } from './_affmath_bls.mjs';
import { bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
// import the AFFINE lib (affDbl/affAdd) — it transitively pulls Bls12381LazyG.cash (psi/r2*) +
// the base lazy tower (fp2*/fp12*/line), so this single import covers every op the chunk emits.
const LIB_IMPORT = '../../../singleton/bls12-381/lib/lazy/Bls12381AffG.cash';
const PROBE = join(GEN, '_probe_millerres.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_880_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const decl = (names) => names.map((n) => `int ${n}`).join(', ');
const P = Fp.ORDER;
const red = (x) => ((x % P) + P) % P;

const PAIRS = pairsFor(PUBLIC_INPUTS);
const PINFO = PAIRS.map((pair, j) => {
  const Q = pair.Q.toAffine(), Pt = pair.P.toAffine(), cfg = PT_CFG[j], negQ = Fp2.neg(Q.y);
  return {
    j, cfg, negQ,
    Pxe: cfg.P ? `Px${j}` : `${Pt.x}`, Pye: cfg.P ? `Py${j}` : `${Pt.y}`,
    Qxae: cfg.Q ? `Q${j}xa` : `${Q.x.c0}`, Qxbe: cfg.Q ? `Q${j}xb` : `${Q.x.c1}`,
    Qyae: cfg.Q ? `Q${j}ya` : `${Q.y.c0}`, Qybe: cfg.Q ? `Q${j}yb` : `${Q.y.c1}`,
  };
});
const ptParams = [];
PINFO.forEach((pi, j) => { if (pi.cfg.P) ptParams.push(`Px${j}`, `Py${j}`); if (pi.cfg.Q) ptParams.push(`Q${j}xa`, `Q${j}xb`, `Q${j}ya`, `Q${j}yb`); });
const ptL = PAIRS.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));

// witness for the committed planning instance (chunk math is generic; only window boundaries
// come from this instance). The plan boundary is the raw AFFINE Miller boundary.
const { boundary: fRawPlan } = millerBatchOpsAffine(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN } = residueWitness(fRawPlan);
const { ops, states, boundary, fAB } = millerFusedOpsAffine(PAIRS, C_PLAN, CINV_PLAN);

// baked constant f_{alpha,beta} (pair 1's UNCONJUGATED single-pair Miller value; VK-only),
// multiplied in once by 'cmul1'.
const FAB_LIMBS = fp12limbsOf(fAB).map(String);
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
// state = f(12) + R_B(4, AFFINE) + runtime points + c(12) + cInv(12)
const r4limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1];
const stateLimbs = (s) => [...f12limbs(s.f), ...r4limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 16); const rest = limbs.slice(16); return [...fr, ...ptL, ...rest]; };
const inState = (i) => withPts(stateLimbs(states[i]));
// the FINAL chunk hands off only [fF, c, cInv] (36 limbs, contiguous) to the residue tail —
// R_B/pts are done with once the loop ends. Non-final hand-offs carry the full 50-limb state.
const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

// witnessed slopes (reduced) for the pair0 point ops in window [lo,hi), in DECLARATION order —
// exactly the order genChunk emits the lam params. Each dl/al -> 2 limbs (lam.c0, lam.c1).
export function chunkLambdas(lo, hi) {
  const out = [];
  for (let i = lo; i < hi; i++) {
    const op = ops[i];
    if (op.j !== 0) continue;
    if (op.t === 'dl' || op.t === 'al') out.push(red(op.lam.c0), red(op.lam.c1));
  }
  return out;
}

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
function genChunk(opLo, opHi, isFinal) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb']; // AFFINE (4)
  const stateParams = [...inF, ...inR0, ...ptParams, ...cNames, ...ciNames];
  // lam witness params for this window's pair0 point ops (declaration order); NOT in covIn.
  const lamParams = [];
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i];
    if (op.j === 0 && (op.t === 'dl' || op.t === 'al')) lamParams.push(`lm${i}a`, `lm${i}b`);
  }
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// c^-|x|-fused prepared-VK batched BLS12-381 Miller chunk (L10 affine pair0): ops [${opLo},${opHi}).`);
  L.push('// state = f(12) + R_B(4, AFFINE) [+ runtime points] + c(12) + cInv(12); c,cInv are constant');
  L.push('// carried witness. Pair-0 point ops use witnessed slope lm* (verified). cf op folds c^-1/c.');
  L.push('contract MillerFusedBlsChunk() {');
  L.push(`    function spend(${decl([...stateParams, ...lamParams])}, bytes unused zeroPadding) {`);
  L.push(covIn(stateParams)); // slopes deliberately excluded -> uncommitted witness (transform extras)
  // FUSED input validation (was the standalone g2check pass): the first Miller chunk checks the
  // prover's points are on-curve (A=-P0 & C=P3 on G1 y^2=x^3+4; B=Q0 on G2 y^2=x^3+(4+4u)); the
  // final chunk's psi(B)==[|x|]B subgroup test reuses R_B (=[|x|]B) that this loop already walks.
  if (opLo === 0) {
    L.push('        require(mSqr(Py0) == mAdd(mulFp(mSqr(Px0), Px0), 4));'); // A on G1 (-A shares the curve)
    L.push('        require(mSqr(Py3) == mAdd(mulFp(mSqr(Px3), Px3), 4));'); // C on G1
    L.push('        (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
    L.push('        (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
    L.push('        (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);'); // b' = 4 + 4u
    L.push('        (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
    L.push('        require(by2a == rhsa); require(by2b == rhsb);');
  }
  // precompute -Q.y for any runtime pair whose add-line in this window is negated
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a, int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe});`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  let f = inF.slice(); let r0 = inR0.slice(); let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = line(${f.join(',')}, ${coeffs.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q;
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'cf') { // c-fold: f *= (neg ? c : cInv)
      const g = fresh(12); const m = op.neg ? cNames : ciNames;
      L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${m.join(',')});`); f = g;
    } else if (op.t === 'cmul1') { // f *= baked f_{alpha,beta} (VK constant)
      const g = fresh(12);
      L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${FAB_LIMBS.join(',')});`); f = g;
    } else if (op.t === 'dl') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      // pair-0 AFFINE double: witnessed slope, verified; derives + pins next affine point (4 limbs).
      const dco = fresh(6), dr = fresh(4);
      L.push(`        (${decl([...dco, ...dr])}) = affDbl(${r0.join(',')}, lm${i}a, lm${i}b);`); r0 = dr;
      emitLine(dco, pi);
    } else if (op.t === 'al') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(4);
      L.push(`        (${decl([...aco, ...ar])}) = affAdd(${r0.join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]}, lm${i}a, lm${i}b);`); r0 = ar;
      emitLine(aco, pi);
    }
  }
  // final chunk: G2 subgroup test on B, fused from the standalone g2check pass. R_B (=r0) is the
  // running pair-0 point, which at loop end equals [|x|]B in AFFINE coords. The membership relation
  // is psi(B) == -[|x|]B, so require affine Rx == psi(B).x and Ry == -psi(B).y (no Rz: affine).
  // Rejects any B outside the prime-order subgroup.
  if (isFinal) {
    L.push(`        (int psxa, int psxb, int psya, int psyb) = psi(Q0xa, Q0xb, Q0ya, Q0yb);`);
    L.push('        (int npya, int npyb) = fp2Neg(psya, psyb);');
    L.push(`        require(${r0[0]} == psxa); require(${r0[1]} == psxb);`);
    L.push(`        require(${r0[2]} == npya); require(${r0[3]} == npyb);`);
  }
  // final chunk hands off only [fF, c, cInv] to the residue tail; others carry full state.
  L.push(isFinal ? covOut([...f, ...cNames, ...ciNames]) : covOut([...f, ...r0, ...ptParams, ...cNames, ...ciNames]));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// push order for a raw (untransformed) measurement: committed state limbs, then window slopes.
const pushInts = (lo, hi, i) => [...inState(i), ...chunkLambdas(lo, hi)];

if (process.argv[2] === 'probe') {
  for (const [a, b] of [[0, 4], [0, 8], [ops.length - 4, ops.length]]) {
    const m = measureCovenantFile(genChunk(a, b, b === ops.length), pushInts(a, b, a), inState(a), outState(b), PROBE);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

// A1 REJECTION GATE. The affine offload must FORCE B into the prime-order G2 subgroup AND force the
// witnessed slope/trajectory correct. Prove:
//   (1) off-TWIST B          -> genesis y^2 == x^3+(4+4u) require fails.
//   (2) on-twist off-SUBGROUP B -> final psi(B) == -[|x|]B require fails.
//   (3) TAMPERED slope        -> affDbl/affAdd slope require fails.
//   (4) WRONG intermediate pt -> forced-derivation + covOut binding => output mismatch / reject.
// Every case MUST reject (1 forgery = 0); controls (valid B, honest slopes) must accept.
//   node gen_miller_residue.mjs forge
if (process.argv[2] === 'forge') {
  const F2 = Fp2;
  const b2 = F2.create({ c0: 4n, c1: 4n }); // twist b' = 4 + 4u
  const ok = (v) => (v ? 'PASS' : 'FAIL');
  const last = ops.length;
  let pass = true;

  // controls: honest genesis + honest final accept.
  const cGen = measureCovenantFile(genChunk(0, 4, false), pushInts(0, 4, 0), inState(0), outState(4), PROBE);
  const cFin = measureCovenantFile(genChunk(last - 4, last, true), pushInts(last - 4, last, last - 4), inState(last - 4), outState(last), PROBE);
  console.error(`control  honest genesis accepted=${cGen.accepted}  honest final accepted=${cFin.accepted}`);
  pass &&= cGen.accepted && cFin.accepted;

  // (1) off-TWIST B: bump Q0.y.c0. layout: f(12)+R_B(4) then ptL=[P0x,P0y,Q0xa,Q0xb,Q0ya,...]; Q0ya at index 20.
  const offTwist = pushInts(0, 4, 0).map((x) => BigInt(x)); offTwist[20] += 1n;
  const commitT = inState(0).map(BigInt); commitT[20] += 1n;
  const gT = measureCovenantFile(genChunk(0, 4, false), offTwist, commitT, outState(4), PROBE);
  console.error(`forge#1  off-twist B      -> genesis REJECT: ${ok(!gT.accepted)} (accepted=${gT.accepted})`);
  pass &&= !gT.accepted;

  // (2) off-SUBGROUP B: on the twist (clears genesis) but NOT torsion-free -> psi(B) != -[|x|]B.
  let off = null;
  for (let i = 1n; i < 4000n && !off; i++) {
    const x = F2.create({ c0: i, c1: 0n });
    const rhs = F2.add(F2.mul(F2.sqr(x), x), b2);
    let y; try { y = F2.sqrt(rhs); } catch { continue; }
    if (!F2.eql(F2.sqr(y), rhs)) continue;
    try { const pt = bls12_381.G2.Point.fromAffine({ x, y }); try { pt.assertValidity(); } catch { off = { x, y }; } } catch { /* not constructible */ }
  }
  if (!off) { console.error('forge#2  no off-subgroup B found in search bound -- FAIL'); pass = false; }
  else {
    const Aa = proof.a.toAffine(), Ca = proof.c.toAffine();
    const fp = proofFromLimbs(Aa.x, Aa.y, off.x.c0, off.x.c1, off.y.c0, off.y.c1, Ca.x, Ca.y);
    const fPairs = pairsFor(PUBLIC_INPUTS, fp);
    const fData = millerFusedOpsAffine(fPairs, C_PLAN, CINV_PLAN);
    const fStates = fData.states;
    const fPtL = fPairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
    const sLimbs = stateLimbs(fStates[last - 4]);
    const fInCommit = [...sLimbs.slice(0, 16), ...fPtL, ...sLimbs.slice(16)];
    // window slopes for the FORGED instance's final window
    const fSlopes = [];
    for (let i = last - 4; i < last; i++) { const op = fData.ops[i]; if (op.j === 0 && (op.t === 'dl' || op.t === 'al')) fSlopes.push(red(op.lam.c0), red(op.lam.c1)); }
    const fPush = [...fInCommit, ...fSlopes];
    const fOut = [...f12limbs(fStates[last].f), ...f12limbs(fStates[last].c), ...f12limbs(fStates[last].cInv)];
    const gS = measureCovenantFile(genChunk(last - 4, last, true), fPush, fInCommit, fOut, PROBE);
    console.error(`forge#2  off-subgroup B  -> final psi REJECT: ${ok(!gS.accepted)} (accepted=${gS.accepted})`);
    pass &&= !gS.accepted;
  }

  // (3) TAMPERED slope: flip one slope limb in the genesis window; affDbl/affAdd slope require must fail.
  const push0 = pushInts(0, 4, 0).map(BigInt);
  const nState = inState(0).length; // slopes start right after committed state in the push list
  if (push0.length > nState) {
    const tampered = push0.slice(); tampered[nState] = (BigInt(tampered[nState]) + 1n) % P;
    const gL = measureCovenantFile(genChunk(0, 4, false), tampered, inState(0), outState(4), PROBE);
    console.error(`forge#3  tampered slope   -> affDbl REJECT: ${ok(!gL.accepted)} (accepted=${gL.accepted})`);
    pass &&= !gL.accepted;
  } else { console.error('forge#3  no slope in [0,4) window -- widen window'); pass = false; }

  // (4) WRONG intermediate point: substitute a bad committed R_B into a MID chunk (with honest slopes).
  // The chunk derives the next point from the (wrong) R and honest slopes; its recomputed outBlob no
  // longer matches the honest outState -> covOut/forward binding rejects. Use window [4,8).
  {
    const badCommit = inState(4).map(BigInt);
    // R_B affine sits at limbs 12..15 (f(12) then R_B(4)); corrupt Rx.c0.
    badCommit[12] = (badCommit[12] + 1n) % P;
    const badPush = [...badCommit, ...chunkLambdas(4, 8)];
    const gW = measureCovenantFile(genChunk(4, 8, false), badPush, badCommit, outState(8), PROBE);
    console.error(`forge#4  wrong interm. pt -> covOut REJECT: ${ok(!gW.accepted)} (accepted=${gW.accepted})`);
    pass &&= !gW.accepted;
  }

  console.error(`\nA1 affine-offload gate: ${pass ? 'PASS (all forgeries rejected; controls accept)' : 'FAIL'}`);
  process.exit(pass ? 0 : 1);
}

console.error(`planning FUSED BLS12-381 Miller chunks (L10 affine) (${ops.length} flat ops, ${ops.filter((o) => o.t === 'cf').length} c-folds)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi, hi === ops.length);
    const m = measureCovenantFile(src, pushInts(lo, hi, lo), inL, outL, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final: hi === ops.length, outgoing: commit(outL), src, m };
  };
  const best = planChunk(lo, ops.length, OP_TARGET, tryHi, planState);
  if (!best) throw new Error(`no fitting fused window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: commit(inL), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`fused miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify({
  fused: true, affine: true, numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error('wrote generated/manifest_millerres.json');
