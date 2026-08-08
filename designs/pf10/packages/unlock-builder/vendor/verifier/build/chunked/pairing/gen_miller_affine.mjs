import { repoPath as vcRepoPath } from '#repo-paths';
// S3 AFFINE-offload variant of gen_miller_residue.mjs. Pair0 (the only runtime-point pair) rides
// AFFINE (R = 4 limbs) and its pointDouble/pointAdd are replaced by affDbl/affAdd with a WITNESSED
// slope lam (2 limbs / point-op, pushed in the unlocking, NOT committed). The slope is verified
// (lam*2y==3x^2 / lam*(Rx-Qx)==Ry-Qy) so lam is uniquely forced (2y!=0 / Rx!=Qx guarded) and the
// derived next affine point equals 2R / R+Q; that point is pinned forward as covenant state so a
// cheating prover cannot substitute. Line coeffs equal pointDouble/pointAdd at Z=1 (proven vs
// noble), so the folded f is a valid Miller value; the residue witness is recomputed from THIS
// affine boundary by the driver. Everything else (fusion, self-pin, tail) is identical.
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import {
  Fp2, f12limbs, pairsFor, vec, singlePairMiller, PT_CFG, ptLimbs, decl, covIn, covOut, proofFromLimbs,
} from './_millermath.mjs';
import { millerBatchOpsAffine, millerFusedOpsAffine } from './_affmath.mjs';
import { residueWitness } from './_residuemath.mjs';
import { hexToBin, vmNumberToBigInt } from '@bitauth/libauth';

const LIB_IMPORT = process.env.LIB_IMPORT ?? '../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash';

// ELIGIBILITY (runtimeGeneral) instance selector — DEFAULT-INERT. Unset => committed proof #0 (chunk
// states byte-identical). Set ELIG_INSTANCE=proof1|worstcase (matching unified_affine.mjs) to build the
// miller trajectory for a DISTINCT proof; the chunk redeem is generic (baked f_ab is the fixed-VK pair),
// so only the covIn/covOut/lambda WITNESS values change — the P2SH32 lockings are invariant.
function eligPairs() {
  const sel = process.env.ELIG_INSTANCE;
  if (!sel) return pairsFor(vec.publicInputs);
  const mp = JSON.parse(readFileSync(vcRepoPath('harness/src/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
  const parse = (hex) => { const b = hexToBin(hex), v = []; let i = 0; while (i < b.length) { const op = b[i++]; if (op === 0x00) v.push(0n); else if (op === 0x4f) v.push(-1n); else if (op >= 0x51 && op <= 0x60) v.push(BigInt(op - 0x50)); else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); v.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; } } const d = v.reverse(); return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] }; };
  const s = sel === 'worstcase' ? mp.worstCaseProof : mp.proofs[Number(process.env.ELIG_IDX ?? 1)];
  const p = parse(s.unlocking);
  return pairsFor([p.in0, p.in1], proofFromLimbs(p.Ax, p.Ay, p.Bxa, p.Bxb, p.Bya, p.Byb, p.Cx, p.Cy));
}
const PAIRS = eligPairs();
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

// planning instance witness (chunk math is generic; only window boundaries + baked f_ab come from it)
const { boundary: fRawPlan } = millerBatchOpsAffine(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN } = residueWitness(fRawPlan);
export const { ops, states, boundary } = millerFusedOpsAffine(PAIRS, C_PLAN, CINV_PLAN, singlePairMiller);

const FAB_LIMBS = f12limbs(singlePairMiller(PAIRS[1]).f).map((x) => x.toString());
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
// AFFINE R0 = 4 limbs (x,y) instead of Jacobian 6.
const r4limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1];
const stateLimbs = (s) => [...f12limbs(s.f), ...r4limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 16); const rest = limbs.slice(16); return [...fr, ...ptL, ...rest]; };
export const inState = (i) => withPts(stateLimbs(states[i]));
export const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

// witnessed slopes (reduced) for the pair0 point ops in window [lo,hi), in DECLARATION order —
// exactly the order genChunk emits the lam params. dl/al -> 2 limbs; pp -> 4 (two psi-adds).
const red = (x) => ((x % 21888242871839275222246405745257275088696311157297823662689037894645226208583n) + 21888242871839275222246405745257275088696311157297823662689037894645226208583n) % 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export function chunkLambdas(lo, hi) {
  const out = [];
  for (let i = lo; i < hi; i++) {
    const op = ops[i];
    if (op.j !== 0) continue;
    if (op.t === 'dl' || op.t === 'al') out.push(red(op.lam.c0), red(op.lam.c1));
    else if (op.t === 'pp') { out.push(red(op.lams[0].c0), red(op.lams[0].c1), red(op.lams[1].c0), red(op.lams[1].c1)); }
  }
  return out;
}

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
export function genChunk(opLo, opHi, isFinal, relocGenesis = false, succSpk = null) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb'];           // AFFINE (4)
  const stateParams = [...inF, ...inR0, ...ptParams, ...cNames, ...ciNames];
  // lam witness params for this window's pair0 point ops (declaration order)
  const lamParams = [];
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i];
    if (op.j !== 0) continue;
    if (op.t === 'dl' || op.t === 'al') lamParams.push(`lm${i}a`, `lm${i}b`);
    else if (op.t === 'pp') lamParams.push(`lp${i}_0a`, `lp${i}_0b`, `lp${i}_1a`, `lp${i}_1b`);
  }
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// AFFINE-offload prepared-VK batched BN254 Miller chunk: ops [${opLo},${opHi}). Pair0 rides`);
  L.push('// affine (R=4 limbs) with witnessed slope lam; slope verified + point derived + pinned forward.');
  L.push('contract MillerAffineChunk() {');
  if (relocGenesis) {
    L.push(`    function spend(${decl([...stateParams, ...lamParams])}, bytes unused zeroPadding) {`);
    L.push(covIn(ptParams));
    L.push('        ' + inF.map((n, i) => `require(${n} == ${ciNames[i]});`).join(' '));
    // pin R0 = B (pair0's Q) AFFINE: (R0x,R0y) = (Q0x,Q0y)
    L.push('        require(R0xa == Q0xa); require(R0xb == Q0xb); require(R0ya == Q0ya); require(R0yb == Q0yb);');
  } else {
    L.push(`    function spend(${decl([...stateParams, ...lamParams])}, bytes unused zeroPadding) {`);
    L.push(covIn(stateParams));
  }
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe}, 64);`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  let f = inF.slice(); let r0 = inR0.slice(); let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = line(${f.join(',')}, ${coeffs.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q;
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'cf') { const g = fresh(12); const m = op.neg ? cNames : ciNames; L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${m.join(',')});`); f = g; }
    else if (op.t === 'cmul1') { const g = fresh(12); L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${FAB_LIMBS.join(',')});`); f = g; }
    else if (op.t === 'dl') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const dco = fresh(6), dr = fresh(4);                 // AFFINE: 6 coeffs + 4 point
      L.push(`        (${decl([...dco, ...dr])}) = affDbl(${r0.join(',')}, lm${i}a, lm${i}b);`); r0 = dr;
      emitLine(dco, pi);
    } else if (op.t === 'al') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(4);
      L.push(`        (${decl([...aco, ...ar])}) = affAdd(${r0.join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]}, lm${i}a, lm${i}b);`); r0 = ar;
      emitLine(aco, pi);
    } else { // pp (pair0): two psi affine adds
      if (fixed) { emitLine(bakedCoeffs(op.coeffs[0]), pi); emitLine(bakedCoeffs(op.coeffs[1]), pi); continue; }
      const q1 = fresh(4);
      L.push(`        (${decl(q1)}) = psi(${pi.Qxae}, ${pi.Qxbe}, ${pi.Qyae}, ${pi.Qybe});`);
      const bco = fresh(6), br = fresh(4);
      L.push(`        (${decl([...bco, ...br])}) = affAdd(${r0.join(',')}, ${q1.join(',')}, lp${i}_0a, lp${i}_0b);`); r0 = br;
      emitLine(bco, pi);
      const q2 = fresh(4); L.push(`        (${decl(q2)}) = psi(${q1.join(',')});`);
      const q2ny = fresh(2); L.push(`        (${decl(q2ny)}) = fp2Neg(${q2[2]}, ${q2[3]}, 64);`);
      const cco = fresh(6), cr = fresh(4);
      L.push(`        (${decl([...cco, ...cr])}) = affAdd(${r0.join(',')}, ${q2[0]}, ${q2[1]}, ${q2ny[0]}, ${q2ny[1]}, lp${i}_1a, lp${i}_1b);`); r0 = cr;
      emitLine(cco, pi);
      // T5-1: FOLD the G2-subgroup membership of pair0's Q (=B) into this final ladder window,
      // replacing the deleted standalone g2check subgroup ladder. After the two psi-adds, r0 (=cr)
      // = R_end = [6x+2]B + psi(B) - psi^2(B). For B in G2 the optimal-ate relation forces
      //   R_end == -psi^3(B)   <=>   phi(B) := [6x+2]B + psi(B) - psi^2(B) + psi^3(B) == O,
      // and ker(phi) ∩ E'(Fp2) == G2 EXACTLY (no twist-cofactor point is killed) — proven by
      // direct-point + eigenvalue on all 4 twist-cofactor primes + cyclic-completeness in
      // intel/validation/T5-1/t5_1_cofactor_kernel.mjs. Compute q3 = psi(q2) = psi^3(B), negate
      // its y, and require R_end == (q3.x, -q3.y). psi/fp2Neg outputs are LAZY (unreduced), r0 is
      // reduced (affAdd % Pm), so compare mod P on both sides. SOUND ONLY for on-twist B: B-on-twist
      // is enforced at the (relocated) vkx genesis and covenant-bound through to here, so this fold
      // never sees an off-twist point (where ker(phi) could exceed G2).
      if (op.j === 0) {
        const q3 = fresh(4); L.push(`        (${decl(q3)}) = psi(${q2.join(',')});`);
        const nq3y = fresh(2); L.push(`        (${decl(nq3y)}) = fp2Neg(${q3[2]}, ${q3[3]}, 64);`);
        // r0 (=cr) is REDUCED (affAdd returns coords % Pm); psi/fp2Neg outputs are LAZY, so reduce the
        // psi side only. Inline the modulus literal (no deep stack local) so the T2-A InvokeCSE pass
        // factors only depth-insensitive literal pushes and its undomint equivalence proof stays exact.
        const Pm = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
        L.push(`        require(${cr[0]} == ${q3[0]} % ${Pm}); require(${cr[1]} == ${q3[1]} % ${Pm});`);
        L.push(`        require(${cr[2]} == ${nq3y[0]} % ${Pm}); require(${cr[3]} == ${nq3y[1]} % ${Pm});`);
      }
    }
  }
  // MODSTRIP: generator-derived canonical (already-reduced, covIn-bound pass-through) limb set.
  // ptParams are covIn-bound + predecessor-reduced in EVERY miller chunk (covIn(ptParams) at genesis,
  // covIn(stateParams) interior/final). cNames/ciNames are canonical ONLY when a predecessor covOut
  // reduced them AND covIn binds them — true for interior & final, but NOT the relocation genesis,
  // whose c/ci arrive as FRESH unbound witnesses (covIn binds only ptParams there). f/r0 are freshly
  // COMPUTED SSA results (v-names), never canonical. This mirrors covIn provenance exactly (not hand-kept).
  const canonOut = relocGenesis
    ? new Set(ptParams)
    : isFinal
      ? new Set([...cNames, ...ciNames])
      : new Set([...ptParams, ...cNames, ...ciNames]);
  L.push(isFinal
    ? covOut([...f, ...cNames, ...ciNames], succSpk, canonOut)
    : covOut([...f, ...r0, ...ptParams, ...cNames, ...ciNames], succSpk, canonOut));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// self-test: emit + report op counts
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  console.error(`affine miller: ${ops.length} fused ops; pair0 lambdas total =`, chunkLambdas(0, ops.length).length / 2);
  console.error('genesis chunk [0,4) preview lines:', genChunk(0, 4, false, true, '00'.repeat(35)).split('\n').length);
}
