// PATH B — SZ-MILLER LIVE TRAJECTORY MODEL (in-repo, zero ephemeral dependency).
//
// Computes, for the REAL instance, the full Schwartz-Zippel evaluated-Miller trajectory that the
// deployed SZ-miller stage threads across chunks: the fused-Miller step decomposition (fin/factors/
// fout), the honest committed chain (Ris), the z-evaluation covector(s), the per-step factor
// z-evaluations prodFactorZ (identity-bound recompute inputs), the aggregated identity witnesses,
// and the DEPLOYED covenant-threaded rolling-FS running-h chain (gamma) + phase-2 z + big_Q.
//
// The accept predicate this models is REUSED VERBATIM from the moonshot reference (_verifier.mjs /
// _rolling_fs.mjs), but every number is recomputed LIVE from the repo's own affine trajectory
// (_affmath.millerFusedOpsAffine — the DEPLOYED miller) + _residuemath (residue witness / COSET27 /
// frob) + _millermath (pairs / vk / f12limbs), so the SZ stage is consistent with the affine build
// it replaces and reproducible without the scratchpad.
//
// DEPLOYED-STATEMENT DEVIATION (soundness-preserving): the moonshot rolling-FS statement block used
// the RAW public inputs; the deployed statement block instead uses the COVENANT-COMMITTED handles
// (A = -negA derived from committed nA, B, C, vk_x) plus BAKED VK constants (alpha/beta/gamma/delta)
// plus the witnessed residue (c,cInv,w). vk_x is the MSM of the inputs (ECIP-certified upstream), so
// binding vk_x binds the instance exactly as raw inputs would; the challenge is still a hash of the
// full committed statement + all Ris (FIX-1 ordering preserved). gamma/z therefore differ from
// sz_ref_fs.json (which used the raw-input layout) but bind the same instance — the deployed build
// recomputes its own transcript live, so it need not match the probe's fixed reference bytes.
//
//   node _szmath.mjs   (self-test: identity holds; finZ/prodFactorZ cross-check vs sz_ref_id.json)
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  bn254, Fp2, Fp6, Fp12, f12limbs, publicInputs, vk, proof, pairsFor, vkxPoint,
  singlePairMiller, PT_CFG, ATE_NAF, proofFromLimbs,
} from './_millermath.mjs';
import { millerFusedOpsAffine } from './_affmath.mjs';
import { residueWitness, frob, COSET27, eq12 } from './_residuemath.mjs';
import { hexToBin, vmNumberToBigInt } from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
export const P = bn254.fields.Fp.ORDER;
export const mod = (a) => ((a % P) + P) % P;
export const mmul = (a, b) => mod(a * b);
export const madd = (a, b) => mod(a + b);
export const msub = (a, b) => mod(a - b);
export const mpow = (a, e) => { let r = 1n, b = mod(a); while (e > 0n) { if (e & 1n) r = mmul(r, b); b = mmul(b, b); e >>= 1n; } return r; };
export const minv = (a) => mpow(a, P - 2n);

// ---- direct-extension basis converter (auto-derived from noble, verbatim from _verifier.mjs) ----
const f6 = (t) => Fp6.create({ c0: Fp2.fromBigTuple([t[0], t[1]]), c1: Fp2.fromBigTuple([t[2], t[3]]), c2: Fp2.fromBigTuple([t[4], t[5]]) });
const mk12loc = (lo, hi) => Fp12.create({ c0: f6(lo), c1: f6(hi) });
const Wt = mk12loc([0n, 0n, 0n, 0n, 0n, 0n], [1n, 0n, 0n, 0n, 0n, 0n]);
const Wpow = []; { let pw = Fp12.ONE; for (let k = 0; k < 12; k++) { Wpow.push(pw); pw = Fp12.mul(pw, Wt); } }
export const P12 = new Array(13).fill(0n); P12[0] = 82n; P12[6] = mod(-18n); P12[12] = 1n;
const Bm = []; for (let r = 0; r < 12; r++) Bm.push(Wpow.map((col) => f12limbs(col)[r]));
function matInv(M) {
  const n = M.length; const A = M.map((row, i) => [...row.map(mod), ...row.map((_, j) => (i === j ? 1n : 0n))]);
  for (let c = 0; c < n; c++) {
    let piv = -1; for (let r = c; r < n; r++) if (A[r][c] !== 0n) { piv = r; break; }
    if (piv < 0) return null;
    [A[c], A[piv]] = [A[piv], A[c]];
    const invp = minv(A[c][c]); for (let j = 0; j < 2 * n; j++) A[c][j] = mmul(A[c][j], invp);
    for (let r = 0; r < n; r++) if (r !== c && A[r][c] !== 0n) { const g = A[r][c]; for (let j = 0; j < 2 * n; j++) A[r][j] = msub(A[r][j], mmul(g, A[c][j])); }
  }
  return A.map((row) => row.slice(n));
}
const Binv = matInv(Bm);
const matVec = (M, v) => M.map((row) => row.reduce((s, m, j) => madd(s, mmul(m, v[j])), 0n));
export const towerToPoly = (f) => matVec(Binv, f12limbs(f).map(mod));
// covector columns: ez[k] = peval(ezCols[k], z), so <f12limbs(f), ez> == peval(towerToPoly(f), z).
export const ezCols = (() => { const cols = []; for (let k = 0; k < 12; k++) { const u = new Array(12).fill(0n); u[k] = 1n; const l = new Array(12).fill(0n); u.forEach((v, i) => l[i] = v); cols.push(towerToPoly(mk12FromLimbs(l))); } return cols; })();
function mk12FromLimbs(l) { return mk12loc(l.slice(0, 6), l.slice(6)); }

// ---- SPARSE-LINE 6-term covector e6col (verbatim decomposition from gen_szfactor_probe / verify_e6) ----
// A Miller line factor L = mul034(ONE, o0=c2*Py, o3=c1*Px, o4=c0) is 6-sparse. mul034 is linear in
// (o0,o3,o4), so its z-eval collapses to  factorZ = o0a*ex0 + o0b*ex1 + o3a*ex2 + o3b*ex3 + o4a*ex4
// + o4b*ex5, where ex_s = peval(e6col[s], z) are 6 baked z-polynomials. c0/c1/c2 are the Fp2 line
// coeffs; (Px,Py) the G1 point. This is what the on-chain (e) recompute evaluates.
function mul034(o0, o3, o4) {
  const f = Fp12.ONE;
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
}
const Z2 = Fp2.ZERO, U0 = Fp2.fromBigTuple([1n, 0n]), U1 = Fp2.fromBigTuple([0n, 1n]);
export const e6col = [
  towerToPoly(mul034(U0, Z2, Z2)), towerToPoly(mul034(U1, Z2, Z2)),  // o0.c0, o0.c1
  towerToPoly(mul034(Z2, U0, Z2)), towerToPoly(mul034(Z2, U1, Z2)),  // o3.c0, o3.c1
  towerToPoly(mul034(Z2, Z2, U0)), towerToPoly(mul034(Z2, Z2, U1)),  // o4.c0, o4.c1
];
// factorZ via the 6-term form, given Fp2 coeffs [c0,c1,c2], G1 (Px,Py), at z (ex_s = peval(e6col[s],z)).
export function lineFactorZ(coeffs, Px, Py, z) {
  const [c0, c1, c2] = coeffs, ex = e6col.map((col) => peval(col, z));
  const o0 = [mmul(c2.c0, Py), mmul(c2.c1, Py)], o3 = [mmul(c1.c0, Px), mmul(c1.c1, Px)], o4 = [mod(c0.c0), mod(c0.c1)];
  return mod(mmul(o0[0], ex[0]) + mmul(o0[1], ex[1]) + mmul(o3[0], ex[2]) + mmul(o3[1], ex[3]) + mmul(o4[0], ex[4]) + mmul(o4[1], ex[5]));
}

// ---- poly helpers over Fp (verbatim from _verifier.mjs) ----
export const trim = (a) => { let n = a.length; while (n > 1 && a[n - 1] === 0n) n--; return a.slice(0, n); };
export const padd = (a, b) => { const n = Math.max(a.length, b.length), r = new Array(n).fill(0n); for (let i = 0; i < n; i++) r[i] = madd(a[i] || 0n, b[i] || 0n); return r; };
export const psub = (a, b) => { const n = Math.max(a.length, b.length), r = new Array(n).fill(0n); for (let i = 0; i < n; i++) r[i] = msub(a[i] || 0n, b[i] || 0n); return r; };
export const pmul = (a, b) => { const r = new Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) r[i + j] = madd(r[i + j], mmul(a[i], b[j])); return r; };
export const pscale = (a, s) => a.map((x) => mmul(x, s));
export const peval = (a, z) => { let r = 0n; for (let i = a.length - 1; i >= 0; i--) r = madd(mmul(r, z), a[i]); return r; };
export function pdivP12(a) {
  const A = [...a]; const q = new Array(Math.max(1, A.length - 12)).fill(0n);
  for (let i = A.length - 1; i >= 12; i--) { const c = A[i]; if (c === 0n) continue; q[i - 12] = c; for (let j = 0; j <= 12; j++) A[i - 12 + j] = msub(A[i - 12 + j], mmul(c, P12[j])); }
  return { q: trim(q), r: trim(A.slice(0, 12)) };
}

// ---- reconstruct fused steps (fin/factors/fout) from the AFFINE fused op-stream ----
// A step = one squaring window: fin = f before the sqr's line-folds; each non-sqr op contributes its
// multiplicative factor(s). LINE ops (dl/al/pp) are decomposed into ONE Fp12 line factor PER line
// (mul034(ONE, o0,o3,o4) from op.coeffs) — so a `pp` (two psi-add lines) yields TWO separate factors.
// This is REQUIRED for the SZ identity: peval is a ring hom on Fp[x] (pre-P12-reduction), so each
// line must be an independent polynomial factor (the cross-terms are absorbed by big_Q*P12); grouping
// L1*L2 into one reduced Fp12 would break peval(L1)*peval(L2)==peval(L1*L2). c-fold (cf) and fAB
// (cmul1) are single Fp12 factors (faft*inv(fbef)). fin/fout still telescope to the true step values.
const SC = (x, k) => Fp2.fromBigTuple([mmul(x.c0, k), mmul(x.c1, k)]);
export const lineFp12 = (coeffs, Px, Py) => mul034(SC(coeffs[2], Py), SC(coeffs[1], Px), coeffs[0]);
export function reconstructSteps(fused, pairs) {
  const st = fused.states; const steps = []; let cur = null;
  const pP = (j) => { const a = pairs[j].P.toAffine(); return [mod(a.x), mod(a.y)]; };
  for (let i = 0; i < fused.ops.length; i++) {
    const op = fused.ops[i]; const fbef = st[i].f, faft = st[i + 1].f;
    if (op.t === 'sqr') { if (cur) steps.push(cur); cur = { fin: fbef, factors: [], fout: faft, ops: [] }; continue; }
    cur.fout = faft;
    if (op.t === 'cf' || op.t === 'cmul1') {
      const factor = Fp12.mul(faft, Fp12.inv(fbef));
      cur.factors.push(factor); cur.ops.push({ op, kindOp: op.t, factor });
    } else { // dl / al / pp : one factor per line, straight from op.coeffs
      const [Px, Py] = pP(op.j);
      const coeffList = op.t === 'pp' ? op.coeffs : [op.coeffs];
      for (let li = 0; li < coeffList.length; li++) {
        const factor = lineFp12(coeffList[li], Px, Py);
        cur.factors.push(factor); cur.ops.push({ op, kindOp: op.t, line: li, factor });
      }
    }
  }
  if (cur) steps.push(cur);
  return steps;
}
export const honestChain = (steps, boundary) => [...steps.map((s) => s.fin), boundary];

// ---- residue tail + canonicality (verbatim semantics from _verifier.mjs) ----
export const tailHolds = (fN, c, cInv, w) => eq12(Fp12.mul(Fp12.mul(fN, w), frob(c, 2)), Fp12.mul(frob(c, 1), frob(c, 3)));
export function canonical(c, cInv, w, chain0) {
  const cInvOk = eq12(Fp12.mul(c, cInv), Fp12.ONE);
  const wOk = COSET27.some((e) => eq12(e, w));
  const genesisOk = eq12(chain0, cInv);
  return { cInvOk, wOk, genesisOk, all: cInvOk && wOk && genesisOk };
}

// ---- aggregated identity value at (gamma,z) (verbatim from _verifier.mjs) ----
export function aggregatedIdentity(statementFactors, chain, bigQ, gamma, z) {
  const n = statementFactors.length;
  const finZ = chain.map((f) => peval(towerToPoly(f), z));
  const P12z = peval(P12, z), bigQz = peval(bigQ, z);
  let aggLHS = 0n, aggFout = 0n, ci = 1n;
  for (let i = 0; i < n; i++) {
    let prod = mmul(finZ[i], finZ[i]);
    for (const fp of statementFactors[i]) prod = mmul(prod, peval(fp, z));
    aggLHS = madd(aggLHS, mmul(ci, prod));
    aggFout = madd(aggFout, mmul(ci, finZ[i + 1]));
    ci = mmul(ci, gamma);
  }
  const rhs = madd(mmul(bigQz, P12z), aggFout);
  return { lhs: aggLHS, rhs, holds: aggLHS === rhs, gamma, z };
}

// ============================ DEPLOYED ROLLING FIAT-SHAMIR ============================
// hash256 = SHA-256d (the VM's OP_HASH256). Length-extension immune; running-h fed forward as a
// FIXED 32-B PREFIX, index+len-prefixed per block, count-bound finalize. Byte-identical construction
// to gen_szfs_probe's compiled+VM-verified SzFsStmt/SzFsRis/SzFsGamma/SzFsZ contracts.
const sha256 = (b) => createHash('sha256').update(b).digest();
export const hash256 = (b) => sha256(sha256(b));
export const be32 = (x) => { const b = Buffer.alloc(32); let v = mod(BigInt(x)); for (let i = 31; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
export const be4 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; };
const serLimbs = (arr) => Buffer.concat(arr.map(be32));
export const TAG_GAMMA = Buffer.from('BN254-SZMILLER-ROLL/gamma/v1', 'ascii');
export const TAG_GAMMA_FIN = Buffer.from('BN254-SZMILLER-ROLL/gamma-final/v1', 'ascii');
export const TAG_Z = Buffer.from('BN254-SZMILLER-ROLL/z/v1', 'ascii');

// The DEPLOYED statement limbs (60): covenant-committed handles + baked VK + witnessed residue.
//   A(2, =-negA), B(4), C(2), vk_x(2), alpha(2 baked), beta(4 baked), gamma(4 baked), delta(4 baked),
//   c(12), cInv(12), w(12)  == 24 + 36.  (order fixed; the on-chain genesis reconstructs the same.)
// L1-7 coset selector: w in {COSET27[0..2]} -> 1-byte class index (soundness-neutral in the transcript:
// the SZ identity is w-independent and the residue TAIL self-checks w; see gen_miller_sz emitGenesisAbsorb).
export const wselOf = (w) => (eq12(w, COSET27[0]) ? 0n : eq12(w, COSET27[1]) ? 1n : eq12(w, COSET27[2]) ? 2n : (() => { throw new Error('w not in 3-class coset'); })());
export function deployedStatementLimbs(nA, Baf, Caf, vkxAff, c, cInv, w) {
  const g2 = (Q) => [Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1];
  const al = vk.alpha.toAffine(), be = vk.beta.toAffine(), ga = vk.gamma.toAffine(), de = vk.delta.toAffine();
  const Ax = mod(nA.x), Ay = mod(P - mod(nA.y)); // A = -(negA): negate y on G1
  const wLimbs = process.env.L17SEL ? [wselOf(w)] : f12limbs(w);
  return [
    Ax, Ay, ...g2(Baf), mod(Caf.x), mod(Caf.y), mod(vkxAff.x), mod(vkxAff.y),
    al.x, al.y, ...g2(be), ...g2(ga), ...g2(de),
    ...f12limbs(c), ...f12limbs(cInv), ...wLimbs,
  ].map(mod);
}

// PHASE 1 rolling gamma over [ STATEMENT(60 limbs) , Ris_0..Ris_{65}(12 limbs each) ], count-bound.
// Returns gamma + the full running-h seam chain (hs[0]=genesis, hs[k+1]=after block k, last=finalize).
export function rollGamma(stmtLimbs, chain) {
  const blocks = [serLimbs(stmtLimbs), ...chain.map((f) => serLimbs(f12limbs(f).map(mod)))];
  const hs = []; let h = hash256(TAG_GAMMA); hs.push(h);
  for (let i = 0; i < blocks.length; i++) { h = hash256(Buffer.concat([h, be4(i), be4(blocks[i].length), blocks[i]])); hs.push(h); }
  h = hash256(Buffer.concat([h, TAG_GAMMA_FIN, be4(blocks.length)])); hs.push(h);
  return { gamma: mod(BigInt('0x' + h.toString('hex'))), hs, blockCount: blocks.length, blockSizes: blocks.map((b) => b.length) };
}
export function rollZ(gamma, bigQ) {
  const payload = Buffer.concat([TAG_Z, be32(gamma), serLimbs(bigQ.map(mod))]);
  return { z: mod(BigInt('0x' + hash256(payload).toString('hex'))), payloadBytes: payload.length };
}

// ---- honest big_Q from the gamma-aggregated (LHS - fout)/P12 quotient ----
export function honestBigQ(statementFactors, chain, gamma) {
  let bigQ = [0n], ci = 1n;
  for (let i = 0; i < statementFactors.length; i++) {
    const pin = towerToPoly(chain[i]);
    let lhs = pmul(pin, pin);
    for (const fp of statementFactors[i]) lhs = pmul(lhs, fp);
    const { q } = pdivP12(psub(lhs, towerToPoly(chain[i + 1])));
    bigQ = padd(bigQ, pscale(q, ci)); ci = mmul(ci, gamma);
  }
  return bigQ;
}

// ============================ FULL LIVE TRAJECTORY ============================
// ELIG_INSTANCE selector — mirrors unified_affine.mjs / gen_miller_affine.mjs (DEFAULT-INERT).
function eligInstance() {
  const sel = process.env.ELIG_INSTANCE;
  if (!sel) return { pf: proof, inputs: [...publicInputs] };
  if (sel === 'file') {
    const j = JSON.parse(readFileSync(process.env.ELIG_FILE, 'utf8'));
    return {
      pf: proofFromLimbs(BigInt(j.Ax), BigInt(j.Ay), BigInt(j.Bxa), BigInt(j.Bxb), BigInt(j.Bya), BigInt(j.Byb), BigInt(j.Cx), BigInt(j.Cy)),
      inputs: [BigInt(j.in0), BigInt(j.in1)],
    };
  }
  const mp = JSON.parse(readFileSync(join(here, '../../../harness/src/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
  const parse = (hex) => { const b = hexToBin(hex), v = []; let i = 0; while (i < b.length) { const op = b[i++]; if (op === 0x00) v.push(0n); else if (op === 0x4f) v.push(-1n); else if (op >= 0x51 && op <= 0x60) v.push(BigInt(op - 0x50)); else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); v.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; } } const d = v.reverse(); return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] }; };
  const s = sel === 'worstcase' ? mp.worstCaseProof : mp.proofs[Number(process.env.ELIG_IDX ?? 1)];
  const p = parse(s.unlocking);
  return { pf: proofFromLimbs(p.Ax, p.Ay, p.Bxa, p.Bxb, p.Bya, p.Byb, p.Cx, p.Cy), inputs: [p.in0, p.in1] };
}

// Per-step ordered factor spec: ONE entry per factor (matching steps[i].factors order) — exactly what
// the on-chain emitter recomputes for prodFactorZ_i. kinds: varline (pair0 affDbl/affAdd, witnessed
// slope), fixline (pairs 2/3 baked coeffs), cfold (c or cInv linear form), fab (baked fAB). `varpp`/
// `fixpp` are just varline/fixline with a psi-point context (two per pp op).
export function stepFactorSpec(t, i) {
  const s = t.steps[i]; const out = [];
  const pP = { 0: [mod(t.nA.x), mod(t.nA.y)], 2: [mod(t.vkxAff.x), mod(t.vkxAff.y)], 3: [mod(t.Caf.x), mod(t.Caf.y)] };
  for (const e of s.ops) {
    const op = e.op;
    if (e.kindOp === 'cf') { out.push({ kind: 'cfold', useC: !!op.neg }); continue; }
    if (e.kindOp === 'cmul1') { out.push({ kind: 'fab' }); continue; }
    const [Px, Py] = pP[op.j];
    const isVar = op.j === 0;
    if (e.kindOp === 'pp') {
      const li = e.line; // 0 or 1
      out.push({ kind: isVar ? 'varpp' : 'fixpp', pair: op.j, ppLine: li, Px, Py,
        coeffs: op.coeffs[li], lam: isVar ? op.lams[li] : null,
        q: isVar ? (li === 0 ? op.q1 : [op.q2[0], op.q2ny]) : null }); // psi add-point (var pp only; fixed baked)
    } else {
      out.push({ kind: isVar ? 'varline' : 'fixline', pair: op.j, op: e.kindOp, neg: !!op.neg, Px, Py, coeffs: op.coeffs, lam: op.lam });
    }
  }
  return out;
}
// Recompute prodFactorZ_i from the spec exactly as the on-chain chunk will (validates the emitter math).
export function prodFactorZfromSpec(t, i, z) {
  const spec = stepFactorSpec(t, i); const ecl = ezCols.map((col) => peval(col, z));
  const cl = f12limbs(t.c).map(mod), cil = f12limbs(t.cInv).map(mod), fabl = f12limbs(t.fAB).map(mod);
  const dot = (limbs) => limbs.reduce((s, v, k) => madd(s, mmul(v, ecl[k])), 0n);
  let prod = 1n;
  for (const f of spec) {
    if (f.kind === 'cfold') prod = mmul(prod, dot(f.useC ? cl : cil));
    else if (f.kind === 'fab') prod = mmul(prod, dot(fabl));
    else prod = mmul(prod, lineFactorZ(f.coeffs, f.Px, f.Py, z)); // varline/fixline/varpp/fixpp
  }
  return prod;
}

let _traj = null;
// SZ_ALLAFF=1 runs the fixed pairs (2,3 = gamma,delta) AFFINE too, so every fixed line carries an
// affine slope `lam` — the de-bake precondition for the moonshot-v2 GENERIC-body architecture. The
// whole trajectory (boundary/chain/bigQ/residue) is recomputed live and stays self-consistent; the
// aggregated identity holds regardless of coordinate system (residueWitness solves w on the boundary).
export const ALLAFF = process.env.SZ_ALLAFF === '1';
const AFFPAIRS = ALLAFF ? new Set([0, 2, 3]) : new Set([0]);
export function trajectory() {
  if (_traj) return _traj;
  const { pf, inputs } = eligInstance();
  const pairs = pairsFor(inputs, pf);
  const fRaw = millerFusedOpsAffine(pairs, Fp12.ONE, Fp12.ONE, singlePairMiller, { affPairs: AFFPAIRS }).boundary; // raw boundary for residue
  const { c, cInv, w } = residueWitness(fRaw);
  const fused = millerFusedOpsAffine(pairs, c, cInv, singlePairMiller, { affPairs: AFFPAIRS });
  const steps = reconstructSteps(fused, pairs);
  const chain = honestChain(steps, fused.boundary);
  const statementFactors = steps.map((s) => s.factors.map((fa) => towerToPoly(fa)));
  // instance affine handles
  const nA = pf.a.negate().toAffine(), Baf = pf.b.toAffine(), Caf = pf.c.toAffine();
  const vkxAff = vkxPoint(inputs).toAffine();
  // rolling FS (deployed statement layout) -> gamma, honest big_Q, z
  const stmtLimbs = deployedStatementLimbs(nA, Baf, Caf, vkxAff, c, cInv, w);
  const g = rollGamma(stmtLimbs, chain);
  const bigQ = honestBigQ(statementFactors, chain, g.gamma);
  const zr = rollZ(g.gamma, bigQ);
  const z = zr.z, gamma = g.gamma;
  // z-evaluations
  const finZ = chain.map((f) => peval(towerToPoly(f), z));
  const prodFactorZ = steps.map((s) => s.factors.reduce((acc, fa) => mmul(acc, peval(towerToPoly(fa), z)), 1n));
  const bigQz = peval(bigQ, z);
  const id = aggregatedIdentity(statementFactors, chain, bigQ, gamma, z);
  _traj = {
    pairs, pf, inputs, c, cInv, w, fused, steps, chain, statementFactors,
    nA, Baf, Caf, vkxAff, stmtLimbs, seamH: g.hs, blockCount: g.blockCount, blockSizes: g.blockSizes,
    gamma, z, bigQ, bigQz, finZ, prodFactorZ, id, fAB: fused.fAB, boundary: fused.boundary,
  };
  return _traj;
}

// ---- self-test: identity holds live; finZ/prodFactorZ cross-check vs sz_ref_id.json (fixed gamma/z) ----
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const t = trajectory();
  const ok = (c, m) => console.log(`  [${c ? 'PASS' : 'FAIL'}] ${m}`);
  console.log('=== _szmath live trajectory self-test ===');
  console.log(`  steps=${t.steps.length} chain=${t.chain.length} blockCount=${t.blockCount} bigQ=${t.bigQ.length}`);
  console.log(`  gamma=${t.gamma.toString().slice(0, 24)}...  z=${t.z.toString().slice(0, 24)}...`);
  ok(t.id.holds, 'live aggregated identity holds at rolling (gamma,z)');
  ok(t.finZ.every((v, i) => v === peval(towerToPoly(t.chain[i]), t.z)), 'finZ_i == <chain_i, e(z)> for all i');
  ok(canonical(t.c, t.cInv, t.w, t.chain[0]).all, 'canonicality: c*cInv==1, w in COSET27, chain0==cInv');
  ok(tailHolds(t.chain[t.chain.length - 1], t.c, t.cInv, t.w), 'residue tail holds on boundary fF');
  // cross-check finZ covector against sz_ref_id.json (its FIXED gamma/z) — validates towerToPoly/ezCols
  try {
    const REFID = JSON.parse(readFileSync(join(here, 'sz_ref_id.json'), 'utf8'));
    const zr = BigInt(REFID.z);
    const ezR = ezCols.map((col) => peval(col, zr));
    const finZref = t.chain.map((f) => { const l = f12limbs(f).map(mod); return l.reduce((s, v, i) => madd(s, mmul(v, ezR[i])), 0n); });
    const finZdirect = t.chain.map((f) => peval(towerToPoly(f), zr));
    ok(finZref.every((v, i) => v === finZdirect[i]), 'ezCols covector reproduces peval(towerToPoly, z_ref) (basis converter correct)');
  } catch (e) { console.log(`  [SKIP] sz_ref_id cross-check: ${String(e.message).slice(0, 60)}`); }
  // factor kind census (doubling=3, add=7, last=dense)
  const hist = {}; t.steps.forEach((s) => { const k = s.factors.length; hist[k] = (hist[k] || 0) + 1; });
  console.log('  step factor-count histogram:', JSON.stringify(hist));
  // EMITTER-MATH validation: prodFactorZ recomputed via the spec (6-term lines + <c/cInv/fAB,ez> folds)
  // must equal the direct peval(towerToPoly(factor),z) for EVERY step. This is exactly what each chunk
  // computes on-chain — if it matches here, the identity-bound recompute is correct.
  const specOk = t.steps.every((_, i) => prodFactorZfromSpec(t, i, t.z) === t.prodFactorZ[i]);
  ok(specOk, 'prodFactorZ_i via emitter spec (6-term lines + c/cInv/fAB folds) == direct peval for ALL 65 steps');
  // rolling-h recompute check: reproduce seamH chain from stmtLimbs + chain (what genesis/interior absorb)
  const g2 = rollGamma(t.stmtLimbs, t.chain);
  ok(g2.hs.every((h, i) => Buffer.compare(h, t.seamH[i]) === 0) && g2.gamma === t.gamma, 'rolling-h seam chain + gamma reproducible from committed statement + chain');
}
