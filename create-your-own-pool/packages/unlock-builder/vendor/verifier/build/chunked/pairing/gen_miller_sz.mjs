// PATH B — SZ-MILLER STAGE GENERATOR (real, covenant-threaded). Drop-in replacement for the affine
// miller STAGE-3 (gen_miller_affine.mjs): same genChunk/ops/inState/outState/chunkLambdas contract,
// same relocGenesis/isFinal/succSpk covenant convention, same INPUT seam (covIn(ptParams)=ecipSEAM2)
// and OUTPUT seam (final covOut = tailState36 = [fF,c,cInv], 36 limbs) that the residue tail consumes.
//
// Instead of folding the Miller f in Fp12 across 17 chunks, each SZ chunk assembles a WINDOW of the
// 65 NAF steps into a Schwartz-Zippel EVALUATED identity at a Fiat-Shamir point z, threading:
//   * the rolling-FS running-h (1 int limb, 33-byte-split encoding) — statement absorbed at genesis,
//     one Ris block (a committed intermediate Miller f) absorbed per step at the chunk producing it;
//   * the aggregated-identity partial sums (aggL, aggF, gp=gamma^i) + the seam finZ (finZ of the
//     shared fout/next-fin, so chain values are absorbed exactly once and never re-witnessed unbound);
//   * the FS challenges (gamma, z) — witnessed at genesis, threaded unchanged, PINNED in the final
//     chunk to finalize(rolling-h)/rollZ(gamma,bigQ) so the whole aggregation is bound to the hash;
//   * the affine pair0 R-ladder (4 limbs) — the ONLY runtime-point pair; its per-step doubling/adding
//     line coeffs are RECOMPUTED on-chain via the deployed affDbl/affAdd (witnessed slope, slope-bound
//     to committed R), so prodFactorZ is IDENTITY-BOUND (A1): never a free witness.
// Fixed-G2 pairs (vkx_gamma, C_delta) bake their proof-independent line coeffs; the alpha_beta pairing
// is the baked GT constant fAB (folded as <fAB, e(z)>); the residue c/cInv folds are the witnessed
// linear form <c/cInv, e(z)>. The witnessed boundary fF (=chain[last]) is bound by BOTH the rolling-h
// (absorbed as the last Ris block) and the identity (finZ_last = <fF, e(z)> is the last fout term), so
// no on-chain Fp12 multiply is needed. cpowFinal folds uniformly into the chain (Ris) values and is
// bound transitively through the per-step c-folds — it is NOT a separate on-chain exponentiation.
//
// The full trajectory (steps, chain, factors, gamma/z/bigQ, prodFactorZ, e6col/ezCols) is computed
// LIVE by ./_szmath.mjs (self-tested: identity holds; prodFactorZ via this exact recompute recipe ==
// direct peval for all 65 steps; rolling-h reproducible). The affine miller it replaces is byte-
// identical semantics (same fF boundary, same residue witness).
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { writeFileSync } from 'node:fs';
import {
  decl, covIn, covOut, serExpr, f12limbs, vk, compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK,
} from './_millermath.mjs';
import {
  trajectory, ezCols, e6col, stepFactorSpec, P, mod,
  hash256, be32 as jsBe32, be4 as jsBe4, TAG_GAMMA, TAG_GAMMA_FIN, TAG_Z, deployedStatementLimbs, wselOf,
} from './_szmath.mjs';
import {
  bigIntToVmNumber, hash256 as laHash256, encodeDataPush, binToHex,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const Pstr = P.toString();
const LIB = '../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash';
const t = trajectory();                       // live trajectory for the active instance
export const stepCount = t.steps.length;      // 65 — the chunkable unit is the STEP

// ---- baked constants (proof-independent OR live-committed; emitted as literals) ----
const hex = (b) => Buffer.from(b).toString('hex');
const H0_HEX = hex(hash256(TAG_GAMMA));       // genesis running-h = hash256(TAG_GAMMA)
const TAGZ_HEX = hex(TAG_Z), TAGFIN_HEX = hex(TAG_GAMMA_FIN);
const be4hex = (n) => n.toString(16).padStart(8, '0');
const BE4_384 = be4hex(384), STMT_BYTES = t.blockSizes[0], BE4_STMT = be4hex(STMT_BYTES);
const RIS_BYTES = t.blockSizes[1];            // 384
const BLOCKCOUNT = t.blockCount;              // 67
const FAB_L = f12limbs(t.fAB).map(mod);
const EZCOLS = ezCols.map((c) => c.map(mod)); // 12 x 12
const E6 = e6col.map((c) => c.map(mod));      // 6 x 12
// baked VK G1/G2 limbs for the statement block (order matches deployedStatementLimbs)
const g2l = (Q) => { const a = Q.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1].map(mod); };
const g1l = (Q) => { const a = Q.toAffine(); return [a.x, a.y].map(mod); };
const VK_AL = g1l(vk.alpha), VK_BE = g2l(vk.beta), VK_GA = g2l(vk.gamma), VK_DE = g2l(vk.delta);
const BIGQ = t.bigQ.map(mod);                 // 103 coeffs (final chunk)
// De-bake constants (moonshot-v2): the fixed pairs' G2 add-points (proof-independent VK consts) and
// their affine T-trajectory start per step boundary. GAMMA_Q=pair2 add-point, DELTA_Q=pair3.
const GAMMA_Q = g2l(vk.gamma), DELTA_Q = g2l(vk.delta);           // [x.c0,x.c1,y.c0,y.c1] affine
// affine fixed-T at the START of each step (Rs[j] at the step's sqr op), + one past the end.
function affStartT(j) {
  const per = [];
  for (let ii = 0; ii < t.fused.ops.length; ii++) if (t.fused.ops[ii].t === 'sqr') { const R = t.fused.states[ii].Rs[j]; per.push([mod(R.x.c0), mod(R.x.c1), mod(R.y.c0), mod(R.y.c1)]); }
  const last = t.fused.states[t.fused.states.length - 1].Rs[j];
  per.push([mod(last.x.c0), mod(last.x.c1), mod(last.y.c0), mod(last.y.c1)]);
  return per;
}
const _Tg = affStartT(2), _Td = affStartT(3);                    // per-step-boundary fixed-T (affine)
// fixed-line lambda count / names / values for window [lo,hi) (dl/al only; pp stays baked at close).
function fixLamMeta(lo, hi) {
  const names = [], vals = []; let c = 0;
  for (let ii = lo; ii < hi; ii++) for (const f of stepFactorSpec(t, ii)) {
    if (f.kind === 'fixline') { names.push(`fl${c}a`, `fl${c}b`); vals.push(mod(f.lam.c0), mod(f.lam.c1)); c++; }
  }
  return { names, vals };
}
// de-bake fixed-data spend params (T-starts + lambdas) and their VALUES for window [lo,hi).
const T_START_NAMES = ['Tgxa', 'Tgxb', 'Tgya', 'Tgyb', 'Tdxa', 'Tdxb', 'Tdya', 'Tdyb'];
export function debakeParams(lo, hi) { return [...T_START_NAMES, ...fixLamMeta(lo, hi).names]; }
export function debakeVals(lo, hi) { return [..._Tg[lo], ..._Td[lo], ...fixLamMeta(lo, hi).vals].map(mod); }

// ---- state limb layout (45) — the covenant-threaded SZ state ----
const PT = ['nAx', 'nAy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'vkxX', 'vkxY', 'Cx', 'Cy']; // 10 (ecipSEAM2 order)
const CN = Array.from({ length: 12 }, (_, i) => `c${i}`);
const CIN = Array.from({ length: 12 }, (_, i) => `ci${i}`);
const RN = ['Rxa', 'Rxb', 'Rya', 'Ryb'];
const SCAL = ['hInt', 'aggL', 'aggF', 'gp', 'gammaW', 'zW', 'finZseam'];
export const STATE = [...PT, ...CN, ...CIN, ...RN, ...SCAL];   // 45 threaded limbs

// per-step witnessed slope count for pair0 (var-G2): dl=2, dl+al=4, last-step pp adds 4 more.
function stepSlopeNames(i) {
  const spec = stepFactorSpec(t, i); const names = [];
  spec.forEach((f, k) => { if (f.kind === 'varline') names.push(`s${i}_${k}a`, `s${i}_${k}b`); if (f.kind === 'varpp') names.push(`s${i}_${k}a`, `s${i}_${k}b`); });
  return names;
}
// per-step witnessed slope VALUES (reduced), declaration order == stepSlopeNames
function stepSlopeVals(i) {
  const spec = stepFactorSpec(t, i); const out = [];
  spec.forEach((f) => { if (f.kind === 'varline' || f.kind === 'varpp') { out.push(mod(f.lam.c0), mod(f.lam.c1)); } });
  return out;
}
// fout witness names/vals for step i (chain[i+1], 12 limbs) — the Ris absorbed this step
const foutNames = (i) => Array.from({ length: 12 }, (_, k) => `r${i + 1}_${k}`);
const chainLimbs = (i) => f12limbs(t.chain[i]).map(mod);

// ---- z-power / covector prologue (computed once per chunk from committed z) ----
// The vendored cashc fork rejects UNUSED locals, so P12z (final only) and fABz (only if the window
// has a fab factor) are emitted conditionally.
function prologue(L, zName, needP12, needFab) {
  L.push(`        int P = ${Pstr};`);
  L.push(`        int zp0 = 1; int zp1 = ${zName} % P;`);
  for (let j = 2; j < 12; j++) L.push(`        int zp${j} = (zp${j - 1} * ${zName}) % P;`);
  const zp = Array.from({ length: 12 }, (_, j) => `zp${j}`);
  const dotB = (coeffs) => { const ts = coeffs.map((c, j) => c === 0n ? null : `${c} * ${zp[j]}`).filter(Boolean); return ts.length ? ts.join(' + ') : '0'; };
  for (let k = 0; k < 12; k++) L.push(`        int ec${k} = (${dotB(EZCOLS[k])}) % P;`);
  for (let s = 0; s < 6; s++) L.push(`        int ex${s} = (${dotB(E6[s])}) % P;`);
  if (needP12) L.push('        int P12z = (zp6 * zp6 + P - (18 * zp6) % P + 82) % P;'); // z^12 - 18 z^6 + 82
  if (needFab) L.push(`        int fABz = (${FAB_L.map((v, k) => v === 0n ? null : `${v} * ec${k}`).filter(Boolean).join(' + ')}) % P;`);
}
// does the step window [lo,hi) contain any alpha_beta (fab) factor? (only the last step does)
function windowHasFab(lo, hi) { for (let i = lo; i < hi; i++) if (stepFactorSpec(t, i).some((f) => f.kind === 'fab')) return true; return false; }
const ecN = Array.from({ length: 12 }, (_, k) => `ec${k}`);
const dotEc = (names) => `(${names.map((n, k) => `${n} * ec${k}`).join(' + ')}) % P`;   // 12-term <names, ec>
const dotEcBaked = (limbs) => `(${limbs.map((v, k) => v === 0n ? null : `${v} * ec${k}`).filter(Boolean).join(' + ')}) % P`;

// 6-term line z-eval given coeff EXPRESSIONS (c0a..c2b) and point exprs (Px,Py).
const lineFz = (c0a, c0b, c1a, c1b, c2a, c2b, Px, Py) =>
  `( mulFp(mulFp(${c2a}, ${Py}), ex0) + mulFp(mulFp(${c2b}, ${Py}), ex1) + mulFp(mulFp(${c1a}, ${Px}), ex2) + mulFp(mulFp(${c1b}, ${Px}), ex3) + mulFp(${c0a}, ex4) + mulFp(${c0b}, ex5) ) % P`;

// ---- emit one step's factor recompute + aggregation into the running (pf, aggL, aggF, gp, finZcur) ----
// r0[] = current affine R names (advanced by var lines). Returns updated r0. `uid` object for SSA.
function emitStep(L, i, r0, uid, isLastStep, ctx = { debake: false }) {
  const spec = stepFactorSpec(t, i);
  const fresh = (n) => Array.from({ length: n }, () => `v${uid.n++}`);
  const PxOf = { 0: 'nAx', 2: 'vkxX', 3: 'Cx' }, PyOf = { 0: 'nAy', 2: 'vkxY', 3: 'Cy' };
  const pf = `pf${i}`;
  // DE-BAKE (channel B): the final step's var-pp adds use the frobenius end-points psi(B)/-psi^2(B).
  // These were baked as B-derived literals (instance-specific => runtimeGeneral fails). The subgroup
  // fold below ALREADY computes the psi chain on-chain from the witnessed B (q1=psi(B), q2=psi^2(B),
  // q3=psi^3(B)); we hoist it here so the pp adds consume q1 / (q2.x,-q2.y) as operands instead of the
  // literals. B is a witnessed param => the finalize redeem is now proof-independent (soundness
  // unchanged: the psi tie R_end==-psi^3(B) still binds R to the on-chain psi chain).
  if (isLastStep && ctx.debakePP) {
    L.push('        (int q1xa,int q1xb,int q1ya,int q1yb) = psi(Bxa, Bxb, Bya, Byb);');
    L.push('        (int q2xa,int q2xb,int q2ya,int q2yb) = psi(q1xa, q1xb, q1ya, q1yb);');
    L.push('        (int q3xa,int q3xb,int q3ya,int q3yb) = psi(q2xa, q2xb, q2ya, q2yb);');
    L.push('        (int nq2ya, int nq2yb) = fp2Neg(q2ya, q2yb, 64);');
    L.push('        (int nq3ya, int nq3yb) = fp2Neg(q3ya, q3yb, 64);');
    ctx._psiDone = true;
  }
  L.push(`        int ${pf} = 1;`);
  spec.forEach((f, k) => {
    if (f.kind === 'cfold') { L.push(`        ${pf} = mulFp(${pf}, ${dotEc(f.useC ? CN : CIN)});`); return; }
    if (f.kind === 'fab') { L.push(`        ${pf} = mulFp(${pf}, fABz);`); return; }
    if (f.kind === 'fixline' && ctx.debake) {
      // DE-BAKE: recompute the fixed-pair line coeffs ON-CHAIN via the deployed affDbl/affAdd from
      // the baked affine slope lam (ctx-supplied, consensus-fixed) + the on-chain-advanced fixed T
      // trajectory (Tg=pair2/gamma, Td=pair3/delta; seeded from the baked window-start T). The slope
      // require in affDbl/affAdd re-binds lam<->T on-chain (a wrong lam REJECTS: A1). No coeff literals.
      const T = f.pair === 2 ? ctx.Tg : ctx.Td;
      const Q = f.pair === 2 ? GAMMA_Q : DELTA_Q;
      const la = `fl${ctx.lc}a`, lb = `fl${ctx.lc}b`; ctx.lc++;
      const co = fresh(6), nt = fresh(4);
      const lit = (x) => mod(x).toString();
      if (f.op === 'dl') L.push(`        (${decl([...co, ...nt])}) = affDbl(${T.join(',')}, ${la}, ${lb});`);
      else {
        const Qy = f.neg ? [lit(mod(P - Q[2])), lit(mod(P - Q[3]))] : [lit(Q[2]), lit(Q[3])];
        L.push(`        (${decl([...co, ...nt])}) = affAdd(${T.join(',')}, ${lit(Q[0])}, ${lit(Q[1])}, ${Qy[0]}, ${Qy[1]}, ${la}, ${lb});`);
      }
      const fz = lineFz(co[0], co[1], co[2], co[3], co[4], co[5], PxOf[f.pair], PyOf[f.pair]);
      L.push(`        ${pf} = mulFp(${pf}, ${fz});`);
      T.splice(0, 4, ...nt);
      return;
    }
    if (f.kind === 'fixline' || f.kind === 'fixpp') {
      const c = f.coeffs; const lit = (x) => mod(x).toString();
      const fz = lineFz(lit(c[0].c0), lit(c[0].c1), lit(c[1].c0), lit(c[1].c1), lit(c[2].c0), lit(c[2].c1), PxOf[f.pair], PyOf[f.pair]);
      L.push(`        ${pf} = mulFp(${pf}, ${fz});`); return;
    }
    // var-G2 (pair0): recompute the line coeffs on-chain via affDbl / affAdd (slope-bound to R)
    const sa = `s${i}_${k}a`, sb = `s${i}_${k}b`;
    const co = fresh(6), nr = fresh(4);
    if (f.kind === 'varline') {
      if (f.op === 'dl') L.push(`        (${decl([...co, ...nr])}) = affDbl(${r0.join(',')}, ${sa}, ${sb});`);
      else { // al: add pair0's Q=(Bxa..) with y possibly negated
        const Y = f.neg ? negBy(L, uid) : ['Bya', 'Byb'];
        L.push(`        (${decl([...co, ...nr])}) = affAdd(${r0.join(',')}, Bxa, Bxb, ${Y[0]}, ${Y[1]}, ${sa}, ${sb});`);
      }
    } else if (isLastStep && ctx.debakePP) { // DE-BAKED var-pp: on-chain psi add-point (q1 / -q2), witnessed slope
      const add = f.ppLine === 0 ? ['q1xa', 'q1xb', 'q1ya', 'q1yb'] : ['q2xa', 'q2xb', 'nq2ya', 'nq2yb'];
      L.push(`        (${decl([...co, ...nr])}) = affAdd(${r0.join(',')}, ${add.join(', ')}, ${sa}, ${sb});`);
    } else { // varpp: affAdd with the psi add-point (baked psi coords), witnessed slope
      const q = f.q; const lit = (x) => mod(x).toString();
      L.push(`        (${decl([...co, ...nr])}) = affAdd(${r0.join(',')}, ${lit(q[0].c0)}, ${lit(q[0].c1)}, ${lit(q[1].c0)}, ${lit(q[1].c1)}, ${sa}, ${sb});`);
    }
    const fz = lineFz(co[0], co[1], co[2], co[3], co[4], co[5], 'nAx', 'nAy');
    L.push(`        ${pf} = mulFp(${pf}, ${fz});`);
    r0.splice(0, 4, ...nr);
  });
  // subgroup fold: after the final step's var pp (2 psi-adds) R_end == -psi^3(B). Enforced in final only.
  if (isLastStep) emitSubgroupFold(L, r0, uid, !!ctx._psiDone);
  return r0;
}
// negate pair0 Q y (=B y) for al steps: fp2Neg(Bya,Byb,64) -> (nqa,nqb)
function negBy(L, uid) { const n = [`nq${uid.n}a`, `nq${uid.n}b`]; uid.n++; L.push(`        (int ${n[0]}, int ${n[1]}) = fp2Neg(Bya, Byb, 64);`); return n; }
// T5-1 subgroup membership fold: R_end (=r0) == -psi^3(B). Bound to on-twist B (checked upstream).
function emitSubgroupFold(L, r0, uid, psiDone = false) {
  const Pm = Pstr;
  if (!psiDone) {
    // stock path: compute the psi chain here (de-bake hoists it into emitStep and sets psiDone).
    L.push('        (int q1xa,int q1xb,int q1ya,int q1yb) = psi(Bxa, Bxb, Bya, Byb);');
    L.push('        (int q2xa,int q2xb,int q2ya,int q2yb) = psi(q1xa, q1xb, q1ya, q1yb);');
    L.push('        (int q3xa,int q3xb,int q3ya,int q3yb) = psi(q2xa, q2xb, q2ya, q2yb);');
    L.push('        (int nq3ya, int nq3yb) = fp2Neg(q3ya, q3yb, 64);');
  }
  L.push(`        require(${r0[0]} == q3xa % ${Pm}); require(${r0[1]} == q3xb % ${Pm});`);
  L.push(`        require(${r0[2]} == nq3ya % ${Pm}); require(${r0[3]} == nq3yb % ${Pm});`);
}

// ---- statement + chain[0] absorb (genesis only) ----
function emitGenesisAbsorb(L) {
  // A = -(negA): (nAx, P-nAy). B,C,vkx from ptParams; alpha/beta/gamma/delta baked; c,cInv,w witnessed.
  L.push('        int Ax = nAx; int Ay = (P - nAy) % P;');
  const be = (e) => `toPaddedBytes(${e}, 32).reverse()`;
  const lit = (v) => `${mod(v)}`;
  // L1-7 coset-selector: w in {ONE,ROOT27,ROOT27^2} is a 3-class residue coset element. Grinding proof
  // randomness gives w=1 ~1/3 of the time (measured 18/61); the residue TAIL relation self-checks w, so
  // the FS transcript only needs to BIND the class, not the full 12 limbs. Absorb a 1-byte coset selector
  // wsel (0/1/2) instead of the 12 w-limbs. Binding preserved (wsel uniquely -> w). Env L17SEL toggles.
  const wTerms = process.env.L17SEL ? [be('wsel')] : Array.from({ length: 12 }, (_, k) => be(`w${k}`));
  const stmtTerms = [
    be('Ax'), be('Ay'), be('Bxa'), be('Bxb'), be('Bya'), be('Byb'), be('Cx'), be('Cy'), be('vkxX'), be('vkxY'),
    be(lit(VK_AL[0])), be(lit(VK_AL[1])), ...VK_BE.map((v) => be(lit(v))), ...VK_GA.map((v) => be(lit(v))), ...VK_DE.map((v) => be(lit(v))),
    ...CN.map(be), ...CIN.map(be), ...wTerms,
  ];
  L.push(`        bytes stmtBlock = ${balancedCat(stmtTerms)};`);
  L.push(`        bytes h = hash256(0x${H0_HEX} + 0x00000000 + 0x${BE4_STMT} + stmtBlock);`);   // block 0 (index 0)
  // chain[0] = cInv (canonical genesis). absorb as block index 1 (be4(1)).
  L.push(`        bytes ris0 = ${balancedCat(CIN.map(be))};`);
  L.push(`        h = hash256(h + 0x00000001 + 0x${BE4_384} + ris0);`);                         // block index 1
}
// absorb a fout (chain[i+1]) named foutNames(i) at block index (i+2)
function emitFoutAbsorb(L, i) {
  const be = (e) => `toPaddedBytes(${e}, 32).reverse()`;
  const blk = balancedCat(foutNames(i).map(be));
  L.push(`        h = hash256(h + 0x${be4hex(i + 2)} + 0x${BE4_384} + ${blk});`);
}

// local balanced OP_CAT (byte-identical to a left fold; O(n log n) VM copies)
function balancedCat(terms) { if (terms.length === 1) return terms[0]; const m = terms.length >> 1; return `(${balancedCat(terms.slice(0, m))} + ${balancedCat(terms.slice(m))})`; }

// ================= genChunk =================
export function genChunk(stepLo, stepHi, isFinal, isGenesis, succSpk = null, opts = {}) {
  const debake = !!opts.debake;   // moonshot-v2: recompute fixed lines on-chain from baked lam + adv T
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB}";`);
  L.push('contract SzMillerChunk() {');
  // spend params: threaded state + per-step witnesses (+ genesis extras / final bigQ)
  const stepWit = [];
  for (let i = stepLo; i < stepHi; i++) { stepWit.push(...foutNames(i), ...stepSlopeNames(i)); }
  // de-bake: fixed-line lambdas + fixed-T window-starts arrive as EXTRA params (consensus-fixed, later
  // sourced from the hash-pinned library slice; here they measure the generic code + drive the VM run).
  const fixData = debake ? debakeParams(stepLo, stepHi) : [];
  // sr-reconstruct-sz63 (Strategy A): the FINALIZE stage consumes the gb3 32-limb SGB interior aggregate
  // (dotC/dotCi + validated points, NO raw c/cInv) instead of the 45-limb SZ state. c/cInv are RE-WITNESSED
  // fresh and bound by <c,e(z)>==dotC && <cInv,e(z)>==dotCi (Schwartz-Zippel); blkidx/Tg/Td are pinned to
  // their consensus constants (real checks, so no unused-param reject). SGB_NAMES == gb3 SGB order, using
  // SZ-body-compatible identifiers (gammaW=gamma, zW=z, finZseam=fC) so the existing finalize body is reused.
  const sgbSeam = !!opts.sgbSeam && isFinal;
  const SGB_NAMES = ['gammaW', 'zW', 'blkidx', 'hInt', 'aggL', 'aggF', 'gp', 'finZseam',
    'nAx', 'nAy', 'vkxX', 'vkxY', 'Cx', 'Cy', 'Bxa', 'Bxb', 'Bya', 'Byb',
    'Rxa', 'Rxb', 'Rya', 'Ryb', 'Tgxa', 'Tgxb', 'Tgya', 'Tgyb', 'Tdxa', 'Tdxb', 'Tdya', 'Tdyb', 'dotC', 'dotCi'];
  let params;
  if (isGenesis) {
    // genesis binds ONLY ptParams (=ecipSEAM2); c,cInv,gammaW,zW,w fresh; R,hInt,agg*,gp,finZseam init.
    const wNames = process.env.L17SEL ? ['wsel'] : Array.from({ length: 12 }, (_, k) => `w${k}`);
    params = [...PT, ...CN, ...CIN, 'gammaW', 'zW', ...wNames, ...stepWit, ...fixData];
  } else if (sgbSeam && opts.sgbConsume) {
    // DIRECT-PORT: SGB_NAMES are NOT pushed params — they are split out of `bytes seamFront` (declared last).
    params = [...CN, ...CIN, ...stepWit, ...fixData];   // c/cInv re-witnessed; SGB state via seamFront blob
  } else if (sgbSeam) {
    params = [...SGB_NAMES, ...CN, ...CIN, ...stepWit, ...fixData];   // c/cInv re-witnessed (NOT covIn-committed)
  } else {
    params = [...STATE, ...stepWit, ...fixData];   // big_Q is NOT here — it lives only in the terminal CLOSE chunk
  }
  // D11: `opts.noPad` drops the op-financing zeroPadding param (genesis/finalize are byte-bound, NOT
  // op-bound — their op is ~1.2-1.5M vs a ~6-7M budget — so the 200-B pad is pure waste). Default keeps
  // it for back-compat with op-bound covenant consumers (unified_affine etc).
  // rg-build (1-tx real-genesis) port: the fused single-tx front-pushes the interior gb3 final-state
  // into genesis's unlock (interior exec8 pins genesis.unlock[3..3+STATE_BYTES]==gb3state). Genesis must
  // CONSUME that leading push (else clean-stack rejects the leftover). `seamConsume` adds `bytes seamFront`
  // as genesis's LAST-declared param (=> stack bottom => unlock front) and require's its length.
  const seamOn = isGenesis && opts.seamConsume;
  const seamDecl = seamOn ? ', bytes seamFront' : '';
  // DIRECT-PORT (channel A): the FINALIZE stage consumes its incoming SGB state as a tokenless SIBLING
  // blob (`bytes seamFront`, the interior gb3 serialization, forward-pinned by genesis) EXACTLY like the
  // interior execs consume their `bytes inBlob` — no incoming NFT covenant. seamFront is the FIRST-declared
  // param (=> unlock front) so genesis can pin it via `.split(3)[1].split(seamBytes)[0]`.
  const dpConsume = sgbSeam && !!opts.sgbConsume;
  // seamFront is the LAST-declared param (== unlock FRONT / stack bottom, same convention as genesis's
  // seamConsume) so genesis's forward-pin `.split(3)[1].split(seamBytes)[0]` reads exactly this blob.
  const dpSeamDecl = dpConsume ? ', bytes seamFront' : '';
  L.push(`    function spend(${decl(params)}${opts.noPad ? '' : ', bytes unused zeroPadding'}${seamDecl}${dpSeamDecl}) {`);
  if (seamOn) {
    L.push(`        require(seamFront.length == ${opts.seamBytes});`);
    if (opts.seamPtSer) L.push(`        require(seamFront.split(${opts.seamPtBytes})[0] == ${opts.seamPtSer});`);
  }
  if (dpConsume) {
    // split seamFront into the 32 SGB limbs (interior gb3 widths) — the tokenless state carriage.
    const W = opts.sgbWidths;
    L.push(`        require(seamFront.length == ${opts.seamBytes});`);
    let cur = 'seamFront';
    SGB_NAMES.forEach((nm, p) => {
      if (p === SGB_NAMES.length - 1) { L.push(`        int ${nm} = int(${cur});`); }
      else { L.push(`        bytes sf${p}, bytes sfr${p} = ${cur}.split(${W[p]}); int ${nm} = int(sf${p});`); cur = `sfr${p}`; }
    });
  }
  // covenant input binding
  if (isGenesis) L.push(covIn(PT));
  else if (dpConsume) { /* tokenless: state came from seamFront (genesis forward-pins it) — no covIn */ }
  else if (sgbSeam) L.push(covIn(SGB_NAMES));   // token commits the gb3 32-limb SGB interior aggregate@stepLo
  else L.push(covIn(STATE));
  prologue(L, 'zW', false, windowHasFab(stepLo, stepHi)); // z==zW; P12z lives only in the CLOSE chunk; fABz iff fab window
  const gName = 'gammaW', zName = 'zW';
  const uid = { n: 0 };
  // de-bake context: threaded fixed-T (Tg=pair2, Td=pair3) seeded from the window-start params; a
  // global lambda counter (lc) consumed in spec order across the window (matches debakeParams order).
  const ctx = { debake, debakePP: !!opts.debakePP, Tg: ['Tgxa', 'Tgxb', 'Tgya', 'Tgyb'], Td: ['Tdxa', 'Tdxb', 'Tdya', 'Tdyb'], lc: 0 };
  let r0;
  if (isGenesis) {
    L.push('        require(gammaW < P); require(zW < P);');            // canonical FS challenges
    r0 = ['Bxa', 'Bxb', 'Bya', 'Byb'];                                 // pin R = B (affine ladder start)
    emitGenesisAbsorb(L);
    L.push('        int aL = 0; int aF = 0; int gP = 1;');
    L.push(`        int fC = ${dotEc(CIN)};`);                          // finZ_0 = <cInv, e(z)> (chain[0]=cInv)
  } else {
    r0 = RN.slice();
    L.push('        bytes h = toPaddedBytes(hInt, 33).split(32)[0];');  // reconstruct running-h (33-split)
    L.push('        int aL = aggL; int aF = aggF; int gP = gp; int fC = finZseam;');
  }
  if (sgbSeam) {
    // (1) c/cInv Schwartz-Zippel bind: pin the re-witnessed constant residue to the gb3-threaded z-evals.
    //     <c,e(z)>==dotC && <cInv,e(z)>==dotCi (z is a transcript-bound FS challenge). c/cInv are NOT
    //     trajectory state — they are the constant final-exp residue, re-witnessed here (same available
    //     constants as at genesis; the tail also re-witnesses + binds them via ccff2==ccff, cc^-1==1, Frob).
    L.push(`        require(${dotEc(CN)} == dotC);`);
    L.push(`        require(${dotEc(CIN)} == dotCi);`);
    // (2) pin the remaining non-body SGB limbs to their consensus constants (real checks; also consumes the
    //     params so the vendored fork does not reject them as unused). blkidx==stepLo+2 pins the step index;
    //     Tg/Td are the fixed-pair (gamma/delta) affine ladder points at the window start (consensus-fixed).
    L.push(`        require(blkidx == ${stepLo + 2});`);
    const eTg = _Tg[stepLo], eTd = _Td[stepLo]; const litm = (x) => mod(x).toString();
    ['Tgxa', 'Tgxb', 'Tgya', 'Tgyb'].forEach((nm, ix) => L.push(`        require(${nm} % P == ${litm(eTg[ix])});`));
    ['Tdxa', 'Tdxb', 'Tdya', 'Tdyb'].forEach((nm, ix) => L.push(`        require(${nm} % P == ${litm(eTd[ix])});`));
  }
  // process the window's steps
  for (let i = stepLo; i < stepHi; i++) {
    const last = isFinal && i === stepHi - 1;
    r0 = emitStep(L, i, r0, uid, last, ctx);
    L.push(`        int fn${i} = ${dotEc(foutNames(i))};`);             // finZ_{i+1} = <chain[i+1], e(z)>
    L.push(`        aL = (aL + gP * ( ((fC*fC)%P) * pf${i} )%P ) % P;`); // aggL += gp*(finZ_i^2 * prodFactor_i)
    L.push(`        aF = (aF + gP * fn${i}) % P;`);                     // aggF += gp*finZ_{i+1}
    L.push(`        gP = (gP * ${gName}) % P;`);
    emitFoutAbsorb(L, i);                                              // absorb chain[i+1] (Ris) into running-h
    L.push(`        fC = fn${i};`);
  }
  // de-bake: BIND the on-chain-advanced fixed-T at the window end to its known (consensus) trajectory
  // point. This (a) consumes the final T SSA (fork rejects unused locals) and (b) is an A1 check — a
  // tampered lambda diverges the T-advance => this require FAILS => REJECT. Interior windows only (the
  // terminal pp step keeps baked coeffs / no on-chain T-advance).
  if (debake && !isFinal) {
    const endTg = _Tg[stepHi], endTd = _Td[stepHi]; const lit = (x) => mod(x).toString();
    ctx.Tg.forEach((nm, ix) => L.push(`        require(${nm} % P == ${lit(endTg[ix])});`));
    ctx.Td.forEach((nm, ix) => L.push(`        require(${nm} % P == ${lit(endTd[ix])});`));
  }
  if (isFinal) {
    // FINALIZE rolling-h -> gamma ; require witnessed gammaW == derived (count-bound). The big_Q-heavy
    // phase-2 z + Horner + identity close is DEFERRED to the terminal CLOSE chunk (genCloseChunk) to
    // keep this chunk's redeem+unlock under the 10,000-B cap. Thread the compact 40-limb close-state.
    L.push(`        h = hash256(h + 0x${TAGFIN_HEX} + 0x${be4hex(BLOCKCOUNT)});`);
    L.push(`        require(${gName} == int(h.reverse() + 0x00) % P);`);
    const fF = foutNames(stepHi - 1);                          // fF = chain[last] = boundary (witnessed, hash-bound)
    L.push('        ' + fF.map((n) => `require(${n} < P);`).join(' ')); // canonicalize boundary for the tail seam
    if (opts.ccff) {
      // D11 forward-compress: fF/c/cInv are NEVER computed on by the CLOSE chunk — it only FORWARDS
      // them to the residue tail. Bind them into ONE digest ccff = hash256(le40(fF)|le40(c)|le40(cInv))
      // (finalize already serialized these 36 limbs for the old 40-limb covOut, so this is the same hash)
      // and thread only [aggL,aggF,gamma,z,ccff] (5). CLOSE covIn then pushes 5 seam limbs, not 40 (−35
      // limbs ≈ −1.8 kB). SOUND: the SZ identity (gamma,z,aggL,aggF,bigQ) is untouched; fF/c/cInv stay
      // hash-bound end-to-end (finalize commits ccff; close forwards it; the tail re-witnesses fF/c/cInv
      // and checks hash256(le40(fF,c,cInv))==ccff before its fF verdict).
      L.push(`        int ccff = int(${serExpr([...fF, ...CN, ...CIN])} + 0x00);`);
      // SF1-K (T6): collapse the two accumulators to accD=(aggL-aggF) mod P (aL,aF each kept %P per step,
      // so accD lands in [0,P)). close then checks accD == bqz*P12z, dropping the aggF seam limb.
      L.push('        int accD = (aL + P - aF) % P;');
      // ccff is a RAW hash-int (may exceed P) — mark canonical so covOut serializes it toPaddedBytes(ccff,40)
      // WITHOUT %Pmod (same handling as the running-h hOut). accD/gamma/z are canonical covIn-derived limbs.
      if (dpConsume) {
        // DIRECT-PORT (channel A): forward-pin the close-seam to the FUSED successor's tokenless witness
        // front (interior forward-pin form) instead of committing it to the fused NFT. closeBlob is the
        // 4x40-byte serialization the fused input carries as its `bytes seamFront`. Also pin the successor
        // contract (P2SH32) so the state cannot be routed to a rogue redeem.
        L.push(`        bytes closeBlob = toPaddedBytes(accD, 40) + toPaddedBytes(${gName}, 40) + toPaddedBytes(${zName}, 40) + toPaddedBytes(ccff, 40);`);
        // fused's 160-byte seamFront pushes via OP_PUSHDATA1 (2-byte prefix), NOT PUSHDATA2 (3-byte) like the
        // 1032-byte interior/genesis blobs — so strip 2, not 3, before reading the close-seam.
        L.push(`        require(closeBlob == tx.inputs[this.activeInputIndex + 1].unlockingBytecode.split(2)[1].split(160)[0]);`);
        if (succSpk) {
          const fhex = typeof succSpk === 'string' ? succSpk : Buffer.from(succSpk).toString('hex');
          L.push(`        require(tx.inputs[this.activeInputIndex + 1].lockingBytecode == 0x${fhex});`);
        }
      } else {
        L.push(covOut(['accD', gName, zName, 'ccff'], succSpk, new Set(['accD', gName, zName, 'ccff'])));
      }
    } else {
      // covOut = CLOSE_IN (40) = [fF, c, cInv, aggL, aggF, gamma, z] -> the terminal CLOSE chunk (genCloseChunk).
      L.push(covOut([...fF, ...CN, ...CIN, 'aL', 'aF', gName, zName], succSpk, new Set([...CN, ...CIN, ...fF])));
    }
  } else if (opts.sgbSeamGenesis) {
    // sr-reconstruct-sz63 (Strategy A) GENESIS: this stage sits DOWNSTREAM of the gb3 interior (exec8's
    // forward-pin binds seamFront == interior SGB state@last). It (a) HEAD-BINDS its own absorb+step0 result
    // state@1 to the interior head exec0's start-state (so the FS transcript origin — statement + vkx point +
    // proof pts + c/cInv — is genuine), and (b) re-emits the consumed interior SGB aggregate@last as its
    // covOut (commit at 40-byte width == the finalize covIn token), chaining genesis -> finalize.
    L.push('        int hOut = int(h + 0x00);');
    // sr-reconstruct-sz63: A(=nA)/C on-curve checks relocated here from vkx (op-offload; genesis is byte-bound,
    // and its covIn(PT)==vkx cross-pinned seam2 commits the same nAx/nAy/Cx/Cy => sound). y^2 == x^3 + 3.
    L.push('        require((nAy * nAy) % P == ((((nAx * nAx) % P) * nAx) % P + 3) % P);');
    L.push('        require((Cy * Cy) % P == ((((Cx * Cx) % P) * Cx) % P + 3) % P);');
    // PT-coord canonicality (< P) for the seam2 limbs whose % Pmod vkx dropped (op-offload; genesis commits
    // the same raw PT via covIn, so the vkx cross-pin now matches raw-against-raw — full canonicality kept).
    (opts.sgbRangeCoords ?? []).forEach((n) => L.push(`        require(${n} >= 0); require(${n} < P);`));
    if (opts.sgbGenB) {
      // B (twist E'(Fp2)) on-curve: By^2 == Bx^3 + b' (i^2=-1). Relocated from vkx (op-offload for density fit).
      const B2a = '19485874751759354771024239261021720505790618469301721065564631296452457478373';
      const B2b = '266929791119991161246907387137283842545076965332900288569378510910307636690';
      L.push('        int bxx = (Bxa * Bxa) % P; int bxy = (Bxb * Bxb) % P;');
      L.push('        int bx0 = (bxx + P - bxy) % P; int bx1 = (((Bxa + Bxb) * (Bxa + Bxb)) % P + 2*P - bxx - bxy) % P;');
      L.push('        int bc0 = ((bx0 * Bxa) % P + P - (bx1 * Bxb) % P) % P;');
      L.push('        int bc1 = (((bx0 + bx1) * (Bxa + Bxb)) % P + 2*P - (bx0 * Bxa) % P - (bx1 * Bxb) % P) % P;');
      L.push(`        int br0 = (bc0 + ${B2a}) % P; int br1 = (bc1 + ${B2b}) % P;`);
      L.push('        int byy = (Bya * Bya) % P; int byz = (Byb * Byb) % P;');
      L.push('        int by0 = (byy + P - byz) % P; int by1 = (((Bya + Byb) * (Bya + Byb)) % P + 2*P - byy - byz) % P;');
      L.push('        require(by0 == br0); require(by1 == br1);');
    }
    const NW = Number(opts.sgbNarrowW ?? 32);
    const w = (p) => (p === 3 ? 40 : NW);   // gb3 stateW: hInt(idx3) raw 40, rest narrowed
    // (a) HEAD-BIND: recompute the gb3-format state@1 blob (SGB order) and require it == exec0's start.
    L.push(`        int dotC = ${dotEc(CN)}; int dotCi = ${dotEc(CIN)};`);
    const eTg1 = _Tg[stepHi], eTd1 = _Td[stepHi]; const litm = (x) => mod(x).toString();
    // SGB order: gamma,z,blkidx,hInt,aggL,aggF,gp,fC, nAx,nAy,vkxX,vkxY,Cx,Cy,Bxa,Bxb,Bya,Byb, R,Tg,Td, dotC,dotCi
    const bx = (expr, p, raw) => `toPaddedBytes(${raw ? expr : `${expr} % P`}, ${w(p)})`;
    const headTerms = [
      bx(gName, 0), bx(zName, 1), bx(String(stepHi + 2), 2), bx('hOut', 3, true),
      bx('aL', 4), bx('aF', 5), bx('gP', 6), bx('fC', 7),
      bx('nAx', 8), bx('nAy', 9), bx('vkxX', 10), bx('vkxY', 11), bx('Cx', 12), bx('Cy', 13),
      bx('Bxa', 14), bx('Bxb', 15), bx('Bya', 16), bx('Byb', 17),
      bx(r0[0], 18), bx(r0[1], 19), bx(r0[2], 20), bx(r0[3], 21),
      bx(litm(eTg1[0]), 22), bx(litm(eTg1[1]), 23), bx(litm(eTg1[2]), 24), bx(litm(eTg1[3]), 25),
      bx(litm(eTd1[0]), 26), bx(litm(eTd1[1]), 27), bx(litm(eTd1[2]), 28), bx(litm(eTd1[3]), 29),
      bx('dotC', 30), bx('dotCi', 31),
    ];
    L.push(`        bytes head1 = ${balancedCat(headTerms)};`);
    L.push(`        require(head1 == tx.inputs[1].unlockingBytecode.split(3)[1].split(${opts.seamBytes})[0]);`);
    const shex = succSpk ? (typeof succSpk === 'string' ? succSpk : Buffer.from(succSpk).toString('hex')) : null;
    if (opts.sgbForwardDirect) {
      // The final executor binds its state directly to FINALIZE's witness front. GENESIS
      // retains only the successor lock pin; no duplicate state blob is required here.
      if (shex) L.push(`        require(tx.inputs[this.activeInputIndex + 1].lockingBytecode == 0x${shex});`);
    } else if (opts.sgbForward) {
      // DIRECT-PORT (channel A): forward-pin the consumed interior SGB aggregate@last (seamFront) straight
      // through to the FINALIZE successor's tokenless witness front — the SAME gb3-narrow serialization the
      // interior threads (no re-widening, no NFT). This is the interior forward-pin (gb3_9k7:127) applied to
      // the genesis->finalize edge: predecessor pins successor's witness bytes. Also pin the successor contract.
      L.push(`        require(seamFront == tx.inputs[this.activeInputIndex + 1].unlockingBytecode.split(3)[1].split(${opts.seamBytes})[0]);`);
      if (shex) L.push(`        require(tx.inputs[this.activeInputIndex + 1].lockingBytecode == 0x${shex});`);
    } else {
      // (b) re-emit the consumed interior SGB aggregate@last (seamFront) as covOut, widened 40B, -> finalize.
      let cur = 'seamFront'; const qn = [];
      const SGB_W = Array.from({ length: 32 }, (_, p) => w(p));
      SGB_W.forEach((ww, p) => {
        if (p === SGB_W.length - 1) { L.push(`        int q${p} = int(${cur});`); }        // last limb == remainder (no unused split tail)
        else { L.push(`        bytes sh${p}, bytes sr${p} = ${cur}.split(${ww}); int q${p} = int(sh${p});`); cur = `sr${p}`; }
        qn.push(`q${p}`);
      });
      const outTerms = qn.map((n) => `toPaddedBytes(${n}, 40)`);
      L.push(`        require(tx.inputs[this.activeInputIndex + 1].nftCommitment == hash256(${balancedCat(outTerms)}));`);
      L.push('        require(tx.inputs[this.activeInputIndex + 1].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);');
      if (shex) L.push(`        require(tx.inputs[this.activeInputIndex + 1].lockingBytecode == 0x${shex});`);
    }
  } else {
    // covOut threaded 45-limb state (hInt canonical: raw 40-byte LE, NOT %Pmod-reduced)
    L.push('        int hOut = int(h + 0x00);');
    const outNames = [...PT, ...CN, ...CIN, ...r0, 'hOut', 'aL', 'aF', 'gP', gName, 'zW', 'fC'];
    const canon = new Set([...PT, ...CN, ...CIN, 'hOut']);
    L.push(covOut(outNames, succSpk, canon));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- CLOSE (terminal SZ) chunk: consumes the 40-limb close-state, verifies phase-2 z, Horner
// big_Q, and the aggregated identity; emits covOut = tailState36 = [fF, c, cInv] to the residue tail.
// Isolating big_Q (103 coeffs, used in BOTH the z-hash and the Horner) here keeps every chunk under
// the 10,000-B cap. fF/c/cInv are covIn-bound (canonical, threaded from the finalize chunk).
const FFN = Array.from({ length: 12 }, (_, i) => `fF${i}`);
export const CLOSE_IN = [...FFN, ...CN, ...CIN, 'aggLf', 'aggFf', 'gammaf', 'zf']; // 40
// D11 forward-compress: the close chunk NEVER computes with fF/c/cInv — it only re-hashes them for its
// covOut to the tail. Replace those 36 seam limbs with one digest ccff (built by finalize). CLOSE covIn
// then pushes 5 seam limbs, not 40 (−35 limbs ≈ −1.8 kB of witness).
// SF1-K (T6): single-accumulator form accDf=(aggL-aggF) mod P drops the aggFf seam limb. 4 limbs, not 5.
export const CLOSE_IN_C = ['accDf', 'gammaf', 'zf', 'ccff']; // 4
export function genCloseChunk(succSpk = null, opts = {}) {
  const compress = !!opts.compress;
  const loop = !!opts.loop;   // L5-3B: OP_BEGIN/OP_UNTIL fold of the unrolled Horner big_Q driver
  const SEAM = compress ? CLOSE_IN_C : CLOSE_IN;
  const bqNames = Array.from({ length: BIGQ.length }, (_, k) => `bq${k}`);
  const be = (e) => `toPaddedBytes(${e}, 32).reverse()`;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push('contract SzMillerClose() {');
  // L5-3B: big_Q arrives as ONE bytes blob (bqBlob = cat_k be32(bq_k), byte-identical to the
  // unrolled zpay preimage) instead of 103 int params. The Horner is then a do/while over 32-byte
  // limbs peeled off the tail (highest coeff first) — one loop body replaces 102 unrolled lines.
  const bqDecl = loop ? `${decl(SEAM)}, bytes bqBlob` : decl([...SEAM, ...bqNames]);
  L.push(`    function spend(${bqDecl}${opts.noPad ? '' : ', bytes unused zeroPadding'}) {`);
  L.push(covIn(SEAM));
  L.push(`        int P = ${Pstr};`);
  // z-powers for P12z: z^2, z^4, z^6, z^12
  L.push('        int z2 = (zf*zf)%P; int z4=(z2*z2)%P; int z6=(z4*z2)%P; int z12=(z6*z6)%P;');
  L.push('        int P12z = (z12 + P - (18*z6)%P + 82) % P;');
  // PHASE 2: z = int(hash256(TAG_Z || be32(gamma) || big_Q)) ; require threaded zf == derived
  const bqPre = loop ? 'bqBlob' : balancedCat(bqNames.map(be));
  L.push(`        bytes zpay = 0x${TAGZ_HEX} + toPaddedBytes(gammaf, 32).reverse() + ${bqPre};`);
  L.push('        require(zf == int(hash256(zpay).reverse() + 0x00) % P);');
  if (loop) {
    // Horner big_Q(z) via a bounded do/while: peel the last 32-byte limb (highest remaining coeff)
    // off `rest`, fold it in, until the blob is exhausted. bqz starts 0 so the first fold sets it to
    // the top coeff (0*z + c_top). big_Q has BIGQ.length coeffs => the loop runs exactly that many times.
    L.push('        int bqz = 0; bytes rest = bqBlob; bytes lo = 0x;');
    L.push('        do {');
    L.push('            (rest, lo) = rest.split(rest.length - 32);');
    L.push('            bqz = (bqz * zf + int(lo.reverse())) % P;');
    L.push('        } while (rest.length > 0);');
  } else {
    // Horner big_Q(z) ; identity aggL == bigQz*P12z + aggF
    L.push(`        int bqz = ${bqNames[BIGQ.length - 1]};`);
    for (let k = BIGQ.length - 2; k >= 0; k--) L.push(`        bqz = (bqz * zf + ${bqNames[k]}) % P;`);
  }
  if (compress) {
    // SF1-K: single-accumulator form of the aggregated SZ identity (accDf = aggL - aggF mod P).
    L.push('        require(accDf % P == (bqz * P12z) % P);');
  } else {
    L.push('        int rhs = ((bqz * P12z) % P + aggFf) % P;');
    L.push('        require(aggLf % P == rhs % P);');                   // THE aggregated SZ identity closes
  }
  if (compress) {
    // covOut = [ccff] (the forwarded digest) -> residue tail (tail re-witnesses fF/c/cInv, checks
    // hash256(le40(fF,c,cInv))==ccff before its verdict). ccff is a raw hash-int -> serialize raw.
    L.push(covOut(['ccff'], succSpk, new Set(['ccff'])));
  } else {
    // covOut = tailState36 = [fF, c, cInv] (fF/c/cInv covIn-bound canonical) -> residue tail
    L.push(covOut([...FFN, ...CN, ...CIN], succSpk, new Set([...FFN, ...CN, ...CIN])));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
// close-chunk seam values (raw/uncompressed 40-limb form)
export function closeState() { const s = stateVal(t.steps.length); return [...chainLimbs(t.steps.length), ...f12limbs(t.c).map(mod), ...f12limbs(t.cInv).map(mod), s[39], s[40], t.gamma, t.z].map(mod); }
export function closePushedArgs() { return [...closeState(), ...BIGQ].map((x) => mod(BigInt(x))); }
export function closeOutLimbs() { return [...f12limbs(t.boundary).map(mod), ...f12limbs(t.c).map(mod), ...f12limbs(t.cInv).map(mod)]; }
// D11 compressed seam values: ccff = hash256(le40(fF)|le40(c)|le40(cInv)) as an LE-positive int limb.
const _leIntPos = (h) => { let n = 0n; for (let b = h.length - 1; b >= 0; b--) n = (n << 8n) | BigInt(h[b]); return n; };
export function ccffDigest() { return _leIntPos(commitBin([...f12limbs(t.boundary).map(mod), ...f12limbs(t.c).map(mod), ...f12limbs(t.cInv).map(mod)].map(BigInt))); }
export function closeStateC() { const s = stateVal(t.steps.length); return [mod(BigInt(s[39]) - BigInt(s[40])), t.gamma, t.z, ccffDigest()].map(BigInt); } // SF1-K: [accDf=aggLf-aggFf, gammaf, zf, ccff]
export function closePushedArgsC() { return [...closeStateC(), ...BIGQ].map((x) => BigInt(x)); }
export function closeOutLimbsC() { return [ccffDigest()]; }

// ---- STAGE-3 driver contract (mirrors gen_miller_affine exports for unified_affine) ----
// committed inbound limbs for a chunk starting at step `lo` (genesis: ptParams; interior/final: STATE45).
export function committedIn(lo, isGenesis) {
  if (isGenesis) return PT.map((_, k) => stateVal(0)[k]);   // ptParams values
  return stateVal(lo);
}
// full decl-order pushed witnesses for chunk [lo,hi). opts.debake appends the fixed-line lambdas +
// fixed-T window-starts (consensus-fixed data) in the SAME order as debakeParams / the emitStep walk.
export function pushedArgs(lo, hi, isGenesis, isFinal, opts = {}) {
  const stepWit = []; for (let i = lo; i < hi; i++) stepWit.push(...chainLimbs(i + 1), ...stepSlopeVals(i));
  const fix = opts.debake ? debakeVals(lo, hi) : [];
  let base;
  if (isGenesis) { const wPush = process.env.L17SEL ? [wselOf(t.w)] : f12limbs(t.w).map(mod); base = [...stateVal(0).slice(0, 10), ...f12limbs(t.c).map(mod), ...f12limbs(t.cInv).map(mod), t.gamma, t.z, ...wPush, ...stepWit, ...fix]; }
  else base = [...stateVal(lo), ...stepWit, ...fix];
  // NOTE: the isFinal STEP chunk (genChunk isFinal=true) does NOT consume big_Q — it only finalizes
  // gamma and threads the 40-limb close-state. big_Q (103 coeffs) lives ONLY in the terminal CLOSE
  // chunk, whose witnesses come from closePushedArgs() (its own [...closeState(), ...BIGQ]). Appending
  // BIGQ here was stale affine-miller carryover: it pushed 103 unconsumed limbs that inflated the
  // finalize unlock past the 10,000-B cap, so the VM rejected the unlock at length-validation (op=0,
  // accepted=false) BEFORE running any opcode — the sole full-build finalize reject. Do NOT re-add it.
  void isFinal;
  // hInt (STATE index 38) is the rolling running-h — a RAW hash-int that legitimately EXCEEDS P and is
  // threaded/committed/serialized canonically (toPaddedBytes(hInt,40), NO %Pmod). Every other limb is a
  // field element (< P), so a blanket `mod` is a no-op for them but CORRUPTS hInt for the ~55% of step
  // boundaries whose 32-byte hash > P: the pushed value would then disagree with the committed raw hInt
  // and covIn's hash-check fails (this is the sole interior-chunk failure). Push hInt RAW; reduce the rest.
  const HINT = isGenesis ? -1 : STATE.indexOf('hInt');
  return base.map((x, k) => (k === HINT ? BigInt(x) : mod(BigInt(x))));
}
// covOut limbs for a chunk ending at step `hi`. The FINALIZE chunk (isFinal) outputs the compact
// 40-limb close-state consumed by genCloseChunk; interior chunks output the 45-limb threaded state.
export function outLimbs(hi, isFinal) {
  if (isFinal) { const s = stateVal(hi); return [...chainLimbs(hi), ...f12limbs(t.c).map(mod), ...f12limbs(t.cInv).map(mod), s[39], s[40], t.gamma, t.z].map(mod); }
  return stateVal(hi);
}

// ---- live threaded-state VALUES at step boundary `s` (for measurement/commitments) ----
// State at boundary s (BEFORE step s == after processing steps 0..s-1):
//   PT(const), c(const), cInv(const), R = affine pair0 point at the start of step s,
//   hInt = running-h (LE-positive int) after absorbing statement + chain[0] + chain[1..s]
//          == seamH[s+2] (seamH[1]=after statement, [2]=after chain[0], [i+2]=after chain[i+1]),
//   aggL/aggF = identity partial sums over steps 0..s-1, gp = gamma^s,
//   gammaW=gamma, zW=z (threaded challenges), finZseam = finZ_s = <chain[s], e(z)>.
let _stateCache = null;
function stateVal(s) { if (!_stateCache) _stateCache = buildStates(); return _stateCache[s]; }
function buildStates() {
  const EZ = ezCols.map((col) => col.reduce((acc, cf, j) => acc, 0n)); // placeholder (unused)
  const ez = ezCols.map((col) => { let r = 0n; for (let j = col.length - 1; j >= 0; j--) r = mod(r * t.z + col[j]); return r; });
  const finZ = (i) => chainLimbs(i).reduce((acc, v, k) => mod(acc + v * ez[k]), 0n);
  const PTV = [mod(t.nA.x), mod(t.nA.y), ...g2l(t.pf.b), mod(t.vkxAff.x), mod(t.vkxAff.y), mod(t.Caf.x), mod(t.Caf.y)];
  const cV = f12limbs(t.c).map(mod), ciV = f12limbs(t.cInv).map(mod);
  const Rs = affStartR();
  const leIntPos = (h) => { let n = 0n; for (let b = h.length - 1; b >= 0; b--) n = (n << 8n) | BigInt(h[b]); return n; };
  const states = [];
  for (let s = 0; s <= t.steps.length; s++) {
    const hIdx = Math.min(s + 2, t.seamH.length - 1); // seamH[s+2] = after absorbing chain[s-1] (s>=1); s=0 -> [2]
    let aggL = 0n, aggF = 0n, gp = 1n;
    for (let i = 0; i < s; i++) { const fc = finZ(i); aggL = mod(aggL + gp * mod(mod(fc * fc) * t.prodFactorZ[i])); aggF = mod(aggF + gp * finZ(i + 1)); gp = mod(gp * t.gamma); }
    states.push([...PTV, ...cV, ...ciV, ...Rs[s], leIntPos(t.seamH[hIdx]), aggL, aggF, gp, t.gamma, t.z, finZ(s)]);
  }
  return states;
}
// affine pair0 R at the start of each step (the R at the step's sqr op) + one extra past the end.
function affStartR() {
  const per = [];
  for (let i = 0; i < t.fused.ops.length; i++) if (t.fused.ops[i].t === 'sqr') { const R = t.fused.states[i].Rs[0]; per.push([mod(R.x.c0), mod(R.x.c1), mod(R.y.c0), mod(R.y.c1)]); }
  const last = t.fused.states[t.fused.states.length - 1].Rs[0];
  per.push([mod(last.x.c0), mod(last.x.c1), mod(last.y.c0), mod(last.y.c1)]);
  return per;
}

// ================= self-test (compile-sanity genesis + final) =================
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  runSanity();
}
function runSanity() {
  const vm = createVirtualMachineBch2026(false);
  const here = dirname(fileURLToPath(import.meta.url));
  const GEN = join(here, 'generated');
  const PLAN_SPK = '11'.repeat(35).replace(/../g, (m, i) => m); // placeholder 35B succSpk hex
  const spk = 'aa20' + '11'.repeat(32) + '87';
  const compile = (name, src) => { const p = join(GEN, `_szm_${name}.cash`); writeFileSync(p, src); return Uint8Array.from([...compileFileBytecode(p)]); };
  const drive = (name, src, committed, pushed, outL, terminal) => {
    let redeem; try { redeem = compile(name, src); } catch (e) { return { ok: false, err: 'compile: ' + String(e?.message ?? e).slice(0, 200) }; }
    const rpush = encodeDataPush(redeem);
    const locking = encodeLockingBytecodeP2sh32(laHash256(redeem));
    const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
    const pad = encodeDataPush(new Uint8Array(200));
    const argb = Uint8Array.from([...pushed].reverse().flatMap((c) => [...pushInt(c)]));
    const unlocking = Uint8Array.from([...pad, ...argb, ...rpush]);
    const tok = (com) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: com } });
    const inCommit = commitBin(committed.map(BigInt));
    const outCommit = outL === null ? null : commitBin(outL.map(BigInt));
    const spkBin = Uint8Array.from(Buffer.from(spk, 'hex'));
    const prog = {
      inputIndex: 0,
      sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
      transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
        outputs: [terminal ? { lockingBytecode: locking, valueSatoshis: 1000n } : { lockingBytecode: spkBin, valueSatoshis: 1000n, token: tok(outCommit) }], locktime: 0 },
    };
    const st = vm.evaluate(prog); const top = st.stack[st.stack.length - 1];
    const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
    return { ok: accepted, err: st.error ?? null, op: st.metrics.operationCost, redeemLen: redeem.length, unlockLen: unlocking.length, inCommit: binToHex(inCommit), outCommit: outCommit ? binToHex(outCommit) : null };
  };
  console.log('=== SZ-miller stage genChunk compile-sanity (genesis + final) ===');
  // GENESIS: steps [0, G)
  const G = 2;
  const gSrc = genChunk(0, G, false, true, spk);
  const gRes = drive('genesis', gSrc, committedIn(0, true), pushedArgs(0, G, true, false), outLimbs(G, false), false);
  console.log(`  GENESIS [0,${G}): compile=${gRes.err && String(gRes.err).startsWith('compile') ? 'FAIL' : 'ok'} accept=${gRes.ok} op=${gRes.op ?? ''} redeem=${gRes.redeemLen ?? ''}B unlock=${gRes.unlockLen ?? ''}B`);
  if (gRes.err) console.log('    err:', String(gRes.err).slice(0, 300));
  // seam: genesis covIn == ecipSEAM2
  const ecipSEAM2 = [mod(t.nA.x), mod(t.nA.y), ...g2l(t.pf.b), mod(t.vkxAff.x), mod(t.vkxAff.y), mod(t.Caf.x), mod(t.Caf.y)];
  console.log(`  genesis covIn commit = ${gRes.inCommit ?? '(n/a)'}  (ecipSEAM2 ptParams)`);
  console.log(`  genesis covIn == commitBin(ecipSEAM2): ${gRes.inCommit === binToHex(commitBin(ecipSEAM2.map(BigInt)))}`);
  // FINALIZE: steps [F, 65) — finalize gamma, thread the 40-limb close-state (NOT terminal)
  const F = 63;
  const fSrc = genChunk(F, stepCount, true, false, spk);
  const fRes = drive('finalize', fSrc, committedIn(F, false), pushedArgs(F, stepCount, false, false), outLimbs(stepCount, true), false);
  console.log(`  FINALIZE[${F},${stepCount}): compile=${fRes.err && String(fRes.err).startsWith('compile') ? 'FAIL' : 'ok'} accept=${fRes.ok} op=${fRes.op ?? ''} redeem=${fRes.redeemLen ?? ''}B unlock=${fRes.unlockLen ?? ''}B`);
  if (fRes.err) console.log('    err:', String(fRes.err).slice(0, 300));
  // CLOSE (terminal SZ): big_Q z-derive + Horner + identity + covOut=tailState36 (succSpk = residue tail)
  const cSrc = genCloseChunk(spk);
  const cRes = drive('close', cSrc, closeState(), closePushedArgs(), closeOutLimbs(), false);
  console.log(`  CLOSE          : compile=${cRes.err && String(cRes.err).startsWith('compile') ? 'FAIL' : 'ok'} accept=${cRes.ok} op=${cRes.op ?? ''} redeem=${cRes.redeemLen ?? ''}B unlock=${cRes.unlockLen ?? ''}B`);
  if (cRes.err) console.log('    err:', String(cRes.err).slice(0, 300));
  // OUTPUT seam: close covOut == commitBin(tailState36) that the residue tail consumes
  const tailState36 = closeOutLimbs();
  console.log(`  close covOut == commitBin(tailState36[fF,c,cInv]): ${cRes.outCommit === binToHex(commitBin(tailState36.map(BigInt)))}  (len=${tailState36.length})`);
}
