// gen_vkx_ecip_a1.mjs — ARITY-1 variant of gen_vkx_ecip.mjs (M9 mininputs 2->1).
// vk_x = IC0 + in0*IC1  (2-point MSM). ECIP hint over 2 base points => coeff counts (3,4,4,7)
// vs the 3-point (4,5,5,8). Drops in1 from SEAM1, IC2, the in1 neg-3 decomposition, and the
// IC2 point-challenge term. Reuses zkEcipHint (the ported garaga math) from the base module.
import { bn254 } from '@noble/curves/bn254.js';
import { createHash } from 'node:crypto';
import { vmNumberToBigInt } from '@bitauth/libauth';
import { epen, MAXTRY } from './gen_vkx_ecip.mjs';
const G1 = bn254.G1.Point;
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ---- Fp ----
const fp = (x) => ((x % P) + P) % P;
const fadd = (a, b) => fp(a + b), fsub = (a, b) => fp(a - b), fmul = (a, b) => fp(a * b), fneg = (a) => fp(-a);
const fpow = (b, e) => { let r = 1n; b = fp(b); while (e > 0n) { if (e & 1n) r = fmul(r, b); b = fmul(b, b); e >>= 1n; } return r; };
const finv = (a) => fpow(fp(a), P - 2n);
const fdiv = (a, b) => fmul(a, finv(b));
const peval = (a, x) => { let v = 0n, xi = 1n; for (const c of a) { v = fadd(v, fmul(c, xi)); xi = fmul(xi, x); } return v; };
const aff = (pt) => pt.toAffine();

const le32 = (x) => { const b = Buffer.alloc(32); let v = fp(x); for (let i = 0; i < 32; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const vmInt31 = (digest) => fp(vmNumberToBigInt(digest.subarray(0, 31), { maximumVmNumberByteLength: 32, requireMinimalEncoding: false }));
const sqrtFp = (a) => fpow(fp(a), (P + 1n) / 4n);
const isQR = (a) => { a = fp(a); if (a === 0n) return true; return fpow(a, (P - 1n) / 2n) === 1n; };
const nextX = (x) => vmInt31(createHash('sha256').update(le32(x)).digest());
const rhsOf = (x) => fadd(fmul(fmul(x, x), x), 3n);

// arity-1 Fiat-Shamir preimage: le32 of [in0, Qx, Qy] ++ coeffs.
export function fsChallenge1(in0, Qx, Qy, h) {
  const parts = [in0, Qx, Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den].map(le32);
  return vmInt31(createHash('sha256').update(Buffer.concat(parts)).digest());
}

// arity-1 ECIP verification (IC = [IC0,IC1], scalars = [1,in0]).
export function ecipVerify1(IC, scalars, h) {
  if (IC.length !== 2 || scalars.length !== 2) throw new Error('ecipVerify1: expects 2 points / 2 scalars');
  const Qx = h.Qx, Qy = h.Qy;
  const xseed = fsChallenge1(scalars[1], Qx, Qy, h);
  let x = xseed, nfail = 0; const gRoots = [];
  while (!isQR(rhsOf(x))) { gRoots.push(sqrtFp(fmul(3n, rhsOf(x)))); x = nextX(x); nfail++; if (nfail > MAXTRY) throw new Error('MAXTRY exceeded'); }
  const xA0 = x;
  const yA0 = sqrtFp(rhsOf(xA0));
  const mA0 = fdiv(fmul(3n, fmul(xA0, xA0)), fmul(2n, yA0));
  const bA0 = fsub(yA0, fmul(mA0, xA0));
  const x2d = fsub(fmul(mA0, mA0), fmul(2n, xA0));
  const y2d = fsub(fmul(mA0, fsub(xA0, x2d)), yA0);
  const xA2 = x2d, yA2 = fneg(y2d);
  const mA0A2 = fdiv(fsub(yA2, yA0), fsub(xA2, xA0));
  const c2den = fsub(fmul(3n, fmul(xA2, xA2)), fmul(2n, fmul(mA0A2, yA2)));
  const coeff2 = fdiv(fmul(2n, fmul(yA2, fsub(xA0, xA2))), c2den);
  const coeff0 = fadd(coeff2, fmul(2n, mA0A2));
  const EPN = scalars.map((s) => epen(BigInt(s)));
  const chalTerm = (Px, Py, mult) => { const den = fsub(fsub(Py, fmul(mA0, Px)), bA0); const num = fmul(fp(mult), fsub(xA0, Px)); return { term: den === 0n ? 0n : fdiv(num, den), den, num }; };
  const pts = IC.map((pt) => { const a = aff(pt); return [fp(a.x), fp(a.y)]; });
  let basis = 0n; const chalWit = [];
  for (let i = 0; i < 2; i++) {
    const [Px, Py] = pts[i]; const [ep, en] = EPN[i];
    const tp = chalTerm(Px, Py, ep); const tn = chalTerm(Px, fneg(Py), en);
    basis = fadd(basis, fadd(tp.term, tn.term));
    chalWit.push({ Px, Py, epMod: fp(ep), enMod: fp(en), termP: tp.term, termN: tn.term });
  }
  const tQ = chalTerm(Qx, fneg(Qy), 1n);
  const RHS = fadd(tQ.term, basis);
  const adenA0 = peval(h.a_den, xA0), bdenA0 = peval(h.b_den, xA0);
  const adenA2 = peval(h.a_den, xA2), bdenA2 = peval(h.b_den, xA2);
  const fEval = (x, y, iad, ibd) => fadd(fmul(peval(h.a_num, x), iad), fmul(y, fmul(peval(h.b_num, x), ibd)));
  const fA0 = fEval(xA0, yA0, finv(adenA0), finv(bdenA0));
  const fA2 = fEval(xA2, yA2, finv(adenA2), finv(bdenA2));
  const LHS = fsub(fmul(coeff0, fA0), fmul(coeff2, fA2));
  const ok = LHS === RHS;
  return { ok, nfail, gRoots, xseed, yA0, xA0, yA2, xA2, mA0, bA0, mA0A2, coeff0, coeff2, c2den, RHS, LHS,
    invAdenA0: finv(adenA0), invBdenA0: finv(bdenA0), invAdenA2: finv(adenA2), invBdenA2: finv(bdenA2),
    fA0, fA2, chalWit, tQterm: tQ.term, EPN };
}

// ---- arity-1 .cash generator ----
const B2 = ['19485874751759354771024239261021720505790618469301721065564631296452457478373',
            '266929791119991161246907387137283842545076965332900288569378510910307636690'];
const FR = '21888242871839275222246405745257275088548364400416034343698204186575808495617';
const PSTR = P.toString();
const SEAM1 = ['nAx', 'nAy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'in0'];        // 9 (drop in1)
const SEAM2 = ['nAx', 'nAy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'vkxX', 'vkxY', 'Cx', 'Cy']; // 10 (unchanged)
// arity-1 coeff counts: a_num=3, a_den=4, b_num=4, b_den=7 (measured; garaga 2-pt divisor).
const AN = ['an0', 'an1', 'an2'], AD = ['ad0', 'ad1', 'ad2', 'ad3'];
const BN = ['bn0', 'bn1', 'bn2', 'bn3'], BD = ['bd0', 'bd1', 'bd2', 'bd3', 'bd4', 'bd5', 'bd6'];
const GR = Array.from({ length: MAXTRY }, (_, i) => `gr${i}`);
export const WIT1 = [
  'Qx', 'Qy', ...AN, ...AD, ...BN, ...BD, 'yA0', 'nfail', ...GR,
  'mA0', 'mA0A2', 'coeff2', 'iad0', 'ibd0', 'iad2', 'ibd2',
  't0p', 't0n', 't1p', 't1n', 'tQ',
];
const horner = (names, X) => { let e = names[names.length - 1]; for (let i = names.length - 2; i >= 0; i--) e = `addFp(mulFp(${e},${X}),${names[i]})`; return e; };

export function emitCashVerifier1(IC, succSpk, crossPinIdx = null) {
  if (IC.length !== 2) throw new Error('emitCashVerifier1: expects 2 IC points');
  const [[i0x, i0y], [i1x, i1y]] = IC.map((pt) => { const a = aff(pt); return [fp(a.x).toString(), fp(a.y).toString()]; });
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`function addFp(int x,int y) returns(int){return (x+y)%${PSTR};}`);
  L.push(`function subFp(int x,int y) returns(int){return (x-y+${PSTR})%${PSTR};}`);
  L.push(`function mulFp(int x,int y) returns(int){return (x*y)%${PSTR};}`);
  L.push(`function fp2Mul(int a0,int a1,int b0,int b1) returns(int,int){int v0=mulFp(a0,b0);int v1=mulFp(a1,b1);return subFp(v0,v1),subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1));}`);
  L.push(`function fp2Add(int a0,int a1,int b0,int b1) returns(int,int){return addFp(a0,b0),addFp(a1,b1);}`);
  L.push('contract VkxEcip1() {');
  L.push(`    function spend(${[...SEAM1, ...WIT1].map((n) => `int ${n}`).join(',')}, bytes unused zeroPadding) {`);
  L.push(`        int Pmod = ${PSTR};`);
  L.push(`        require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(${SEAM1.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ')}));`);
  L.push(`        require(in0 < ${FR});`);
  L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));');
  L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');
  L.push('        (int oxa,int oxb) = fp2Mul(Bxa, Bxb, Bxa, Bxb);');
  L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
  L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
  L.push('        (int oba,int obb) = fp2Mul(Bya, Byb, Bya, Byb);');
  L.push('        require(oba == ora); require(obb == orb);');
  for (const n of ['Qx', 'Qy', ...AN, ...AD, ...BN, ...BD]) L.push(`        require(${n} >= 0); require(${n} < Pmod);`);
  const pre = ['in0', 'Qx', 'Qy', ...AN, ...AD, ...BN, ...BD].map((n) => `toPaddedBytes(${n}, 32)`).join(' + ');
  L.push(`        int cseed = int(bytes(sha256(${pre}).split(31)[0]));`);
  L.push('        int x = cseed % Pmod; if (x < 0) { x = x + Pmod; }');
  L.push('        require(nfail >= 0); require(nfail <= ' + MAXTRY + ');');
  for (let t = 0; t < MAXTRY; t++) {
    L.push(`        if (nfail > ${t}) { require(mulFp(${GR[t]}, ${GR[t]}) == mulFp(3, addFp(mulFp(mulFp(x,x),x), 3)));`);
    L.push(`            int hc${t} = int(bytes(sha256(toPaddedBytes(x, 32)).split(31)[0])); x = hc${t} % Pmod; if (x < 0) { x = x + Pmod; } }`);
  }
  L.push('        int xA0 = x;');
  L.push('        require(mulFp(yA0, yA0) == addFp(mulFp(mulFp(xA0,xA0),xA0), 3));');
  L.push('        require(mulFp(mulFp(2, yA0), mA0) == mulFp(3, mulFp(xA0, xA0)));');
  L.push('        int bA0 = subFp(yA0, mulFp(mA0, xA0));');
  L.push('        int x2d = subFp(mulFp(mA0, mA0), mulFp(2, xA0));');
  L.push('        int y2d = subFp(mulFp(mA0, subFp(xA0, x2d)), yA0);');
  L.push('        int xA2 = x2d; int yA2 = subFp(0, y2d);');
  L.push('        require(mulFp(mA0A2, subFp(xA2, xA0)) == subFp(yA2, yA0));');
  L.push('        require(mulFp(coeff2, subFp(mulFp(3, mulFp(xA2, xA2)), mulFp(2, mulFp(mA0A2, yA2)))) == mulFp(2, mulFp(yA2, subFp(xA0, xA2))));');
  L.push('        int coeff0 = addFp(coeff2, mulFp(2, mA0A2));');
  // base(-3) multiplicities ep/en for in0 only (scalar 1 => ep=1,en=0 baked)
  L.push('        int s0 = in0; int ep0 = 0; int en0 = 0; int pw = 1;');
  L.push('        for (int k = 0; k < 161; k = k + 1) { if (s0 != 0) {');
  L.push('            int r0 = s0 % 3; if (r0 < 0) { r0 = r0 + 3; } int d0 = 0; if (r0 == 2) { d0 = -1; } else { d0 = r0; }');
  L.push('            if (d0 == 1) { ep0 = ep0 + pw; } if (d0 == -1) { en0 = en0 + pw; } s0 = (d0 - s0) / 3; pw = 0 - (3 * pw); } }');
  L.push('        require(s0 == 0);');
  L.push('        int ep0m = ep0 % Pmod; if (ep0m < 0) { ep0m = ep0m + Pmod; } int en0m = en0 % Pmod; if (en0m < 0) { en0m = en0m + Pmod; }');
  const chal = (tp, tn, Px, Py, epv, env) => {
    L.push(`        int mx${tp} = mulFp(mA0, ${Px});`);
    L.push(`        require(mulFp(${tp}, subFp(subFp(${Py}, mx${tp}), bA0)) == mulFp(${epv}, subFp(xA0, ${Px})));`);
    L.push(`        require(mulFp(${tn}, subFp(subFp(subFp(0, ${Py}), mx${tp}), bA0)) == mulFp(${env}, subFp(xA0, ${Px})));`);
  };
  chal('t0p', 't0n', i0x, i0y, '1', '0');        // IC0, scalar 1
  chal('t1p', 't1n', i1x, i1y, 'ep0m', 'en0m');  // IC1, scalar in0
  L.push('        int mxQ = mulFp(mA0, Qx);');
  L.push('        require(mulFp(tQ, subFp(subFp(subFp(0, Qy), mxQ), bA0)) == subFp(xA0, Qx));');
  L.push('        int RHS = addFp(tQ, addFp(addFp(t0p, t0n), addFp(t1p, t1n)));');
  L.push(`        int adA0 = ${horner(AD, 'xA0')}; require(mulFp(adA0, iad0) == 1);`);
  L.push(`        int bdA0 = ${horner(BD, 'xA0')}; require(mulFp(bdA0, ibd0) == 1);`);
  L.push(`        int adA2 = ${horner(AD, 'xA2')}; require(mulFp(adA2, iad2) == 1);`);
  L.push(`        int bdA2 = ${horner(BD, 'xA2')}; require(mulFp(bdA2, ibd2) == 1);`);
  L.push(`        int fA0 = addFp(mulFp(${horner(AN, 'xA0')}, iad0), mulFp(yA0, mulFp(${horner(BN, 'xA0')}, ibd0)));`);
  L.push(`        int fA2 = addFp(mulFp(${horner(AN, 'xA2')}, iad2), mulFp(yA2, mulFp(${horner(BN, 'xA2')}, ibd2)));`);
  L.push('        int LHS = subFp(mulFp(coeff0, fA0), mulFp(coeff2, fA2));');
  L.push('        require(LHS == RHS);');
  const _SR = process.env.SIBLING_READ === '1';
  // sr-reconstruct-sz63: cross-pin a FIXED input index (genesis@crossPinIdx) rather than aii+1. vkx sits
  // AFTER genesis in the input order (genesis is structurally pinned @10 as the interior state@64 consumer),
  // so vkx binds its verified vkx point Q into genesis's PT token: input[crossPinIdx].nftCommitment==commit(seam2).
  const _tgt = crossPinIdx !== null ? `tx.inputs[${crossPinIdx}]` : (_SR ? 'tx.inputs[this.activeInputIndex + 1]' : 'tx.outputs[0]');
  L.push('        int vkxX = Qx; int vkxY = Qy;');
  L.push(`        require(${_tgt}.nftCommitment == hash256(${SEAM2.map((n) => `toPaddedBytes(${n} % Pmod, 40)`).join(' + ')}));`);
  L.push(`        require(${_tgt}.tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);`);
  if (succSpk !== null && succSpk !== undefined) {
    const hex = typeof succSpk === 'string' ? succSpk : Buffer.from(succSpk).toString('hex');
    if (!_SR) L.push('        require(tx.outputs.length == 1);');
    L.push(`        require(${_tgt}.lockingBytecode == 0x${hex});`);
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

export function emitWitness1(IC, scalars, h, v) {
  const gr = Array.from({ length: MAXTRY }, (_, i) => (i < v.gRoots.length ? v.gRoots[i] : 0n));
  const cw = v.chalWit; // [IC0, IC1]
  return [
    h.Qx, h.Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den, v.yA0, BigInt(v.nfail), ...gr,
    v.mA0, v.mA0A2, v.coeff2, v.invAdenA0, v.invBdenA0, v.invAdenA2, v.invBdenA2,
    cw[0].termP, cw[0].termN, cw[1].termP, cw[1].termN, v.tQterm,
  ].map((x) => ((x % P) + P) % P);
}
