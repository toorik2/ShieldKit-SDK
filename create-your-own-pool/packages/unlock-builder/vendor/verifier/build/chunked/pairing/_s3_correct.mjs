import { bn254, Fp2, Fp12, pairsFor, vec, pointDouble, pointAdd, ATE_NAF, Fp2B, INV2 } from './_millermath.mjs';
const { Fp } = bn254.fields;
const PAIRS = pairsFor(vec.publicInputs);
const pair0 = PAIRS[0]; // e(-A, B): P = -A (G1), Q = B (G2)
const Qa = pair0.Q.toAffine(), Pa = pair0.P.toAffine();
// --- affine helpers ---
const A=(x,y)=>Fp2.add(x,y), S=(x,y)=>Fp2.sub(x,y), M=(x,y)=>Fp2.mul(x,y), SQ=(x)=>Fp2.sqr(x), N=(x)=>Fp2.neg(x), SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const eq=(a,b)=>a.c0===b.c0&&a.c1===b.c1;
// mul034 / line convention from _millermath (lineFn: mul034(f, c2*Py, c1*Px, c0))
function mul034(f, o0, o3, o4){
  const { Fp6 } = bn254.fields;
  const Aa = Fp6.create({ c0: M(f.c0.c0, o0), c1: M(f.c0.c1, o0), c2: M(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), A(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), Aa), c1: Fp6.sub(E, Fp6.add(Aa, B)) });
}
const lineFn=(f,c0,c1,c2,Px,Py)=>mul034(f, SC(c2,Py), SC(c1,Px), c0);

// AFFINE doubling with witnessed slope lam=3x^2/(2y)
function affDouble(x,y){
  const l3=SC(SQ(x),3n); const lam = M(l3, Fp2.inv(A(y,y))); // 3x^2
  // slope: lam*(2y)=3x^2
  const xn = S(SQ(lam), A(x,x));
  const yn = S(M(lam, S(x,xn)), y);
  // coeffs must match pointDouble(x,y,1)
  const c0 = S(SC(Fp2B,3n), SQ(y));  // 3*B - y^2
  const c1 = l3;                     // 3x^2
  const c2 = N(A(y,y));              // -2y
  return {xn,yn,lam,coeffs:[c0,c1,c2]};
}
// AFFINE add R+Q with witnessed slope lam=(Qy-Ry)/(Qx-Rx)
function affAdd(Rx,Ry,Qx,Qy){
  const t1 = S(Rx,Qx);           // Rx-Qx
  const t0 = S(Ry,Qy);           // Ry-Qy
  const lam = M(t0, Fp2.inv(t1));// slope
  const xn = S(S(SQ(lam), Rx), Qx);
  const yn = S(M(lam, S(Rx,xn)), Ry);
  const c0 = S(M(t0,Qx), M(t1,Qy));
  const c1 = N(t0);
  const c2 = t1;
  return {xn,yn,lam,coeffs:[c0,c1,c2]};
}
// verify affine coeffs match noble pointDouble/pointAdd at Z=1
{
  const d = pointDouble(Qa.x, Qa.y, Fp2.ONE);
  const ad = affDouble(Qa.x, Qa.y);
  // normalize d.R to affine
  const zi = Fp2.inv(d.R.z), zi2=SQ(zi), zi3=M(zi2,zi);
  const dxAff = M(d.R.x, zi2), dyAff = M(d.R.y, zi3);
  console.log('DBL coeffs match:', eq(d.coeffs[0],ad.coeffs[0]), eq(d.coeffs[1],ad.coeffs[1]), eq(d.coeffs[2],ad.coeffs[2]));
  console.log('DBL next-point match:', eq(dxAff, ad.xn), eq(dyAff, ad.yn));
  // pointAdd at Z=1: R=2Q (from double), Q=Qa
  const R2 = {x:ad.xn, y:ad.yn};
  const a = pointAdd(R2.x, R2.y, Fp2.ONE, Qa.x, Qa.y);
  const aa = affAdd(R2.x, R2.y, Qa.x, Qa.y);
  const azi=Fp2.inv(a.R.z), azi2=SQ(azi), azi3=M(azi2,azi);
  console.log('ADD coeffs match:', eq(a.coeffs[0],aa.coeffs[0]), eq(a.coeffs[1],aa.coeffs[1]), eq(a.coeffs[2],aa.coeffs[2]));
  console.log('ADD next-point match:', eq(M(a.R.x,azi2), aa.xn), eq(M(a.R.y,azi3), aa.yn));
}
// FULL single-pair Miller for pair0 in AFFINE, then finalExp, compare to noble pairing
const negQy = N(Qa.y);
function psiAff(x,y){
  const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER-1n)/3n), PSI_Y = Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/2n);
  return [M(Fp2.frobeniusMap(x,1),PSI_X), M(Fp2.frobeniusMap(y,1),PSI_Y)];
}
let f = Fp12.ONE; let Rx=Qa.x, Ry=Qa.y;
for(let k=0;k<ATE_NAF.length;k++){
  f = Fp12.sqr(f);
  const d = affDouble(Rx,Ry); Rx=d.xn; Ry=d.yn;
  f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], Pa.x, Pa.y);
  if(ATE_NAF[k]){
    const useY = ATE_NAF[k]===-1 ? negQy : Qa.y;
    const a = affAdd(Rx,Ry,Qa.x,useY); Rx=a.xn; Ry=a.yn;
    f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], Pa.x, Pa.y);
  }
}
// postPrecompute (2 psi adds)
{
  const q1 = psiAff(Qa.x,Qa.y);
  let a1 = affAdd(Rx,Ry,q1[0],q1[1]); Rx=a1.xn; Ry=a1.yn;
  f = lineFn(f,a1.coeffs[0],a1.coeffs[1],a1.coeffs[2],Pa.x,Pa.y);
  const q2 = psiAff(q1[0],q1[1]);
  let a2 = affAdd(Rx,Ry,q2[0], N(q2[1])); Rx=a2.xn; Ry=a2.yn;
  f = lineFn(f,a2.coeffs[0],a2.coeffs[1],a2.coeffs[2],Pa.x,Pa.y);
}
// finalExp via noble
const myPairing = bn254.fields.Fp12.finalExponentiate ? bn254.fields.Fp12.finalExponentiate(f) : null;
const noblePair = bn254.pairing(pair0.P, pair0.Q);
console.log('\nfull affine pair0 finalExp == noble pairing:', myPairing? eq12simple(myPairing, noblePair): 'no finalExp fn');
function eq12simple(a,b){ const t=x=>[x.c0.c0.c0,x.c0.c0.c1,x.c0.c1.c0,x.c0.c1.c1,x.c0.c2.c0,x.c0.c2.c1,x.c1.c0.c0,x.c1.c0.c1,x.c1.c1.c0,x.c1.c1.c1,x.c1.c2.c0,x.c1.c2.c1]; const A=t(a),B=t(b); return A.every((v,i)=>v===B[i]); }
