import { bn254, Fp2, Fp12, pairsFor, vec, pointDouble, pointAdd, ATE_NAF, Fp2B } from './_millermath.mjs';
const { Fp } = bn254.fields;
const PAIRS = pairsFor(vec.publicInputs);
const pair0 = PAIRS[0];
const Qa = pair0.Q.toAffine();
const A=(x,y)=>Fp2.add(x,y), S=(x,y)=>Fp2.sub(x,y), M=(x,y)=>Fp2.mul(x,y), SQ=(x)=>Fp2.sqr(x), N=(x)=>Fp2.neg(x), SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const eq=(a,b)=>a.c0===b.c0&&a.c1===b.c1;
function affDouble(x,y){
  const lam = M(SC(SQ(x),3n), Fp2.inv(A(y,y)));
  const xn = S(SQ(lam), A(x,x));
  const yn = S(M(lam, S(x,xn)), y);
  return {xn,yn,lam};
}
function affAdd(Rx,Ry,Qx,Qy){
  const t1=S(Rx,Qx), t0=S(Ry,Qy);
  const lam=M(t0,Fp2.inv(t1));
  const xn=S(S(SQ(lam),Rx),Qx);
  const yn=S(M(lam,S(Rx,xn)),Ry);
  return {xn,yn,lam};
}
// ground truth: noble G2 doubling & add
const twoQ = pair0.Q.double().toAffine();
const ad = affDouble(Qa.x,Qa.y);
console.log('affDouble == noble 2Q:', eq(ad.xn, twoQ.x), eq(ad.yn, twoQ.y));
const threeQ = pair0.Q.add(pair0.Q.double()).toAffine(); // 2Q + Q = 3Q
const aa = affAdd(ad.xn, ad.yn, Qa.x, Qa.y);
console.log('affAdd(2Q,Q) == noble 3Q:', eq(aa.xn, threeQ.x), eq(aa.yn, threeQ.y));
// homogeneous projective normalization of pointDouble (X/Z, Y/Z)
const d = pointDouble(Qa.x, Qa.y, Fp2.ONE);
const zi = Fp2.inv(d.R.z);
console.log('pointDouble(proj X/Z,Y/Z) == 2Q:', eq(M(d.R.x,zi), twoQ.x), eq(M(d.R.y,zi), twoQ.y));
