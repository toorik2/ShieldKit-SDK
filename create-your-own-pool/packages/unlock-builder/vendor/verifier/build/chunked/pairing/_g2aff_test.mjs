import { bn254, Fp2, proof } from './_millermath.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
const { Fp } = bn254.fields;
const BN_X = 4965661367192848881n, NBITS=63;
const bit=(k)=>(BN_X>>BigInt(NBITS-1-k))&1n;
const B = proof.b.toAffine();
const eq=(a,b)=>a.c0===b.c0&&a.c1===b.c1;
// affine ladder starting at R=B (after k=0), process k=1..62
let R={x:B.x,y:B.y};
for(let k=1;k<NBITS;k++){ const d=affDoubleJS(R.x,R.y); R=d.R; if(bit(k)){ const a=affAddJS(R.x,R.y,B.x,B.y); R=a.R; } }
// noble ground truth x0*B
const x0B = proof.b.multiply(BN_X).toAffine();
console.log('affine [x0]B == noble x0*B:', eq(R.x,x0B.x)&&eq(R.y,x0B.y));
// endo check (affine): [x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B)
const PSI_X=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/3n), PSI_Y=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/2n);
const conj=(x)=>Fp2.fromBigTuple([x.c0,(Fp.ORDER-x.c1)%Fp.ORDER]);
const psi=(x,y)=>[Fp2.mul(conj(x),PSI_X), Fp2.mul(conj(y),PSI_Y)]; // matches Miller.cash psi = frob*PSI
const a0={x:R.x,y:R.y}; // [x0]B affine
const b_=psi(a0.x,a0.y), c_=psi(b_[0],b_[1]), d_=psi(c_[0],c_[1]);
// LHS = a0 + B + psi(a0) + psi^2(a0)  (affine adds)
let l1=affAddJS(a0.x,a0.y,B.x,B.y);
let l2=affAddJS(l1.R.x,l1.R.y,b_[0],b_[1]);
let l3=affAddJS(l2.R.x,l2.R.y,c_[0],c_[1]);
// RHS = 2*psi^3(a0)  (affine double of d_)
let rr=affDoubleJS(d_[0],d_[1]);
console.log('endo relation holds (affine):', eq(l3.R.x,rr.R.x)&&eq(l3.R.y,rr.R.y));
// count ladder ops
let nd=0,na=0; for(let k=1;k<NBITS;k++){nd++; if(bit(k))na++;}
console.log('ladder ops: doubles',nd,'adds',na,'| endo adds 3 + endo double 1 | popcount x0 =', BN_X.toString(2).split('').filter(c=>c==='1').length);
