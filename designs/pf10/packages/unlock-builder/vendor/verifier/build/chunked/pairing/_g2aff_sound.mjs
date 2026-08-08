import { bn254, Fp2, proof } from './_millermath.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
const { Fp } = bn254.fields;
const BN_X=4965661367192848881n, NBITS=63, bit=(k)=>(BN_X>>BigInt(NBITS-1-k))&1n;
const PSI_X=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/3n), PSI_Y=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/2n);
const conj=(x)=>Fp2.fromBigTuple([x.c0,(Fp.ORDER-x.c1)%Fp.ORDER]);
const psi=(x,y)=>[Fp2.mul(conj(x),PSI_X),Fp2.mul(conj(y),PSI_Y)];
const eq=(a,b)=>a.c0===b.c0&&a.c1===b.c1;
function endoCheck(B){ // returns 'accept' if relation holds, or 'reject'/'exc' 
  try{
    let R={x:B.x,y:B.y};
    for(let k=1;k<NBITS;k++){ const d=affDoubleJS(R.x,R.y); R=d.R; if(bit(k)){ const a=affAddJS(R.x,R.y,B.x,B.y); R=a.R; } }
    const a0={x:R.x,y:R.y}, b_=psi(a0.x,a0.y), c_=psi(b_[0],b_[1]), d_=psi(c_[0],c_[1]);
    const l1=affAddJS(a0.x,a0.y,B.x,B.y), l2=affAddJS(l1.R.x,l1.R.y,b_[0],b_[1]), l3=affAddJS(l2.R.x,l2.R.y,c_[0],c_[1]);
    const rr=affDoubleJS(d_[0],d_[1]);
    return (eq(l3.R.x,rr.R.x)&&eq(l3.R.y,rr.R.y))?'ACCEPT':'REJECT';
  }catch(e){ return 'REJECT(exceptional div0: '+String(e.message).slice(0,30)+')'; }
}
// valid B (in subgroup)
console.log('valid subgroup B ->', endoCheck(proof.b.toAffine()));
// non-subgroup on-curve G2 point: take a random x, solve for y on twist, that point is on-curve
// but almost surely NOT in the r-torsion subgroup.
const b2=Fp2.fromBigTuple([19485874751759354771024239261021720505790618469301721065564631296452457478373n,266929791119991161246907387137283842545076965332900288569378510910307636690n]);
function onCurvePoint(seed){
  for(let s=seed;;s++){ const x=Fp2.fromBigTuple([BigInt(s),3n]); const rhs=Fp2.add(Fp2.mul(Fp2.sqr(x),x),b2);
    // try sqrt in Fp2
    try{ const y=Fp2.sqrt(rhs); if(eq(Fp2.sqr(y),rhs)) return {x,y}; }catch(e){} }
}
for(const seed of [1,7,13,99]){
  const Pt=onCurvePoint(seed);
  // check subgroup membership: r*Pt == O ?
  console.log(`nonsub seed=${seed} ->`, endoCheck(Pt));
}
