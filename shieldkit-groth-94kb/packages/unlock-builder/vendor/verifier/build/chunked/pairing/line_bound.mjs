// Sound interval bound on line/mul034 OUTPUT magnitude (the fp12Sqr input in Miller).
// Model: mulFp(x,y) reduces => output in [0,P) for any non-negative inputs; addFp/subFp exact.
// This yields a bound INDEPENDENT of the f-input scale (every product is reduced), so it holds
// for ALL f entering the chunk. Then recompute the delayed-reduction fp12Sqr bias for that input
// bound so V2 is a sound Miller drop-in.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const I=(lo,hi)=>({lo,hi});
const add=(a,b)=>I(a.lo+b.lo,a.hi+b.hi);
const sub=(a,b)=>I(a.lo-b.hi,a.hi-b.lo);
const RED=()=>I(0n,P-1n);                         // mulFp reduces -> [0,P)
const subFp=(a,b,k)=>{k=BigInt(k);return I(a.lo-b.hi+k*P, a.hi-b.lo+k*P);};
// fp2 = [c0,c1]
const f2add=(a,b)=>[add(a[0],b[0]),add(a[1],b[1])];
const f2mul=()=>[RED(),RED()];                    // both comps reduced-scale: r0=subFp(v0,v1,1)->[0,2p); r1=subFp(m,v0+v1,2)->(0,3p)
// exact fp2Mul output ranges (baseline): r0=subFp(v0,v1,1), r1=subFp(mulFp,addFp(v0,v1),2)
const f2mulExact=()=>[ subFp(RED(),RED(),1), subFp(RED(),add(RED(),RED()),2) ];
const f2mulxi=(a,k)=>[ subFp(RED(),a[1],k), add(RED(),a[0]) ]; // subFp(mulFp(9,a0),a1,k), addFp(mulFp(9,a1),a0)
const f6add=(a,b)=>[f2add(a[0],b[0]),f2add(a[1],b[1]),f2add(a[2],b[2])];
const f6sub=(a,b,k)=>[[subFp(a[0][0],b[0][0],k),subFp(a[0][1],b[0][1],k)],[subFp(a[1][0],b[1][0],k),subFp(a[1][1],b[1][1],k)],[subFp(a[2][0],b[2][0],k),subFp(a[2][1],b[2][1],k)]];
const f6mulbyv=(a,k)=>[f2mulxi(a[2],k), a[0], a[1]];
// fp6Mul01 output ranges (baseline structure)
function f6mul01(){
  const t0=f2mulExact(), t1=f2mulExact();
  const u0=[subFp(RED(),t1[0],3),subFp(RED(),t1[1],3)];  // subFp(m12,t1,3)
  const xu0=f2mulxi(u0,6);
  const r0=f2add(xu0,t0);
  const u1=[subFp(RED(),t0[0],3),subFp(RED(),t0[1],3)];
  const r1=[subFp(u1[0],t1[0],3),subFp(u1[1],t1[1],3)];
  const u2=[subFp(RED(),t0[0],3),subFp(RED(),t0[1],3)];
  const r2=f2add(u2,t1);
  return [r0,r1,r2];
}
// mul034 output (baseline): C0..5=fp6Add(VB,A); C6..11=fp6Sub(G,AB,12)
function mul034(){
  const A=[f2mulExact(),f2mulExact(),f2mulExact()];   // A0..A5
  const B=f6mul01();                                   // B0..B5
  const G=f6mul01();                                   // G0..G5
  const VB=f6mulbyv(B,9);
  const C_lo=f6add(VB,A);
  const AB=f6add(A,B);
  const C_hi=f6sub(G,AB,12);
  const flat=(f)=>[f[0][0],f[0][1],f[1][0],f[1][1],f[2][0],f[2][1]];
  return [...flat(C_lo),...flat(C_hi)];
}
const out=mul034();
let maxHi=0n, minLo=0n;
out.forEach(o=>{ if(o.hi>maxHi)maxHi=o.hi; if(o.lo<minLo)minLo=o.lo; });
const Bin = maxHi/P + 1n;   // line output limbs in [minLo, maxHi] ; use upper bound in units of p
console.log('line/mul034 output limb range: [', (Number(minLo)/Number(P)).toFixed(2),'p ,', (Number(maxHi)/Number(P)).toFixed(2),'p ]');
console.log('all outputs >= 0 :', minLo>=0n);
console.log('Bin (upper bound in units of p) =', Bin.toString());
