// Soundness stress for V2 delayed-reduction fp12Sqr.
// 1) Independently compute the SIGNED pre-reduction limb values (mirror of the .cash, exact BigInt)
//    over many inputs (random + adversarial corners) and confirm none is below -BIG*p  => the mod
//    dividend (x+BIG*p) is always >= 0 => reduceOut lands in [0,p). This is the A1 non-forgery gate.
// 2) Confirm reduceOut(pre) === noble Fp12.sqr(input) mod p for every case (formula correctness).
import { Fp12, Fp } from './_millermath.mjs';
const P = Fp.ORDER;
const BIGxP = 507361791401603590146065339884462786506408203206435770960198222587060229213828216047103990131139210776525628370024303086564595223859909885393566267333524240n;

// exact signed BigInt mirror of the .cash V2 computation
const f2mulW = (a0,a1,b0,b1) => { const w0=a0*b0, w1=a1*b1; return [w0-w1, (a0+a1)*(b0+b1)-w0-w1]; };
const f2xiW  = (a0,a1) => [9n*a0-a1, 9n*a1+a0];
function f6mulW(a,b){ // a,b arrays of 6
  const [a0a,a0b,a1a,a1b,a2a,a2b]=a, [b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const [t0a,t0b]=f2mulW(a0a,a0b,b0a,b0b);
  const [t1a,t1b]=f2mulW(a1a,a1b,b1a,b1b);
  const [t2a,t2b]=f2mulW(a2a,a2b,b2a,b2b);
  const [p1a,p1b]=f2mulW(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b);
  const [x1a,x1b]=f2xiW(p1a-t1a-t2a, p1b-t1b-t2b);
  const c0a=t0a+x1a, c0b=t0b+x1b;
  const [p2a,p2b]=f2mulW(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b);
  const [x2a,x2b]=f2xiW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a, c1b=p2b-t0b-t1b+x2b;
  const [p3a,p3b]=f2mulW(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a, c2b=p3b-t0b-t2b+t1b;
  return [c0a,c0b,c1a,c1b,c2a,c2b];
}
const f6vW = (a) => { const [n0a,n0b]=f2xiW(a[4],a[5]); return [n0a,n0b,a[0],a[1],a[2],a[3]]; };
function preReduce(A){ // A: 12 limbs -> 12 signed pre-reduction values (Clo0..5, Chi0..5)
  const lo=A.slice(0,6), hi=A.slice(6,12);
  const t0=f6mulW(lo,hi);
  const vc=f6vW(hi);
  const s=lo.map((x,i)=>x+hi[i]);
  const u=lo.map((x,i)=>x+vc[i]);
  const t1=f6mulW(s,u);
  const vt0=f6vW(t0);
  const Clo=[0,1,2,3,4,5].map(i=> t1[i]-t0[i]-vt0[i]);
  const Chi=[0,1,2,3,4,5].map(i=> t0[i]+t0[i]);
  return [...Clo,...Chi];
}
// noble reference
const mk2=(a,b)=>({c0:a,c1:b});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleSqr=(L)=>flat(Fp12.sqr(toF12(L.map(x=>((x%P)+P)%P))));

let minDividend = 1n<<400n, worstNeg=0n, formulaFails=0, dividendFails=0, n=0;
function test(L){
  n++;
  const pre = preReduce(L);
  const exp = nobleSqr(L);
  for(let i=0;i<12;i++){
    const div = pre[i] + BIGxP;
    if (div < minDividend) minDividend = div;
    if (pre[i] < 0n && -pre[i] > worstNeg) worstNeg = -pre[i];
    if (div < 0n) dividendFails++;
    const red = ((div % P)+P)%P;
    if (red !== exp[i]) formulaFails++;
  }
}
// random
let s=88172645463325252n;
const rnd=()=>{ s^=s<<13n; s&=(1n<<64n)-1n; s^=s>>7n; s^=s<<17n; s&=(1n<<64n)-1n; return s; };
const rndFull=()=>{ let x=0n; for(let k=0;k<4;k++) x=(x<<64n)|rnd(); return x%P; };
for(let t=0;t<2000;t++) test(Array.from({length:12},()=>rndFull()));
// adversarial corners: each limb in {0, 1, p-1} in structured patterns
const corners=[0n,1n,P-1n];
for(let mask=0; mask<300; mask++){ // random corner assignments
  test(Array.from({length:12},()=> corners[Number(rnd()% 3n)]));
}
// all p-1, all 0, alternating
test(Array.from({length:12},()=>P-1n));
test(Array.from({length:12},()=>0n));
test(Array.from({length:12},(_,i)=> i%2? P-1n:0n));
test(Array.from({length:12},(_,i)=> i<6? P-1n:0n));

console.log(`cases tested: ${n*12} limbs across ${n} inputs`);
console.log(`worst observed |neg pre-reduce| = ${worstNeg} (~${(Number(worstNeg)/Number(P*P)).toFixed(1)} p^2)`);
console.log(`min dividend (pre+BIGxP)        = ${minDividend}  (>=0 required)`);
console.log(`dividend<0 failures = ${dividendFails}   formula(mod p mismatch vs noble) failures = ${formulaFails}`);
console.log(dividendFails===0 && formulaFails===0 ? 'SOUND: all dividends >=0 AND all limbs match noble mod p' : 'UNSOUND -- INVESTIGATE');
