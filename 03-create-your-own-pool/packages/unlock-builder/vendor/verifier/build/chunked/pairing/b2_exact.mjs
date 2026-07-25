// EXACT worst-case |neg| for the lazy mul034 pre-reduction limbs.
// mul034's 12 wide output limbs are each MULTILINEAR (degree <=1) in the 12 F-limbs and the
// 6 o-limbs, so the min of each limb over the input box is attained at a VERTEX of the box.
// Brute-force all 2^18 vertices => the EXACT (not interval-loose) worst-case negativity.
// F_i in {0, p-1}; o0*/o3* in {0, p-1}; o4* in {0, o4max}. Compare to deployed bias.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;

const f2mW = (a0,a1,b0,b1) => { const w0=a0*b0, w1=a1*b1; return [w0-w1,(a0+a1)*(b0+b1)-w0-w1]; };
const f2xW = (a0,a1) => [9n*a0-a1, 9n*a1+a0];
const f6vWn = (a) => { const [n0a,n0b]=f2xW(a[4],a[5]); return [n0a,n0b,a[0],a[1],a[2],a[3]]; };
function f6m01(c,b0a,b0b,b1a,b1b){const[c0a,c0b,c1a,c1b,c2a,c2b]=c;
  const[t0a,t0b]=f2mW(c0a,c0b,b0a,b0b),[t1a,t1b]=f2mW(c1a,c1b,b1a,b1b);
  const[m12a,m12b]=f2mW(c1a+c2a,c1b+c2b,b1a,b1b),[xu0a,xu0b]=f2xW(m12a-t1a,m12b-t1b);
  const r0a=xu0a+t0a,r0b=xu0b+t0b;
  const[m1a,m1b]=f2mW(b0a+b1a,b0b+b1b,c0a+c1a,c0b+c1b);
  const r1a=m1a-t0a-t1a,r1b=m1b-t0b-t1b;
  const[m2a,m2b]=f2mW(c0a+c2a,c0b+c2b,b0a,b0b);
  const r2a=m2a-t0a+t1a,r2b=m2b-t0b+t1b;
  return[r0a,r0b,r1a,r1b,r2a,r2b];}
function pre034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const A0=f2mW(F[0],F[1],o0a,o0b),A2=f2mW(F[2],F[3],o0a,o0b),A4=f2mW(F[4],F[5],o0a,o0b);
  const A=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B=f6m01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>F[i]+F[6+i]);
  const G=f6m01(S,o0a+o3a,o0b+o3b,o4a,o4b);
  const VB=f6vWn(B);
  const Clo=[0,1,2,3,4,5].map(i=>VB[i]+A[i]);
  const Chi=[0,1,2,3,4,5].map(i=>G[i]-A[i]-B[i]);
  return[...Clo,...Chi];
}
const Pm = P - 1n;

function exactWorst(o4max) {
  const oVals = [[0n,Pm],[0n,Pm],[0n,Pm],[0n,Pm],[0n,o4max],[0n,o4max]]; // o0a,o0b,o3a,o3b,o4a,o4b
  let minLimb = new Array(12).fill(1n<<600n);
  let argmin = new Array(12).fill(null);
  const F = new Array(12);
  for (let om=0; om<64; om++){
    const o = [0,1,2,3,4,5].map(b=>oVals[b][(om>>b)&1]);
    for (let fm=0; fm<4096; fm++){
      for (let b=0;b<12;b++) F[b] = (fm>>b)&1 ? Pm : 0n;
      const pre = pre034(F,o[0],o[1],o[2],o[3],o[4],o[5]);
      for (let i=0;i<12;i++) if (pre[i]<minLimb[i]) { minLimb[i]=pre[i]; argmin[i]={fm,om}; }
    }
  }
  let worstNeg=0n, wi=-1;
  for (let i=0;i<12;i++){ const neg = minLimb[i]<0n ? -minLimb[i] : 0n; if (neg>worstNeg){worstNeg=neg; wi=i;} }
  return { worstNeg, wi, minLimb, argmin };
}

for (const k of [4n,5n,6n]) {
  const o4max = k*P; // upper end of [0,kp]; multilinear extremum uses the endpoint
  const r = exactWorst(o4max);
  const minDiv = BIAS - r.worstNeg;
  console.log(`o4 in [0,${k}p]  EXACT worst|neg| = ${r.worstNeg}  (~${(Number(r.worstNeg)/Number(P*P)).toFixed(2)} p^2)  at limb ${r.wi}`);
  console.log(`    bias - worst|neg| (min dividend) = ${minDiv}   ${minDiv>=0n?'>=0  SOUND':'<0  *** UNSOUND: FORGERY POSSIBLE ***'}   (marginP=${minDiv/P})`);
}
