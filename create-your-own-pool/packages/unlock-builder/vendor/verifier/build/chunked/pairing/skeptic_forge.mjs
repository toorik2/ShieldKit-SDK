// SKEPTIC in-vm-forgery audit of fp12Mul-lazy / mul034-lazy (reduceOutMul bias).
// Written fresh. Re-derives pre-reduce limbs from V3_millerres_lib.cash, computes EXACT worst|neg|
// (not a scan) for BOTH mul034 (o4<=6p) and residue fp12Mul (A,B in [0,p)) using the
// multilinear/bilinear structure, and stress-tests the o4 structural bound + a break-past-6p test.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const P2 = P*P;
const asP2 = (x)=> (Number(x)/Number(P2)).toFixed(2);
const byteLen=(x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};

// ---------- wide signed ops, transcribed from V3_millerres_lib.cash (lines 146-249) ----------
const f2mW=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return[w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xW=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
const f6vW=(a)=>{const[n0a,n0b]=f2xW(a[4],a[5]);return[n0a,n0b,a[0],a[1],a[2],a[3]];};
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
  const VB=f6vW(B);
  return[...[0,1,2,3,4,5].map(i=>VB[i]+A[i]),...[0,1,2,3,4,5].map(i=>G[i]-A[i]-B[i])];}
function f6mW(a,b){const[a0a,a0b,a1a,a1b,a2a,a2b]=a,[b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const[t0a,t0b]=f2mW(a0a,a0b,b0a,b0b),[t1a,t1b]=f2mW(a1a,a1b,b1a,b1b),[t2a,t2b]=f2mW(a2a,a2b,b2a,b2b);
  const[p1a,p1b]=f2mW(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b),[x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a,c0b=t0b+x1b;
  const[p2a,p2b]=f2mW(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b),[x2a,x2b]=f2xW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
  const[p3a,p3b]=f2mW(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;
  return[c0a,c0b,c1a,c1b,c2a,c2b];}
function pre12Mul(A,B){
  const Alo=A.slice(0,6),Ahi=A.slice(6,12),Blo=B.slice(0,6),Bhi=B.slice(6,12);
  const t0=f6mW(Alo,Blo),t1=f6mW(Ahi,Bhi),vt=f6vW(t1);
  const Clo=[0,1,2,3,4,5].map(i=>t0[i]+vt[i]);
  const sa=[0,1,2,3,4,5].map(i=>Alo[i]+Ahi[i]),sb=[0,1,2,3,4,5].map(i=>Blo[i]+Bhi[i]);
  const pr=f6mW(sa,sb);
  const Chi=[0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]);
  return[...Clo,...Chi];}

const Pm=P-1n;
// ---------- EXACT worst|neg| for mul034: 2^12 F-vertices x sign-optimal o (linear in o) ----------
// For fixed F, each pre-limb is AFFINE in the 6 o-vars; min over o-box by per-coord sign.
function exactMul034(o4max){
  const oLo=[0n,0n,0n,0n,0n,0n], oHi=[Pm,Pm,Pm,Pm,o4max,o4max];
  const minLimb=new Array(12).fill(1n<<900n); const witness=new Array(12).fill(null);
  const F=new Array(12);
  for(let fm=0;fm<4096;fm++){
    for(let b=0;b<12;b++)F[b]=(fm>>b)&1?Pm:0n;
    const L0=pre034(F,oLo[0],oLo[1],oLo[2],oLo[3],oLo[4],oLo[5]); // o at lower bound (all 0)
    // coefficient of each o-var per limb: L(o_j=hi)-L(o_j=lo)
    const coeff=[]; // coeff[j] = array of 12
    for(let j=0;j<6;j++){const o=oLo.slice();o[j]=oHi[j];const Lj=pre034(F,o[0],o[1],o[2],o[3],o[4],o[5]);coeff.push(Lj.map((v,i)=>v-L0[i]));}
    for(let i=0;i<12;i++){
      let v=L0[i];
      for(let j=0;j<6;j++){ if(coeff[j][i]<0n) v+=coeff[j][i]; } // add hi-contribution only if it lowers
      if(v<minLimb[i]){minLimb[i]=v; witness[i]={fm,pickHi:[0,1,2,3,4,5].map(j=>coeff[j][i]<0n)};}
    }
  }
  let worst=0n,wi=-1; for(let i=0;i<12;i++){const neg=minLimb[i]<0n?-minLimb[i]:0n; if(neg>worst){worst=neg;wi=i;}}
  return {worst,wi,minLimb,witness};
}
// ---------- EXACT worst|neg| for fp12Mul: 2^12 A-vertices x sign-optimal B (linear in B) ----------
function exactFp12Mul(){
  const minLimb=new Array(12).fill(1n<<900n); const witA=new Array(12).fill(null);
  const A=new Array(12), B0=new Array(12).fill(0n);
  for(let am=0;am<4096;am++){
    for(let b=0;b<12;b++)A[b]=(am>>b)&1?Pm:0n;
    // Only the low-12-bit A-vertices? A has 12 limbs -> 2^12 vertices. Good.
    const L0=pre12Mul(A,B0);
    const coeff=[];
    for(let j=0;j<12;j++){const B=B0.slice();B[j]=Pm;const Lj=pre12Mul(A,B);coeff.push(Lj.map((v,i)=>v-L0[i]));}
    for(let i=0;i<12;i++){
      let v=L0[i];
      for(let j=0;j<12;j++){ if(coeff[j][i]<0n) v+=coeff[j][i]; }
      if(v<minLimb[i]){minLimb[i]=v; witA[i]=am;}
    }
  }
  let worst=0n,wi=-1; for(let i=0;i<12;i++){const neg=minLimb[i]<0n?-minLimb[i]:0n; if(neg>worst){worst=neg;wi=i;}}
  return {worst,wi,minLimb};
}

console.log('=== EXACT worst|neg| (multilinear vertex, per-limb sign-optimal opposite operand) ===');
for(const k of [4n,6n,8n,10n,12n]){
  const r=exactMul034(k*P);
  const div = -r.worst + BIAS;
  console.log(`  mul034 o4<=${k}p : worst|neg|=${asP2(r.worst)} p^2  bias-worst=${asP2(BIAS-r.worst)} p^2  minDividend ${div>=0n?'>=0 SOUND':'<0 *** FORGERY WINDOW ***'}`);
}
{const r=exactFp12Mul();
 console.log(`  fp12Mul A,B in[0,p): EXACT worst|neg|=${asP2(r.worst)} p^2 (limb ${r.wi})  bias-worst=${asP2(BIAS-r.worst)} p^2  ${BIAS-r.worst>=0n?'>=0 SOUND':'*** FORGERY WINDOW ***'}`);
}

// ---------- structural o4 (=raw line c0) ceiling: is it really <=6p for in-[0,p) point coords? ----------
// Mirror pointDouble c0 (fp2Sub(t2,t0,1)) and pointAdd c0 (fp2Sub(t0qx,t1qy,3)); every t* is a mulFp
// output in [0,p). Adversarially search reduced inputs for the largest c0a/c0b.
const mulFp=(x,y)=>((x*y)%P+P)%P;
const subFp=(x,y,k)=>x-y+k*P;
function pdC0(){ // pointDouble c0 range: t2,t0 in [0,p); c0=subFp(t2,t0,1)
  // max over t2,t0 in [0,p): max = (p-1)-0+p = 2p-1 ; min = 0-(p-1)+p = p+1
  return {max:subFp(Pm,0n,1n), min:subFp(0n,Pm,1n)};
}
function paC0(){ // pointAdd c0=subFp(t0qx,t1qy,3)
  return {max:subFp(Pm,0n,3n), min:subFp(0n,Pm,3n)};
}
const pd=pdC0(), pa=paC0();
console.log('\n=== structural o4 = raw line c0 ceiling (inputs = mulFp outputs in [0,p)) ===');
console.log(`  pointDouble c0: [${asP2(pd.min*P/P2)}?] max=${(Number(pd.max)/Number(P)).toFixed(3)}p  min=${(Number(pd.min)/Number(P)).toFixed(3)}p`);
console.log(`  pointAdd    c0: max=${(Number(pa.max)/Number(P)).toFixed(3)}p  min=${(Number(pa.min)/Number(P)).toFixed(3)}p`);
console.log(`  => structural o4 in (0, 4p) ; audit's conservative box uses 6p (extra headroom).`);

// ---------- BREAK TEST: find the o4 at which reduceOutMul first yields a WRONG residue ----------
// Drive the worst-case limb0 with o4a=o4b=o4, everything at the min-inducing vertex, increase o4.
console.log('\n=== break test: smallest o4 (uniform) that makes SOME dividend < 0 (wrong residue) ===');
{
  // reuse worst vertex structure from exactMul034(6p): F all p-1 or 0, o0/o3 at p-1 or 0, o4 large.
  const r=exactMul034(6n*P); const w=r.witness[r.wi];
  const F=new Array(12); for(let b=0;b<12;b++)F[b]=(w.fm>>b)&1?Pm:0n;
  const oLoHi=[[0n,Pm],[0n,Pm],[0n,Pm],[0n,Pm]]; // o0a,o0b,o3a,o3b picks
  const opick=[0,1,2,3].map(j=>w.pickHi[j]?oLoHi[j][1]:oLoHi[j][0]);
  const o4pickHi=[w.pickHi[4],w.pickHi[5]];
  let broke=null;
  for(let mult=6n; mult<=400n; mult++){
    const o4a=o4pickHi[0]?mult*P:0n, o4b=o4pickHi[1]?mult*P:0n;
    const pre=pre034(F,opick[0],opick[1],opick[2],opick[3],o4a,o4b);
    let neg=false; for(const x of pre) if(x+BIAS<0n) neg=true;
    if(neg){broke=mult;break;}
  }
  console.log(`  first o4 multiple with a negative dividend at the worst vertex: ${broke===null?'>400p (never in range)':broke+'p'}  (deployed regime ceiling 6p)`);
}
