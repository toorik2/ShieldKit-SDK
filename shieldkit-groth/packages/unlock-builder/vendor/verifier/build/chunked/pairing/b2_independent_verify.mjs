// B2 INDEPENDENT verification (written from scratch off V3_miller_lib.cash source).
// Goals:
//  (1) Mirror mul034's wide signed ops EXACTLY (fp2MulW, fp2MulXiW, fp6MulByVW, fp6Mul01W, mul034).
//  (2) PROVE each of the 12 pre-reduce output limbs is MULTILINEAR in the 18 inputs
//      (12 F-limbs, o0a,o0b,o3a,o3b,o4a,o4b) -> extremum over the input box is at a VERTEX.
//  (3) Exhaustively enumerate the 2^18 vertices at o4 in [0,6p] -> EXACT worst |neg|.
//  (4) Re-derive required BIG*p and byte length; compare to the DEPLOYED reduceOutMul constant.
//  (5) Confirm output-in-range: dividend >= 0 AND (pre+bias)%p == true residue for the worst case.
//  Also: fp12Mul exact worst |neg| at A,B in [0,p).
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
// deployed reduceOutMul constant, read from V3_miller_lib.cash line 209 / V3_mul_delayed.cash line 82
const DEPLOYED_MUL_BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;

// ---- exact wide signed ops (bit-for-bit mirror of V3_miller_lib.cash) ----
const f2mW = (a0,a1,b0,b1) => { const w0=a0*b0, w1=a1*b1; return [w0-w1, (a0+a1)*(b0+b1)-w0-w1]; };
const f2xW = (a0,a1) => [9n*a0-a1, 9n*a1+a0];
const f6vW = (a) => { const [n0a,n0b]=f2xW(a[4],a[5]); return [n0a,n0b,a[0],a[1],a[2],a[3]]; };
function f6m01(c,b0a,b0b,b1a,b1b){ const [c0a,c0b,c1a,c1b,c2a,c2b]=c;
  const [t0a,t0b]=f2mW(c0a,c0b,b0a,b0b), [t1a,t1b]=f2mW(c1a,c1b,b1a,b1b);
  const [m12a,m12b]=f2mW(c1a+c2a,c1b+c2b,b1a,b1b), [xu0a,xu0b]=f2xW(m12a-t1a,m12b-t1b);
  const r0a=xu0a+t0a, r0b=xu0b+t0b;
  const [m1a,m1b]=f2mW(b0a+b1a,b0b+b1b,c0a+c1a,c0b+c1b);
  const r1a=m1a-t0a-t1a, r1b=m1b-t0b-t1b;
  const [m2a,m2b]=f2mW(c0a+c2a,c0b+c2b,b0a,b0b);
  const r2a=m2a-t0a+t1a, r2b=m2b-t0b+t1b;
  return [r0a,r0b,r1a,r1b,r2a,r2b]; }
// PRE-reduce mul034 (12 wide limbs) exactly as V3_miller_lib.cash mul034 before reduceOutMul.
function pre034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const A0=f2mW(F[0],F[1],o0a,o0b), A2=f2mW(F[2],F[3],o0a,o0b), A4=f2mW(F[4],F[5],o0a,o0b);
  const A=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B=f6m01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>F[i]+F[6+i]);
  const G=f6m01(S,o0a+o3a,o0b+o3b,o4a,o4b);
  const VB=f6vW(B);
  const Clo=[0,1,2,3,4,5].map(i=>VB[i]+A[i]);
  const Chi=[0,1,2,3,4,5].map(i=>G[i]-A[i]-B[i]);
  return [...Clo,...Chi]; }
// PRE-reduce fp12Mul (12 wide limbs)
function f6mW(a,b){ const [a0a,a0b,a1a,a1b,a2a,a2b]=a, [b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const [t0a,t0b]=f2mW(a0a,a0b,b0a,b0b), [t1a,t1b]=f2mW(a1a,a1b,b1a,b1b), [t2a,t2b]=f2mW(a2a,a2b,b2a,b2b);
  const [p1a,p1b]=f2mW(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b), [x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a, c0b=t0b+x1b;
  const [p2a,p2b]=f2mW(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b), [x2a,x2b]=f2xW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a, c1b=p2b-t0b-t1b+x2b;
  const [p3a,p3b]=f2mW(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a, c2b=p3b-t0b-t2b+t1b;
  return [c0a,c0b,c1a,c1b,c2a,c2b]; }
function pre12Mul(A,B){ // A,B: 12 limbs each
  const Alo=A.slice(0,6), Ahi=A.slice(6,12), Blo=B.slice(0,6), Bhi=B.slice(6,12);
  const t0=f6mW(Alo,Blo), t1=f6mW(Ahi,Bhi);
  const vt=f6vW(t1);
  const Clo=[0,1,2,3,4,5].map(i=>t0[i]+vt[i]);
  const sa=[0,1,2,3,4,5].map(i=>Alo[i]+Ahi[i]), sb=[0,1,2,3,4,5].map(i=>Blo[i]+Bhi[i]);
  const pr=f6mW(sa,sb);
  const Chi=[0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]);
  return [...Clo,...Chi]; }

// ================= (2) MULTILINEARITY PROOF (mul034) =================
// A function g(x_1..x_n) is multilinear iff for every variable x_k, holding all others fixed,
// g is affine in x_k, i.e. the 2nd finite difference in x_k is 0:
//   g(..,x_k=a,..) - g(..,x_k=b,..) - (g(..,x_k=c,..) - g(..,x_k=d,..)) with equal steps == 0.
// Simpler exact test: g(x_k = t) must equal g(0) + t*(g(1)-g(0)) for ALL t (affine). We test with
// random background + 3 distinct probe values per variable and require exact linearity, for all
// 12 output limbs and all 18 variables. If any nonlinearity existed the vertex-min could be missed.
let s = 0x2545F4914F6CDD1Dn;
const rnd = () => { s^=s<<13n; s&=(1n<<64n)-1n; s^=s>>7n; s^=s<<17n; s&=(1n<<64n)-1n; return s; };
const rF = () => rnd()%P;                 // background F-limb in [0,p)
const rO4 = () => rnd()%(6n*P);           // background o4 in [0,6p)
function evalMul034(vars){ // vars: [F0..F11, o0a,o0b,o3a,o3b,o4a,o4b]
  return pre034(vars.slice(0,12), vars[12],vars[13],vars[14],vars[15],vars[16],vars[17]); }
function multilinearOK(trials){
  for (let t=0;t<trials;t++){
    const base = [];
    for (let i=0;i<12;i++) base.push(rF());
    base.push(rF(),rF(),rF(),rF(),rO4(),rO4());
    for (let k=0;k<18;k++){
      // three probe values for variable k (must lie in its natural domain, but affinity holds for ANY reals)
      const dom = k<16 ? P : 6n*P;
      const x0 = 0n, x1 = dom-1n, x2 = (dom/3n); // 0, top, and an interior third
      const mk = (val)=>{ const v=base.slice(); v[k]=val; return evalMul034(v); };
      const g0=mk(x0), g1=mk(x1), gm=mk(x2);
      for (let i=0;i<12;i++){
        // affine check: gm[i] must equal g0[i] + (g1[i]-g0[i])*(x2-x0)/(x1-x0), done exactly with cross-mult
        // gm*(x1-x0) == g0*(x1-x0) + (g1-g0)*(x2-x0)
        const lhs = gm[i]*(x1-x0);
        const rhs = g0[i]*(x1-x0) + (g1[i]-g0[i])*(x2-x0);
        if (lhs!==rhs) return {ok:false, k, i, t};
      }
    }
  }
  return {ok:true};
}

// ================= (3) EXHAUSTIVE VERTEX WORST |neg| (mul034, o4 in [0,6p]) =================
function exactWorstMul034(o4max){
  const Pm=P-1n;
  const oVals=[[0n,Pm],[0n,Pm],[0n,Pm],[0n,Pm],[0n,o4max],[0n,o4max]];
  const minLimb=new Array(12).fill(1n<<800n); const arg=new Array(12).fill(null);
  const F=new Array(12);
  for (let om=0; om<64; om++){
    const o=[0,1,2,3,4,5].map(b=>oVals[b][(om>>b)&1]);
    for (let fm=0; fm<4096; fm++){
      for (let b=0;b<12;b++) F[b]=(fm>>b)&1?Pm:0n;
      const pre=pre034(F,o[0],o[1],o[2],o[3],o[4],o[5]);
      for (let i=0;i<12;i++) if (pre[i]<minLimb[i]){minLimb[i]=pre[i]; arg[i]={fm,om,F:F.slice(),o:o.slice()};}
    }
  }
  let worst=0n, wi=-1;
  for (let i=0;i<12;i++){ const neg=minLimb[i]<0n?-minLimb[i]:0n; if(neg>worst){worst=neg;wi=i;} }
  return {worst, wi, minLimb, arg};
}
// fp12Mul exact worst |neg| (A,B in [0,p)): also multilinear (product of two DISTINCT input vectors),
// so vertex enum over 2^24 is too big; but each limb is BILINEAR (deg1 in A-vars, deg1 in B-vars),
// so min over box = min over the 4 combos of (A at vertex)x(B at vertex) PER MONOMIAL. We instead
// bound it via: worst is attained with each A-limb,B-limb in {0,p-1}. Random-restart hill search on
// the 24-var vertex cube gives a certified LOWER bound on |neg|; combined with the loose interval
// (988 p^2) upper bound it brackets the truth. (fp12Mul soundness already holds by the interval
// bound alone since 988 p^2 == bias; this is just to show real margin.)
function fp12MulVertexScan(iters){
  const Pm=P-1n; let worst=0n;
  let A=new Array(12), B=new Array(12);
  for (let it=0; it<iters; it++){
    for (let i=0;i<12;i++){A[i]=rnd()&1n?Pm:0n; B[i]=rnd()&1n?Pm:0n;}
    // local descent: flip each bit if it lowers some limb further
    for (let pass=0; pass<3; pass++){
      for (let v=0; v<24; v++){
        const arr=v<12?A:B, idx=v%12; const old=arr[idx];
        arr[idx]= old===0n?Pm:0n;
        const pre=pre12Mul(A,B); let mn=0n; for(const x of pre) if(x<0n && -x>mn) mn=-x;
        arr[idx]=old; const pre0=pre12Mul(A,B); let mn0=0n; for(const x of pre0) if(x<0n && -x>mn0) mn0=-x;
        if (mn>mn0) arr[idx]= old===0n?Pm:0n; // keep the flip if more negative
      }
    }
    const pre=pre12Mul(A,B); for(const x of pre) if(x<0n && -x>worst) worst=-x;
  }
  return worst;
}

const byteLen=(x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};
const mod=(x)=>((x%P)+P)%P;

console.log('P byteLen =', byteLen(P), ' (32-byte prime)');
console.log('\n=== (2) MULTILINEARITY of mul034 pre-reduce limbs (exact affine test) ===');
const ml = multilinearOK(2000);
console.log(ml.ok ? '  PROVEN multilinear over 2000 random backgrounds x 18 vars x 12 limbs (all affine, 2nd diff = 0)'
                  : `  *** NONLINEAR at var ${ml.k}, limb ${ml.i} *** (vertex-min would be INVALID)`);

console.log('\n=== (3) EXACT worst |neg| by exhaustive 2^18 vertex enumeration (mul034) ===');
for (const k of [4n,6n]){
  const r = exactWorstMul034(k*P);
  console.log(`  o4 in [0,${k}p]: EXACT worst|neg| = ${(Number(r.worst)/Number(P*P)).toFixed(2)} p^2  (limb ${r.wi})`);
}
const R6 = exactWorstMul034(6n*P);
console.log('\n=== (4) BIAS re-derivation (mul034, TRUE regime o4<=6p) ===');
const needBIG = R6.worst / P + 1n;                 // smallest integer BIG with BIG*p > worst
const needBias = needBIG * P;
console.log(`  worst|neg| (o4<=6p)   = ${R6.worst}`);
console.log(`  minimal required bias = ${needBias}  (BIG=${needBIG}, byteLen=${byteLen(needBias)})`);
console.log(`  DEPLOYED reduceOutMul = ${DEPLOYED_MUL_BIAS}`);
console.log(`  deployed byteLen      = ${byteLen(DEPLOYED_MUL_BIAS)}   deployed % p == 0 ? ${DEPLOYED_MUL_BIAS%P===0n}`);
console.log(`  deployed / p^2        = ${(Number(DEPLOYED_MUL_BIAS)/Number(P*P)).toFixed(1)}`);
console.log(`  deployed - worst|neg| = ${DEPLOYED_MUL_BIAS - R6.worst}  (${DEPLOYED_MUL_BIAS>=R6.worst?'>=0 COVERS':'<0 UNSOUND'}, margin ${(Number(DEPLOYED_MUL_BIAS-R6.worst)/Number(P*P)).toFixed(0)} p^2)`);

console.log('\n=== (5) OUTPUT-IN-RANGE at the worst vertex (dividend>=0 AND (pre+bias)%p == true residue) ===');
{
  // rebuild the worst vertex's full pre-limbs and check every limb
  const a = R6.arg[R6.wi];
  const pre = pre034(a.F, a.o[0],a.o[1],a.o[2],a.o[3],a.o[4],a.o[5]);
  let allGE0=true, allCanon=true, maxDivB=0;
  for (const x of pre){
    const div = x + DEPLOYED_MUL_BIAS;
    if (div < 0n) allGE0=false;
    // BCH OP_MOD on a nonneg dividend returns div % p in [0,p); check it equals the TRUE residue of x
    const outLimb = div % P;                 // (nonneg dividend) % p
    if (outLimb < 0n || outLimb >= P) allCanon=false;
    if (outLimb !== mod(x)) allCanon=false;  // == canonical residue of the intended value
    if (byteLen(div) > maxDivB) maxDivB = byteLen(div);
  }
  console.log(`  worst-vertex 12 limbs: dividend>=0 all ? ${allGE0}   output in [0,p) & == true residue ? ${allCanon}`);
  console.log(`  max dividend byteLen at worst vertex = ${maxDivB} bytes`);
}

console.log('\n=== fp12Mul (residue regime A,B in [0,p)) worst |neg| lower bound (vertex hill-scan) ===');
const fmWorst = fp12MulVertexScan(4000);
console.log(`  vertex-scan worst|neg| >= ${(Number(fmWorst)/Number(P*P)).toFixed(2)} p^2   (interval upper bound = 988 p^2 == bias; both inputs [0,p))`);
console.log(`  deployed bias - scan worst = ${(Number(DEPLOYED_MUL_BIAS - fmWorst)/Number(P*P)).toFixed(0)} p^2 margin (>=0 => covered)`);
