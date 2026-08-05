// SKEPTIC overflow-bound audit — written fresh, independent of b2_*.mjs.
// Mirrors V3_mul_delayed.cash / V3_miller_lib.cash ops. Two goals:
//  (A) EXACT worst-case pre-OP_MOD negativity for mul034 AND fp12Mul via the BILINEAR-FORM
//      decomposition (both pre-reduce limbs are pure bilinear forms => exact min in O(2^12)).
//  (B) Max intermediate wide-int magnitude / byteLen => VM number-size cap (10000 B) check.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const P2 = P*P;
const byteLen = (x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};

// ---- wide signed ops, re-typed independently from the .cash source ----
function fp2MulW(a0,a1,b0,b1){ const w0=a0*b0, w1=a1*b1; return [w0-w1,(a0+a1)*(b0+b1)-w0-w1]; }
function fp2MulXiW(a0,a1){ return [9n*a0-a1, 9n*a1+a0]; }
function fp6MulByVW(a){ const [n0,n1]=fp2MulXiW(a[4],a[5]); return [n0,n1,a[0],a[1],a[2],a[3]]; }
function fp6MulW(a,b){
  const [a0,a1,a2,a3,a4,a5]=a,[b0,b1,b2,b3,b4,b5]=b;
  const [t0,t1]=fp2MulW(a0,a1,b0,b1), [u0,u1]=fp2MulW(a2,a3,b2,b3), [v0,v1]=fp2MulW(a4,a5,b4,b5);
  const [p1,p2]=fp2MulW(a2+a4,a3+a5,b2+b4,b3+b5); const [x1,x2]=fp2MulXiW(p1-u0-v0,p2-u1-v1);
  const c0=t0+x1,c1=t1+x2;
  const [q1,q2]=fp2MulW(a0+a2,a1+a3,b0+b2,b1+b3); const [y1,y2]=fp2MulXiW(v0,v1);
  const c2=q1-t0-u0+y1, c3=q2-t1-u1+y2;
  const [r1,r2]=fp2MulW(a0+a4,a1+a5,b0+b4,b1+b5);
  const c4=r1-t0-v0+u0, c5=r2-t1-v1+u1;
  return [c0,c1,c2,c3,c4,c5];
}
function fp6Mul01W(c,b0,b1,b2,b3){ // c = 6 limbs, b0..b3 = two fp2
  const [c0,c1,c2,c3,c4,c5]=c;
  const [t0,t1]=fp2MulW(c0,c1,b0,b1), [u0,u1]=fp2MulW(c2,c3,b2,b3);
  const [m0,m1]=fp2MulW(c2+c4,c3+c5,b2,b3), [x0,x1]=fp2MulXiW(m0-u0,m1-u1);
  const r0=x0+t0, r1=x1+t1;
  const [n0,n1]=fp2MulW(b0+b2,b1+b3,c0+c2,c1+c3);
  const r2=n0-t0-u0, r3=n1-t1-u1;
  const [p0,p1]=fp2MulW(c0+c4,c1+c5,b0,b1);
  const r4=p0-t0+u0, r5=p1-t1+u1;
  return [r0,r1,r2,r3,r4,r5];
}
function preMul034(F,o){ // F: 12, o: [o0a,o0b,o3a,o3b,o4a,o4b]
  const [o0a,o0b,o3a,o3b,o4a,o4b]=o;
  const A0=fp2MulW(F[0],F[1],o0a,o0b), A2=fp2MulW(F[2],F[3],o0a,o0b), A4=fp2MulW(F[4],F[5],o0a,o0b);
  const A=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B=fp6Mul01W(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=F.slice(0,6).map((_,i)=>F[i]+F[6+i]);
  const G=fp6Mul01W(S,o0a+o3a,o0b+o3b,o4a,o4b);
  const VB=fp6MulByVW(B);
  return [0,1,2,3,4,5].map(i=>VB[i]+A[i]).concat([0,1,2,3,4,5].map(i=>G[i]-A[i]-B[i]));
}
function preFp12Mul(A,B){
  const Alo=A.slice(0,6),Ahi=A.slice(6,12),Blo=B.slice(0,6),Bhi=B.slice(6,12);
  const t0=fp6MulW(Alo,Blo), t1=fp6MulW(Ahi,Bhi), vt=fp6MulByVW(t1);
  const sa=Alo.map((_,i)=>Alo[i]+Ahi[i]), sb=Blo.map((_,i)=>Blo[i]+Bhi[i]);
  const pr=fp6MulW(sa,sb);
  return [0,1,2,3,4,5].map(i=>t0[i]+vt[i]).concat([0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]));
}

// ---- (0) sanity: pre-reduce limbs are pure BILINEAR forms (homogeneous deg1 in each side) ----
// L(kX,Y)=k L(X,Y), L(X,0)=0. Test on random vectors.
let seed=88172645463325252n;
const rnd=()=>{seed^=seed<<13n;seed&=(1n<<64n)-1n;seed^=seed>>7n;seed^=seed<<17n;seed&=(1n<<64n)-1n;return seed;};
function bilinearCheck(pre, nL, nR, trials){
  for(let t=0;t<trials;t++){
    const X=Array.from({length:nL},()=>rnd()%P), Y=Array.from({length:nR},()=>rnd()%P);
    const base=pre(X,Y);
    const k=rnd()%97n+2n;
    const Xk=X.map(v=>v*k), l1=pre(Xk,Y);
    const Yk=Y.map(v=>v*k), l2=pre(X,Yk);
    const Z=new Array(nL).fill(0n), l3=pre(Z,Y);
    for(let i=0;i<12;i++){
      if(l1[i]!==k*base[i]) return {ok:false,why:'left-homogeneity',i,t};
      if(l2[i]!==k*base[i]) return {ok:false,why:'right-homogeneity',i,t};
      if(l3[i]!==0n) return {ok:false,why:'nonzero-at-origin',i,t};
    }
  }
  return {ok:true};
}

// ---- extract 12 bilinear coefficient matrices M[limb][i][j] (L = sum_ij M[i][j] X_i Y_j) ----
function extractM(pre,nL,nR){
  const M=Array.from({length:12},()=>Array.from({length:nL},()=>new Array(nR).fill(0n)));
  for(let i=0;i<nL;i++)for(let j=0;j<nR;j++){
    const X=new Array(nL).fill(0n), Y=new Array(nR).fill(0n); X[i]=1n; Y[j]=1n;
    const L=pre(X,Y);
    for(let l=0;l<12;l++) M[l][i][j]=L[l];
  }
  return M;
}
// verify M reproduces pre() on random inputs (guards the extraction)
function verifyM(pre,M,nL,nR,trials){
  for(let t=0;t<trials;t++){
    const X=Array.from({length:nL},()=>rnd()%(6n*P)), Y=Array.from({length:nR},()=>rnd()%(6n*P));
    const L=pre(X,Y);
    for(let l=0;l<12;l++){
      let s=0n; for(let i=0;i<nL;i++)for(let j=0;j<nR;j++) s+=M[l][i][j]*X[i]*Y[j];
      if(s!==L[l]) return {ok:false,l,t};
    }
  }
  return {ok:true};
}
// EXACT min of a bilinear form over box: X_i in {0,xhi[i]}, Y_j in {0,yhi[j]}.
// For fixed X-vertex, L linear in each Y_j => min picks Y_j endpoint by sign of column sum.
// Enumerate 2^nL X-vertices (nL<=12 => 4096). Returns most-negative value across the 12 limbs.
function exactWorstNeg(M,nL,nR,xhi,yhi){
  let worst=0n, arg=null;
  for(let xm=0; xm<(1<<nL); xm++){
    const X=[]; for(let i=0;i<nL;i++) X.push((xm>>i)&1?xhi[i]:0n);
    for(let l=0;l<12;l++){
      // g_j = sum_i M[l][i][j]*X_i ; min_Y = sum_j min(0, g_j*yhi[j])
      let mn=0n;
      for(let j=0;j<nR;j++){
        let g=0n; for(let i=0;i<nL;i++) g+=M[l][i][j]*X[i];
        const term=g*yhi[j]; if(term<0n) mn+=term;
      }
      if(mn<0n && -mn>worst){ worst=-mn; arg={xm,l}; }
    }
  }
  return {worst,arg};
}

console.log('=== bias facts ===');
console.log('BIAS % p == 0 :', BIAS%P===0n, '   BIAS/p^2 =', (Number(BIAS)/Number(P2)).toFixed(3), '   byteLen =', byteLen(BIAS));

console.log('\n=== bilinearity (independent homogeneity/origin test) ===');
console.log('mul034  :', bilinearCheck(preMul034,12,6,3000));
console.log('fp12Mul :', bilinearCheck(preFp12Mul,12,12,3000));

const Mmul=extractM(preMul034,12,6);
const Mf12=extractM(preFp12Mul,12,12);
console.log('\n=== coeff-matrix extraction verified against direct eval ===');
console.log('mul034  :', verifyM(preMul034,Mmul,12,6,4000));
console.log('fp12Mul :', verifyM(preFp12Mul,Mf12,12,12,4000));

console.log('\n=== EXACT worst |neg| via bilinear-form vertex min ===');
// mul034 TRUE regime: F_i in [0,p) -> vertex p-1 ; o0a,o0b,o3a,o3b in [0,p) ; o4a,o4b in [0,6p]
const Pm=P-1n;
for(const [tag,kk] of [['4p',4n],['6p',6n],['8p',8n],['12p',12n],['24p',24n]]){
  const {worst}=exactWorstNeg(Mmul,12,6,new Array(12).fill(Pm),[Pm,Pm,Pm,Pm,kk*P,kk*P]);
  const margin=BIAS-worst;
  console.log(`  mul034 o4<=${tag.padEnd(4)}: worst|neg| = ${(Number(worst)/Number(P2)).toFixed(2).padStart(7)} p^2   bias-worst = ${(Number(margin)/Number(P2)).toFixed(1).padStart(8)} p^2   ${margin>=0n?'SOUND':'*** UNSOUND ***'}`);
}
// fp12Mul TRUE regime: A_i,B_j in [0,p)
{
  const {worst}=exactWorstNeg(Mf12,12,12,new Array(12).fill(Pm),new Array(12).fill(Pm));
  const margin=BIAS-worst;
  console.log(`  fp12Mul A,B in[0,p): EXACT worst|neg| = ${(Number(worst)/Number(P2)).toFixed(2)} p^2   bias-worst = ${(Number(margin)/Number(P2)).toFixed(1)} p^2   ${margin>=0n?'SOUND':'*** UNSOUND ***'}`);
}
// stress: what F-magnitude (if F were lazy-carried unreduced) breaks the bias? shows F-reduction is load-bearing
console.log('\n=== sensitivity: if F entered mul034 UNREDUCED at [0,k*p) (o4<=6p) ===');
for(const kf of [1n,2n,4n,8n,16n,32n]){
  const {worst}=exactWorstNeg(Mmul,12,6,new Array(12).fill(kf*P-1n),[Pm,Pm,Pm,Pm,6n*P,6n*P]);
  console.log(`  F in [0,${kf}p): worst|neg| = ${(Number(worst)/Number(P2)).toFixed(1).padStart(9)} p^2   ${BIAS-worst>=0n?'covered':'*** BIAS BREACHED ***'}`);
}

// ---- (B) number-size cap: max |intermediate| across all wide sub-expressions + dividend ----
function maxIntermediateMul034(F,o){
  let mx=0n; const t=(x)=>{const a=x<0n?-x:x; if(a>mx)mx=a; return x;};
  const [o0a,o0b,o3a,o3b,o4a,o4b]=o.map(t);
  F=F.map(t);
  const f2=(a0,a1,b0,b1)=>{const w0=t(a0*b0),w1=t(a1*b1);return [t(w0-w1),t(t(t(a0+a1)*t(b0+b1))-w0-w1)];};
  const fx=(a0,a1)=>[t(t(9n*a0)-a1),t(t(9n*a1)+a0)];
  const A0=f2(F[0],F[1],o0a,o0b),A2=f2(F[2],F[3],o0a,o0b),A4=f2(F[4],F[5],o0a,o0b);
  const A=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const m01=(c,b0,b1,b2,b3)=>{const[c0,c1,c2,c3,c4,c5]=c;
    const[t0,t1]=f2(c0,c1,b0,b1),[u0,u1]=f2(c2,c3,b2,b3);
    const[m0,m1]=f2(t(c2+c4),t(c3+c5),b2,b3),[x0,x1]=fx(t(m0-u0),t(m1-u1));
    const r0=t(x0+t0),r1=t(x1+t1);
    const[n0,n1]=f2(t(b0+b2),t(b1+b3),t(c0+c2),t(c1+c3));
    const r2=t(n0-t0-u0),r3=t(n1-t1-u1);
    const[p0,p1]=f2(t(c0+c4),t(c1+c5),b0,b1);
    const r4=t(p0-t0+u0),r5=t(p1-t1+u1);
    return[r0,r1,r2,r3,r4,r5];};
  const B=m01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>t(F[i]+F[6+i]));
  const G=m01(S,t(o0a+o3a),t(o0b+o3b),o4a,o4b);
  const [n0,n1]=fx(B[4],B[5]); const VB=[n0,n1,B[0],B[1],B[2],B[3]];
  const out=[];
  for(let i=0;i<6;i++) out.push(t(VB[i]+A[i]));
  for(let i=0;i<6;i++) out.push(t(G[i]-A[i]-B[i]));
  const div=out.map(x=>t(x+BIAS)); // dividend fed to OP_MOD
  return {mx, maxDivByte:Math.max(...div.map(byteLen))};
}
// worst-vertex inputs for max magnitude: F=p-1, o4=6p
{
  const F=new Array(12).fill(Pm);
  const o=[Pm,Pm,Pm,Pm,6n*P,6n*P];
  const {mx,maxDivByte}=maxIntermediateMul034(F,o);
  console.log('\n=== (B) number-size cap (mul034, worst-magnitude inputs F=p-1,o4=6p) ===');
  console.log('  max |intermediate wide-int| byteLen =', byteLen(mx), 'bytes   (VM cap = 10000 B)');
  console.log('  max dividend byteLen (fed to OP_MOD) =', maxDivByte, 'bytes');
  console.log('  cap satisfied:', byteLen(mx)<10000 && maxDivByte<10000);
}
