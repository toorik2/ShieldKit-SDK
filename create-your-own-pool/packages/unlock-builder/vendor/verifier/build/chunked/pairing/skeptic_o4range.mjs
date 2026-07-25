// Empirically bound o4 = c0 (raw line coeff) in the LAZY .cash arithmetic (Bn254Lazy.cash
// pointDouble/pointAdd), and confirm R stays bounded (number-cap). Mirrors the .cash primitives:
//   mulFp = (x*y)%p  (ALWAYS reduces)   subFp(x,y,k)=x-y+k*p   addFp=x+y
// c0 bound is input-magnitude-independent because every term routes through mulFp. We stress it by
// feeding R components UNREDUCED (up to bigMul*p) to prove the bound survives lazy-carried R.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const B_RE = 19485874751759354771024239261021720505790618469301721065564631296452457478373n;
const B_IM = 266929791119991161246907387137283842545076965332900288569378510910307636690n;
const HALF = 10944121435919637611123202872628637544348155578648911831344518947322613104292n;
const byteLen=(x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};
let seed=0x1234567deadbeefn;
const rnd=()=>{seed^=seed<<13n;seed&=(1n<<64n)-1n;seed^=seed>>7n;seed^=seed<<17n;seed&=(1n<<64n)-1n;return seed;};

const mulFp=(x,y)=>((x*y)%P);   // note: JS % on nonneg*nonneg stays nonneg; inputs here always nonneg
const subFp=(x,y,k)=>x-y+k*P;
const addFp=(x,y)=>x+y;
const fp2Add=(a0,a1,b0,b1)=>[addFp(a0,b0),addFp(a1,b1)];
const fp2Sub=(a0,a1,b0,b1,k)=>[subFp(a0,b0,k),subFp(a1,b1,k)];
const fp2Neg=(a0,a1,k)=>[subFp(0n,a0,k),subFp(0n,a1,k)];
const fp2Mul=(a0,a1,b0,b1)=>{const v0=mulFp(a0,b0),v1=mulFp(a1,b1);
  return [subFp(v0,v1,1n), subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1),2n)];};
const fp2Sqr=(a0,a1)=>[mulFp(addFp(a0,a1),subFp(a0,a1,64n)), mulFp(2n,mulFp(a0,a1))];
const fp2Scale=(a0,a1,k)=>[mulFp(a0,k),mulFp(a1,k)];
const fp2MulByB=(a0,a1)=>fp2Mul(a0,a1,B_RE,B_IM);
const fp2Half=(a0,a1)=>[mulFp(a0,HALF),mulFp(a1,HALF)];

function pointDouble(Xa,Xb,Ya,Yb,Za,Zb){
  const [t0a,t0b]=fp2Sqr(Ya,Yb);
  const [t1a,t1b]=fp2Sqr(Za,Zb);
  const [s1a,s1b]=fp2Scale(t1a,t1b,3n);
  const [t2a,t2b]=fp2MulByB(s1a,s1b);
  const [t3a,t3b]=fp2Scale(t2a,t2b,3n);
  const [yza,yzb]=fp2Add(Ya,Yb,Za,Zb);
  const [sqa,sqb]=fp2Sqr(yza,yzb);
  const [u4a,u4b]=fp2Sub(sqa,sqb,t1a,t1b,1n);
  const [t4a,t4b]=fp2Sub(u4a,u4b,t0a,t0b,1n);
  const [c0a,c0b]=fp2Sub(t2a,t2b,t0a,t0b,1n);
  const [rxqa,rxqb]=fp2Sqr(Xa,Xb);
  const [c1a,c1b]=fp2Scale(rxqa,rxqb,3n);
  const [c2a,c2b]=fp2Neg(t4a,t4b,64n);
  const [da,db]=fp2Sub(t0a,t0b,t3a,t3b,1n);
  const [dxa,dxb]=fp2Mul(da,db,Xa,Xb);
  const [dxya,dxyb]=fp2Mul(dxa,dxb,Ya,Yb);
  const [nxa,nxb]=fp2Half(dxya,dxyb);
  const [sa,sb]=fp2Add(t0a,t0b,t3a,t3b);
  const [sha,shb]=fp2Half(sa,sb);
  const [sh2a,sh2b]=fp2Sqr(sha,shb);
  const [t2sa,t2sb]=fp2Sqr(t2a,t2b);
  const [t2s3a,t2s3b]=fp2Scale(t2sa,t2sb,3n);
  const [nya,nyb]=fp2Sub(sh2a,sh2b,t2s3a,t2s3b,1n);
  const [nza,nzb]=fp2Mul(t0a,t0b,t4a,t4b);
  return {c0:[c0a,c0b],R:[nxa,nxb,nya,nyb,nza,nzb]};
}
function pointAdd(Xa,Xb,Ya,Yb,Za,Zb,Qxa,Qxb,Qya,Qyb){
  const [qyza,qyzb]=fp2Mul(Qya,Qyb,Za,Zb);
  const [t0a,t0b]=fp2Sub(Ya,Yb,qyza,qyzb,3n);
  const [qxza,qxzb]=fp2Mul(Qxa,Qxb,Za,Zb);
  const [t1a,t1b]=fp2Sub(Xa,Xb,qxza,qxzb,3n);
  const [t0qxa,t0qxb]=fp2Mul(t0a,t0b,Qxa,Qxb);
  const [t1qya,t1qyb]=fp2Mul(t1a,t1b,Qya,Qyb);
  const [c0a,c0b]=fp2Sub(t0qxa,t0qxb,t1qya,t1qyb,3n);
  const [c1a,c1b]=fp2Neg(t0a,t0b,64n);
  const c2a=t1a,c2b=t1b;
  const [t2a,t2b]=fp2Sqr(t1a,t1b);
  const [t3a,t3b]=fp2Mul(t2a,t2b,t1a,t1b);
  const [t4a,t4b]=fp2Mul(t2a,t2b,Xa,Xb);
  const [t42a,t42b]=fp2Scale(t4a,t4b,2n);
  const [d35a,d35b]=fp2Sub(t3a,t3b,t42a,t42b,1n);
  const [t0sa,t0sb]=fp2Sqr(t0a,t0b);
  const [t0sza,t0szb]=fp2Mul(t0sa,t0sb,Za,Zb);
  const [t5a,t5b]=fp2Add(d35a,d35b,t0sza,t0szb);
  const [nxa,nxb]=fp2Mul(t1a,t1b,t5a,t5b);
  const [d45a,d45b]=fp2Sub(t4a,t4b,t5a,t5b,7n);
  const [d45t0a,d45t0b]=fp2Mul(d45a,d45b,t0a,t0b);
  const [t3rya,t3ryb]=fp2Mul(t3a,t3b,Ya,Yb);
  const [nya,nyb]=fp2Sub(d45t0a,d45t0b,t3rya,t3ryb,3n);
  const [nza,nzb]=fp2Mul(Za,Zb,t3a,t3b);
  return {c0:[c0a,c0b],R:[nxa,nxb,nya,nyb,nza,nzb]};
}

let maxC0=0n, maxR=0n, maxInter=0n;
const inP=()=>rnd()%P;
// probe 1: reduced inputs [0,p)
// probe 2: WIDE inputs — feed R components up to 6p (lazy-carried) to prove bound is magnitude-robust
for(let trial=0;trial<200000;trial++){
  const wide = (trial%2===0);
  const scal = wide ? 6n : 1n;
  const rv=()=> (rnd()%(scal*P));
  const Xa=rv(),Xb=rv(),Ya=rv(),Yb=rv(),Za=rv(),Zb=rv(),Qxa=inP(),Qxb=inP(),Qya=inP(),Qyb=inP();
  const d=pointDouble(Xa,Xb,Ya,Yb,Za,Zb);
  const a=pointAdd(Xa,Xb,Ya,Yb,Za,Zb,Qxa,Qxb,Qya,Qyb);
  for(const c of [d.c0[0],d.c0[1],a.c0[0],a.c0[1]]){ if(c<0n) throw new Error('neg c0!'); if(c>maxC0)maxC0=c; }
  for(const r of [...d.R,...a.R]){ if(r>maxR)maxR=r; if(byteLen(r)>byteLen(maxInter))maxInter=r; }
}
console.log('LAZY .cash pointDouble/pointAdd — 200k random trials (half with R carried up to 6p):');
console.log('  max c0 (=o4) / p        =', (Number(maxC0)/Number(P)).toFixed(4), ' => o4 bound', Number(maxC0)/Number(P) < 6 ? '<= 6p CONFIRMED' : '*** EXCEEDS 6p ***');
console.log('  max c0 byteLen          =', byteLen(maxC0), 'bytes');
console.log('  max R-component / p      =', (Number(maxR)/Number(P)).toFixed(4));
console.log('  max R-component byteLen  =', byteLen(maxR), 'bytes  (VM number cap 10000 B)');
