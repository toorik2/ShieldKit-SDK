// Force the lazy residue fp12Mul into the NEGATIVE-dividend regime (operand c wildly out of range)
// and check: (a) is the committed limb still the CORRECT residue class mod p? (homomorphism test)
// (b) does the real compiled chunk still accept? (c) can it EVER commit a value != correct residue?
process.env.LIB_IMPORT = '../variants/V3_millerres_lib.cash';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const mod=(x)=>((x%P)+P)%P;
const byteLen=(x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};
const bchTrunc=(x)=> x>=0n ? x%P : -((-x)%P); // BCH OP_MOD truncated toward zero

const { genChunk, ops, inState, outState } = await import('./gen_miller_residue.mjs');
const { measureCovenantFile } = await import('./_millermath.mjs');
const { bn254, Fp12, Fp2 } = await import('./_millermath.mjs').then(m=>m).catch(()=>({}));
const { join, dirname } = await import('node:path'); const { fileURLToPath } = await import('node:url');
const PROBE = join(dirname(fileURLToPath(import.meta.url)), 'generated', '_probe_forge2.cash');

// pre12Mul mirror
const f2mW=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return[w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xW=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
const f6vW=(a)=>{const[n0a,n0b]=f2xW(a[4],a[5]);return[n0a,n0b,a[0],a[1],a[2],a[3]];};
function f6mW(a,b){const[a0a,a0b,a1a,a1b,a2a,a2b]=a,[b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const[t0a,t0b]=f2mW(a0a,a0b,b0a,b0b),[t1a,t1b]=f2mW(a1a,a1b,b1a,b1b),[t2a,t2b]=f2mW(a2a,a2b,b2a,b2b);
  const[p1a,p1b]=f2mW(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b),[x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a,c0b=t0b+x1b;
  const[p2a,p2b]=f2mW(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b),[x2a,x2b]=f2xW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
  const[p3a,p3b]=f2mW(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;
  return[c0a,c0b,c1a,c1b,c2a,c2b];}
function pre12Mul(A,B){const Alo=A.slice(0,6),Ahi=A.slice(6,12),Blo=B.slice(0,6),Bhi=B.slice(6,12);
  const t0=f6mW(Alo,Blo),t1=f6mW(Ahi,Bhi),vt=f6vW(t1);
  const Clo=[0,1,2,3,4,5].map(i=>t0[i]+vt[i]);
  const sa=[0,1,2,3,4,5].map(i=>Alo[i]+Ahi[i]),sb=[0,1,2,3,4,5].map(i=>Blo[i]+Bhi[i]);
  const pr=f6mW(sa,sb);const Chi=[0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]);return[...Clo,...Chi];}

const CF = ops.findIndex(o=>o.t==='cf'); const C_OFF=28;
const stIn = inState(CF).map(BigInt); const fL=stIn.slice(0,12); const cRed=stIn.slice(C_OFF,C_OFF+12);
const trueOut = pre12Mul(fL,cRed).map(x=>mod(bchTrunc(x+BIAS)));   // correct residue (canonical, reduced c)
const src = genChunk(CF, CF+1, false);

console.log('Testing lazy residue fp12Mul(f, c_raw) across escalating out-of-range c offsets.');
console.log('Q1: does committed limb %p ALWAYS == correct residue?  Q2: does the real chunk accept?\n');
let anyWrong=false, anyNegDividend=false;
for (const K of [0n,1000n,100000n,10000000n,1000000000n,1000000000000n]){
  // offset ALL 12 c-limbs by K*p (worst case for magnitude), staying within 40 bytes
  const cRaw=cRed.map(x=>x+K*P);
  if (cRaw.some(x=>byteLen(x)>40)){ console.log(`  K=${K}p : c_raw exceeds 40 bytes (not covenant-encodable) -> skip`); continue; }
  const pre=pre12Mul(fL,cRaw);
  const negDiv = pre.some(x=>x+BIAS<0n); anyNegDividend = anyNegDividend||negDiv;
  const committed = pre.map(x=>bchTrunc(x+BIAS));       // reduceOutMul rep
  const committedCanon = committed.map(x=>bchTrunc(x)); // covOut applies %Pmod again
  const wrong = trueOut.some((v,i)=> mod(committedCanon[i]) !== v);
  anyWrong = anyWrong||wrong;
  // drive the REAL compiled chunk: covIn=commit(stForge), covOut expects committedCanon
  const stForge=stIn.slice(); for(let i=0;i<12;i++) stForge[C_OFF+i]=cRaw[i];
  const outForge=outState(CF+1).map(BigInt); for(let i=0;i<12;i++) outForge[i]=committedCanon[i];
  const m = measureCovenantFile(src, stForge, outForge, PROBE);
  const maxPreB = Math.max(...pre.map(x=>byteLen(x+BIAS)));
  console.log(`  K=${String(K).padStart(13)}p : negDividend=${negDiv?'YES':'no '} committed%p==correctResidue=${!wrong}  chunkAccepts=${m.accepted} op=${m.operationCost} maxDividendBytes=${maxPreB} ${m.error?('ERR '+m.error):''}`);
}
console.log(`\n==== ANY wrong residue across all offsets (incl negative-dividend regime)? ${anyWrong} ====`);
console.log(`==== reached negative-dividend regime at least once? ${anyNegDividend} ====`);
console.log('Interpretation: BIAS % p == 0  =>  reduceOutMul(x) === x (mod p) for ALL x  =>  NEVER a wrong residue class.');
