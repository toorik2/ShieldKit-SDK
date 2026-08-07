// IN-VM FORGERY CONSTRUCTION: does the LAZY residue fp12Mul commit a WRONG residue when its
// operand B (the residue witness c/cInv) is out-of-range? c/cInv are prover-supplied, threaded as
// carried state, consumed RAW by the lazy `cf` fp12Mul, and only range-checked (c<p) in the TAIL
// AFTER covOut %Pmod reductions. The eager lib is immune (mulFp reduces). Test the lazy lib.
process.env.LIB_IMPORT = '../variants/V3_millerres_lib.cash'; // the LAZY residue lib
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const mod = (x)=>((x%P)+P)%P;
const byteLen=(x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};

const { genChunk, ops, inState, outState } = await import('./gen_miller_residue.mjs');
const { measureCovenantFile } = await import('./_millermath.mjs');
const { join, dirname } = await import('node:path');
const { fileURLToPath } = await import('node:url');
const here = dirname(fileURLToPath(import.meta.url));
const PROBE = join(here, 'generated', '_probe_forge.cash');

// ---- lazy op mirror (reduceOutMul(pre12Mul)) for A=f (reduced), B=c (raw or reduced) ----
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
  const pr=f6mW(sa,sb);const Chi=[0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]);
  return[...Clo,...Chi];}
const reduceOutMul=(x)=>mod(x+BIAS); // BCH OP_MOD on nonneg dividend == this; if x+BIAS<0 BCH gives a NEG rep
const bchMod=(x)=>{ const d=x+BIAS; return d>=0n ? d%P : -((-d)%P); }; // BCH truncated-toward-zero % on the dividend
function lazyMul(fLimbs, bLimbs){ const pre=pre12Mul(fLimbs,bLimbs); return pre.map(x=>bchMod(x)); }

// ---- locate the first cf op (uses c). state layout: f(0..11) R0(12..17) pts(18..27) c(28..39) cInv(40..51)
const CF = ops.findIndex(o=>o.t==='cf'); // op 5, neg=true -> f *= c
const C_OFF = 28, CI_OFF = 40; // verified below
const win = [CF, CF+1];
const stIn = inState(win[0]).map(BigInt);
const fL = stIn.slice(0,12);
const cRed = stIn.slice(C_OFF, C_OFF+12);
console.log(`first cf op index=${CF} neg=${ops[CF].neg} (f*=c). window [${win[0]},${win[1]}). inState len=${stIn.length}`);
console.log(`sanity: all cRed limbs < p ? ${cRed.every(x=>x>=0n&&x<P)}`);

// ground truth: correct residue of f*c (computed via the SOUND reduced-operand lazy path == eager)
const trueOut = lazyMul(fL, cRed).map(mod);
// honest run through the real compiled LAZY chunk with REDUCED c -> must accept & commit trueOut
const src = genChunk(win[0], win[1], false);
const honestOut = outState(win[1]).map(BigInt).map(mod); // generator's own honest next state (reduced)
const mHonest = measureCovenantFile(src, stIn, outState(win[1]).map(BigInt), PROBE);
console.log(`\n[HONEST reduced-c] chunk accepts=${mHonest.accepted} op=${mHonest.operationCost}  trueOut==generatorOut? ${trueOut.every((v,i)=>v===honestOut[i])}`);

// ---- find MINIMAL offset K (in units of p on c-limb0) that pushes a lazy dividend negative ----
function firstNegK(){
  for (let K=1n; K<=5000n; K++){
    const cRaw=cRed.slice(); cRaw[0]=cRed[0]+K*P;
    const pre=pre12Mul(fL,cRaw);
    if (pre.some(x=>x+BIAS<0n)) return K;
  }
  return null;
}
const Kbreak = firstNegK();
console.log(`\nminimal c-limb0 offset to force a negative dividend: ${Kbreak===null?'>5000p':Kbreak+'p'} (bias covers up to this)`);

// ---- FORGERY: raw c with an offset that DEFINITELY breaks it; c_raw still fits 40 bytes ----
const K = (Kbreak??50n) + 50n; // safely past the break
const cRaw = cRed.slice(); cRaw[0] = cRed[0] + K*P;
console.log(`\n[FORGE] c-limb0 offset = ${K}p ; c_raw[0] byteLen=${byteLen(cRaw[0])} (<=40? ${byteLen(cRaw[0])<=40}) ; c_raw[0] % p == c_red[0] ? ${mod(cRaw[0])===cRed[0]}`);

// what the LAZY chunk actually computes with raw c:
const lazyOutRaw = lazyMul(fL, cRaw);          // signed reps (some may be negative)
const lazyOutCommitted = lazyOutRaw.map(mod);   // covOut commits value % Pmod (BCH % of the lazy rep)
// Actually covOut does (lazyRep) % Pmod in BCH truncated semantics:
const bchTrunc=(x)=> x>=0n ? x%P : -((-x)%P);
const committedByCovOut = lazyOutRaw.map(bchTrunc); // exactly what OP_MOD yields inside covOut
const wrong = trueOut.some((v,i)=> mod(committedByCovOut[i]) !== v);
console.log(`\ntrueResidue (f*c mod p) vs lazy-with-rawc committed limbs:`);
let firstDiff=-1;
for (let i=0;i<12;i++){ if (mod(committedByCovOut[i])!==trueOut[i] && firstDiff<0) firstDiff=i; }
console.log(`  WRONG RESIDUE at some limb? ${wrong}  (first diff limb=${firstDiff})`);
if (firstDiff>=0){
  console.log(`  limb ${firstDiff}: true=${trueOut[firstDiff]}`);
  console.log(`  limb ${firstDiff}: lazyCommitted(mod p)=${mod(committedByCovOut[firstDiff])}`);
  console.log(`  limb ${firstDiff}: raw lazy rep sign=${lazyOutRaw[firstDiff]<0n?'NEGATIVE':'nonneg'} dividend+bias byteLen=${byteLen(pre12Mul(fL,cRaw)[firstDiff]+BIAS)}`);
}

// Build the malicious inState (raw c) and drive the REAL compiled lazy chunk in libauth:
const stForge = stIn.slice(); stForge[C_OFF] = cRaw[0];
// outState with raw c: same as honest but f-block replaced by the lazy raw-c result; c re-reduced by covOut
const outForge = outState(win[1]).map(BigInt);
for (let i=0;i<12;i++) outForge[i] = committedByCovOut[i]; // the f-block the lazy chunk will produce
// NOTE: measureCovenantFile sets output token commitment = commitBin(outLimbs after %Pmod inside the contract);
// the harness passes outLimbs to build the output commitment via the SAME le40; but covOut reduces %Pmod,
// so we must pass the values the contract will commit = committedByCovOut (already the %Pmod images).
const mForgeAccept = measureCovenantFile(src, stForge, outForge, PROBE);
console.log(`\n[FORGE raw-c] chunk accepts (covIn matches crafted commitment, covOut matches lazy output)=${mForgeAccept.accepted} op=${mForgeAccept.operationCost} err=${mForgeAccept.error??''}`);
// And prove the chunk CANNOT commit the true residue for this input:
const outTrueTry = outState(win[1]).map(BigInt); for (let i=0;i<12;i++) outTrueTry[i]=trueOut[i];
const mForgeTrue = measureCovenantFile(src, stForge, outTrueTry, PROBE);
console.log(`[FORGE raw-c] same input but demanding TRUE residue output -> accepts=${mForgeTrue.accepted} (expect FALSE: lazy chunk cannot produce the true residue)`);

console.log(`\n==== VERDICT: lazy chunk ACCEPTS raw-c input=${mForgeAccept.accepted} while committed output != true residue=${wrong} ====`);
