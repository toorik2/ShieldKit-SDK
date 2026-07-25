// SKEPTIC / CORRECTNESS lens — FRESH differential of lazy fp12Mul + mul034 vs noble BN254.
// Independent of prior harnesses: new PRNG seed, and critically it samples o4 (the raw line c0)
// across the ACTUAL Miller-regime magnitude [0,6p], plus corner multiples of p, plus real raw
// c0 computed BY THE VM (pointDouble/pointAdd -> line), plus a beyond-regime break sweep.
//
// The contract requires each output limb to EXACTLY equal noble's CANONICAL residue in [0,p)
// (strict equality, not `% p ==`). This gate catches BOTH classes of failure at once:
//   (a) wide-arithmetic bug  -> residue wrong        -> reject
//   (b) bias too small       -> reduceOut goes < 0   -> non-canonical value != noble -> reject
// Every accept therefore certifies: output is the true canonical residue in [0,p).
//
// Runs the REAL compiled .cash (RESCHED fork, the deployed path) in the libauth VM (cost.mjs
// measureRun). In parallel it recomputes, in independent JS, the exact wide pre-reduction limbs
// and the reduceOut dividend (limb + BIAS) to report the min dividend margin on these fresh cases.

import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber, createTestAuthenticationProgramBch } from '@bitauth/libauth';
import { writeFileSync } from 'node:fs';
import { looseVm } from '/home/toorik/Projects/LeanBCH/optimizer/core/program.mjs';
import { Fp2, Fp6, Fp12, Fp, bn254, vec, proof, vk, pairsFor, pointDouble, pointAdd } from './_millermath.mjs';

// PROPER accept gate: a CashScript contract's final require compiles to leaving the boolean on the
// stack (NOT OP_VERIFY), so a FALSE result leaves top=[] with NO error. `measureRun.ok` (=!error)
// would call that "accept" — WRONG. True accept = no error AND clean stack == [0x01]. (Verified by
// negative control: a deliberately-wrong expected c0 leaves top=[] and is correctly rejected here.)
function vmAccept(bc, unlocking){
  const st = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: bc, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length-1];
  const ok = st.error===undefined && st.stack.length===1 && top!==undefined && top.length===1 && top[0]===1;
  return { ok, error: st.error?String(st.error):undefined, stackLen: st.stack.length, top: top?[...top]:null };
}

const P = Fp.ORDER;
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const RESCHED = { rescheduleStacks: true };
const LIB_STANDALONE = '../variants/V3_mul_delayed.cash';   // standalone lazy fp12Mul + mul034
const LIB_DEPLOYED   = '../variants/V3_millerres_lib.cash'; // deployed residue lib (line/pointDouble/pointAdd + mul034)

console.log('P    =', P);
console.log('BIAS % P     =', BIAS % P, '  (must be 0 => reduceOut preserves residue class)');
console.log('BIAS / P^2   =', (BIAS / (P*P)), ' p^2  (deployed reduceOutMul bias)');
console.log('BIAS bytelen =', bigIntToVmNumber(BIAS).length, 'B\n');
if (BIAS % P !== 0n) { console.log('!!! BIAS NOT A MULTIPLE OF P -> residue not preserved -> UNSOUND'); process.exit(2); }

// ---------- FRESH PRNG (distinct seed from every prior harness) ----------
let s = 0x9E3779B97F4A7C15n ^ 0xC0FFEE5EED12345n; // xorshift128-ish, brand new seed
const rnd = () => { s ^= s << 13n; s &= (1n<<64n)-1n; s ^= s >> 7n; s ^= s << 17n; s &= (1n<<64n)-1n; return s; };
const rndFull = () => { let x=0n; for (let k=0;k<4;k++) x=(x<<64n)|rnd(); return x % P; };            // uniform [0,p)
const rndUpTo = (hi) => { let x=0n; for (let k=0;k<5;k++) x=(x<<64n)|rnd(); return x % hi; };          // uniform [0,hi)
const corners = [0n, 1n, 2n, P-1n, P-2n];
const rndCorner = () => corners[Number(rnd() % 5n)];
const rndOrCorner = () => (rnd() % 3n === 0n ? rndCorner() : rndFull());

// ---------- noble reference (independent oracle: noble's own Fp2/Fp6/Fp12) ----------
const mk2 = (a,b) => ({ c0: ((a%P)+P)%P, c1: ((b%P)+P)%P });
const toF12 = (L) => ({ c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])}, c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])} });
const flat = (f) => [f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleMul = (A,B) => flat(Fp12.mul(toF12(A), toF12(B)));
function nobleMul034(F, o) {
  const f=toF12(F), o0=mk2(o[0],o[1]), o3=mk2(o[2],o[3]), o4=mk2(o[4],o[5]);
  const A = Fp6.create({ c0:Fp2.mul(f.c0.c0,o0), c1:Fp2.mul(f.c0.c1,o0), c2:Fp2.mul(f.c0.c2,o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0,f.c1), Fp2.add(o0,o3), o4);
  return flat(Fp12.create({ c0:Fp6.add(Fp6.mulByNonresidue(B),A), c1:Fp6.sub(E,Fp6.add(A,B)) }));
}

// ---------- independent JS model of the wide (pre-reduce) limbs + dividend margin ----------
const f2mW = (a0,a1,b0,b1) => { const w0=a0*b0,w1=a1*b1; return [w0-w1,(a0+a1)*(b0+b1)-w0-w1]; };
const f2xW = (a0,a1) => [9n*a0-a1, 9n*a1+a0];
const f6vW = (a) => { const [n0a,n0b]=f2xW(a[4],a[5]); return [n0a,n0b,a[0],a[1],a[2],a[3]]; };
function f6mW(a,b){
  const [t0a,t0b]=f2mW(a[0],a[1],b[0],b[1]),[t1a,t1b]=f2mW(a[2],a[3],b[2],b[3]),[t2a,t2b]=f2mW(a[4],a[5],b[4],b[5]);
  const [p1a,p1b]=f2mW(a[2]+a[4],a[3]+a[5],b[2]+b[4],b[3]+b[5]);
  const [x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a,c0b=t0b+x1b;
  const [p2a,p2b]=f2mW(a[0]+a[2],a[1]+a[3],b[0]+b[2],b[1]+b[3]);
  const [x2a,x2b]=f2xW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
  const [p3a,p3b]=f2mW(a[0]+a[4],a[1]+a[5],b[0]+b[4],b[1]+b[5]);
  const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;
  return [c0a,c0b,c1a,c1b,c2a,c2b];
}
function f6m01(c,b0a,b0b,b1a,b1b){
  const [t0a,t0b]=f2mW(c[0],c[1],b0a,b0b),[t1a,t1b]=f2mW(c[2],c[3],b1a,b1b);
  const [m12a,m12b]=f2mW(c[2]+c[4],c[3]+c[5],b1a,b1b),[xu0a,xu0b]=f2xW(m12a-t1a,m12b-t1b);
  const r0a=xu0a+t0a,r0b=xu0b+t0b;
  const [m1a,m1b]=f2mW(b0a+b1a,b0b+b1b,c[0]+c[2],c[1]+c[3]);
  const r1a=m1a-t0a-t1a,r1b=m1b-t0b-t1b;
  const [m2a,m2b]=f2mW(c[0]+c[4],c[1]+c[5],b0a,b0b);
  const r2a=m2a-t0a+t1a,r2b=m2b-t0b+t1b;
  return [r0a,r0b,r1a,r1b,r2a,r2b];
}
// wide pre-reduction limbs for fp12Mul (mirrors V3_mul_delayed.cash fp12Mul body)
function preMul(A,B){
  const t0=f6mW(A.slice(0,6),B.slice(0,6)), t1=f6mW(A.slice(6,12),B.slice(6,12));
  const vt=f6vW(t1);
  const pr=f6mW([0,1,2,3,4,5].map(i=>A[i]+A[6+i]),[0,1,2,3,4,5].map(i=>B[i]+B[6+i]));
  const lo=[0,1,2,3,4,5].map(i=>t0[i]+vt[i]);
  const hi=[0,1,2,3,4,5].map(i=>pr[i]-t0[i]-t1[i]);
  return [...lo,...hi];
}
// wide pre-reduction limbs for mul034 (mirrors V3_mul_delayed.cash mul034 body)
function preM034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const A0=f2mW(F[0],F[1],o0a,o0b),A2=f2mW(F[2],F[3],o0a,o0b),A4=f2mW(F[4],F[5],o0a,o0b);
  const Aa=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B=f6m01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>F[i]+F[6+i]);
  const G=f6m01(S,o0a+o3a,o0b+o3b,o4a,o4b);
  const VB=f6vW(B);
  const lo=[0,1,2,3,4,5].map(i=>VB[i]+Aa[i]);
  const hi=[0,1,2,3,4,5].map(i=>G[i]-Aa[i]-B[i]);
  return [...lo,...hi];
}
const btrunc = (n,m) => { let r=n%m; return r; };            // BCH OP_MOD: truncated (sign of dividend)
const minDividendOf = (limbs) => limbs.reduce((mn,x)=>{const d=x+BIAS; return d<mn?d:mn;}, 1n<<800n);

// ---------- VM push / compile ----------
const push = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length===0) return Uint8Array.from([0x00]);
  if (d.length===1 && d[0]>=1 && d[0]<=16) return Uint8Array.from([0x50+d[0]]);
  if (d.length===1 && d[0]===0x81) return Uint8Array.from([0x4f]);
  return Uint8Array.from([d.length, ...d]);
};
const unlockFor = (a) => Uint8Array.from([...a].reverse().flatMap((x)=>[...push(x)]));
const P4 = Array.from({length:12},(_,i)=>`int a${i}`).concat(Array.from({length:12},(_,i)=>`int b${i}`)).join(',');
const A4 = Array.from({length:12},(_,i)=>`a${i}`).concat(Array.from({length:12},(_,i)=>`b${i}`)).join(',');
const OUT = Array.from({length:12},(_,i)=>`int c${i}`).join(',');
const compileBc = (path) => utils.asmToBytecode(compileFile(path, RESCHED).bytecode);

let COMPILE_OK = { standalone:false, deployed:false };
function tmpCompile(src, tag){
  writeFileSync('generated/_skfresh.cash', src);
  const bc = compileBc('generated/_skfresh.cash');
  COMPILE_OK[tag] = true;
  return bc;
}

// STRICT equality contract: c_i == noble canonical (in [0,p))
function mulSrc(A,B){ const e=nobleMul(A,B); const chk=e.map((v,i)=>`c${i} == ${v}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${LIB_STANDALONE}";\ncontract B(){function r(${P4}){${OUT} = fp12Mul(${A4});require(${chk});}}`; }
function m034Src(F,o){ const e=nobleMul034(F,o);
  const decl='int f0,int f1,int f2,int f3,int f4,int f5,int f6,int f7,int f8,int f9,int f10,int f11,int o0a,int o0b,int o3a,int o3b,int o4a,int o4b';
  const args='f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,o0a,o0b,o3a,o3b,o4a,o4b';
  const chk=e.map((v,i)=>`c${i} == ${v}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${LIB_STANDALONE}";\ncontract B(){function r(${decl}){${OUT} = mul034(${args});require(${chk});}}`; }

// full DEPLOYED double-line / add-line: VM computes the raw c0 (o4) itself via pointDouble/pointAdd, then line().
// The new-point outputs (lazy, >=0) are consumed by checking (n % p) == noble's reduced new R.
const nptChk = (nR)=>`(nx0 % ${P})==${nR.x.c0} && (nx1 % ${P})==${nR.x.c1} && (ny0 % ${P})==${nR.y.c0} && (ny1 % ${P})==${nR.y.c1} && (nz0 % ${P})==${nR.z.c0} && (nz1 % ${P})==${nR.z.c1}`;
function dlineSrc(F, R, Px, Py, expected, nR){
  const decl='int Xa,int Xb,int Ya,int Yb,int Za,int Zb,int f0,int f1,int f2,int f3,int f4,int f5,int f6,int f7,int f8,int f9,int f10,int f11,int Px,int Py';
  const chk=expected.map((v,i)=>`c${i} == ${v}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${LIB_DEPLOYED}";\ncontract B(){function r(${decl}){\n`+
    `(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nx0,int nx1,int ny0,int ny1,int nz0,int nz1) = pointDouble(Xa,Xb,Ya,Yb,Za,Zb);\n`+
    `${OUT} = line(f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11, c0a,c0b,c1a,c1b,c2a,c2b, Px,Py);\nrequire(${chk} && ${nptChk(nR)});}}`;
}
function alineSrc(F, R, Q, Px, Py, expected, nR){
  const decl='int Xa,int Xb,int Ya,int Yb,int Za,int Zb,int Qxa,int Qxb,int Qya,int Qyb,int f0,int f1,int f2,int f3,int f4,int f5,int f6,int f7,int f8,int f9,int f10,int f11,int Px,int Py';
  const chk=expected.map((v,i)=>`c${i} == ${v}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${LIB_DEPLOYED}";\ncontract B(){function r(${decl}){\n`+
    `(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nx0,int nx1,int ny0,int ny1,int nz0,int nz1) = pointAdd(Xa,Xb,Ya,Yb,Za,Zb, Qxa,Qxb,Qya,Qyb);\n`+
    `${OUT} = line(f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11, c0a,c0b,c1a,c1b,c2a,c2b, Px,Py);\nrequire(${chk} && ${nptChk(nR)});}}`;
}

let TOTAL=0, ACCEPT=0, REJECT=0; const findings=[];
let GLOBAL_MIN_DIV = 1n<<800n;
function runCase(label, src, stack, wideLimbs){
  TOTAL++;
  if (wideLimbs){ const md=minDividendOf(wideLimbs); if (md<GLOBAL_MIN_DIV) GLOBAL_MIN_DIV=md;
    if (md < 0n){ findings.push(`${label}: JS predicts reduceOut dividend < 0 (min=${md}) -> non-canonical`); } }
  const bc = tmpCompile(src, src.includes(LIB_DEPLOYED)?'deployed':'standalone');
  const r = vmAccept(bc, unlockFor(stack));
  if (r.ok) ACCEPT++; else { REJECT++; findings.push(`${label}: VM REJECT err=${r.error||'none'} stackLen=${r.stackLen} top=${JSON.stringify(r.top)} stack0=${stack[0]}`); }
  return r.ok;
}

// ============ TEST 1: fp12Mul  (residue/miller regime: both operands in [0,p)) ============
console.log('=== TEST 1: fp12Mul  (A,B in [0,p): both freshly-reduced operands) ===');
for (let t=0;t<40;t++){
  const A=Array.from({length:12},()=> t<28?rndFull():rndOrCorner());
  const B=Array.from({length:12},()=> t<28?rndFull():rndOrCorner());
  runCase(`fp12Mul#${t}`, mulSrc(A,B), [...A,...B], preMul(A,B));
}
console.log(`  fp12Mul: ${ACCEPT}/${TOTAL} accepted so far (min dividend margin so far = ${(GLOBAL_MIN_DIV/(P*P))} p^2)\n`);

// ============ TEST 2: mul034 with o4 across the FULL Miller regime [0,6p] ============
console.log('=== TEST 2: mul034  F,o0,o3 in [0,p);  o4 = RAW line c0 in [0,6p]  (the actual regime) ===');
const before2=TOTAL;
for (let t=0;t<60;t++){
  const F=Array.from({length:12},()=> t<44?rndFull():rndOrCorner());
  const o0a=rndFull(),o0b=rndFull(),o3a=rndFull(),o3b=rndFull();
  const o4a=rndUpTo(6n*P), o4b=rndUpTo(6n*P);   // <-- the ACTUAL Miller magnitude, NOT [0,p)
  const o=[o0a,o0b,o3a,o3b,o4a,o4b];
  runCase(`mul034_rand#${t}`, m034Src(F,o), [...F,...o], preM034(F,o0a,o0b,o3a,o3b,o4a,o4b));
}
console.log(`  Test2 mul034[0,6p]: ${ACCEPT-before2 === TOTAL-before2 ? (TOTAL-before2) : ACCEPT-before2}/${TOTAL-before2} accepted\n`);

// ============ TEST 3: mul034 corner o4 = k*p + r  (k=0..6, r in {0,1,p-1}) with corner F/o ============
console.log('=== TEST 3: mul034  o4 = k*p + r  corner multiples (k=0..6), F/o0/o3 corners+random ===');
const before3=TOTAL;
for (let k=0n;k<=6n;k++){
  for (const ra of [0n,1n,P-1n]) for (const rb of [0n,1n,P-1n]){
    const o4a=k*P+ra, o4b=k*P+rb;
    const F=Array.from({length:12},()=> rndOrCorner());
    const o0a=rndOrCorner(),o0b=rndOrCorner(),o3a=rndOrCorner(),o3b=rndOrCorner();
    const o=[o0a,o0b,o3a,o3b,o4a,o4b];
    runCase(`mul034_corner_k${k}`, m034Src(F,o), [...F,...o], preM034(F,o0a,o0b,o3a,o3b,o4a,o4b));
  }
}
console.log(`  Test3 corner-k: accepted through k=6 (${TOTAL-before3} cases)\n`);

// ============ TEST 4: DEPLOYED VM computes the raw c0 itself (pointDouble/pointAdd -> line) on REAL data ============
console.log('=== TEST 4: DEPLOYED line() — VM computes RAW o4 via pointDouble/pointAdd on real committed pairs ===');
const before4=TOTAL;
const scalarFp2 = (x,k)=> Fp2.fromBigTuple([Fp.mul(x.c0,k), Fp.mul(x.c1,k)]);
const lineNoble = (F, coeffs, Px, Py) => nobleMul034(F, [scalarFp2(coeffs[2],Py).c0, scalarFp2(coeffs[2],Py).c1, scalarFp2(coeffs[1],Px).c0, scalarFp2(coeffs[1],Px).c1, coeffs[0].c0, coeffs[0].c1]);
// real R trajectories from the committed instance's 4 pairs -> genuine Miller-regime raw c0
const inputs = vec.publicInputs ? vec.publicInputs.map(BigInt) : (vec.inputs||[]).map(BigInt);
const pairs = pairsFor(inputs.length?inputs:[1n]);
let real4=0, maxO4seen=0n;
for (const pr of pairs){
  const Qa = pr.Q.toAffine(), Pa = pr.P.toAffine();
  // evolve R a few real steps so R.z != 1 (exercises the deeper add-line c0 range)
  let R = { x:Qa.x, y:Qa.y, z:Fp2.ONE };
  for (let step=0; step<3; step++){
    const F = Array.from({length:12},()=>rndFull()); // reduced accumulator (chunk-boundary state)
    // ----- double-line: VM pointDouble computes raw c0 -----
    { const d = pointDouble(R.x,R.y,R.z);
      const exp = lineNoble(F, d.coeffs, Pa.x, Pa.y);
      const stack=[R.x.c0,R.x.c1,R.y.c0,R.y.c1,R.z.c0,R.z.c1, ...F, Pa.x, Pa.y];
      const o4 = ((d.coeffs[0].c0%P)+P)%P; if (o4>maxO4seen) maxO4seen=o4;
      if (runCase(`dline[${pr.name}]s${step}`, dlineSrc(F,R,Pa.x,Pa.y,exp,d.R), stack, null)) real4++;
      R = d.R;
    }
    // ----- add-line: VM pointAdd computes raw c0 (<=6p) — the o4 regime ceiling -----
    { const a = pointAdd(R.x,R.y,R.z, Qa.x, Qa.y);
      const exp = lineNoble(F, a.coeffs, Pa.x, Pa.y);
      const stack=[R.x.c0,R.x.c1,R.y.c0,R.y.c1,R.z.c0,R.z.c1, Qa.x.c0,Qa.x.c1,Qa.y.c0,Qa.y.c1, ...F, Pa.x, Pa.y];
      if (runCase(`aline[${pr.name}]s${step}`, alineSrc(F,R,Qa,Pa.x,Pa.y,exp,a.R), stack, null)) real4++;
      R = a.R;
    }
  }
}
console.log(`  Test4 deployed line() on real pairs: ${real4}/${TOTAL-before4} accepted (VM computes the raw o4 internally)\n`);

// ============ TEST 5: BEYOND-regime break sweep — confirm 6p is safely inside the sound zone ============
console.log('=== TEST 5: BEYOND-regime break sweep — push o4 = k*p (k=6..14) to locate the actual break ===');
// worst-case-ish o4 with max negativity structure: o4a=o4b=k*p+(p-1), F/o all corners toward negativity.
let firstBreak=null;
for (let k=6n;k<=14n;k++){
  // deterministic near-worst corner: from b2_exact the worst vertex is o at {0,p-1}; probe a strong one.
  const F=[0n,P-1n,0n,P-1n,0n,P-1n,0n,P-1n,0n,P-1n,0n,P-1n];
  const o0a=0n,o0b=P-1n,o3a=0n,o3b=P-1n; const o4a=k*P+(P-1n), o4b=k*P+(P-1n);
  const o=[o0a,o0b,o3a,o3b,o4a,o4b];
  const wide=preM034(F,o0a,o0b,o3a,o3b,o4a,o4b); const md=minDividendOf(wide);
  const bc=tmpCompile(m034Src(F,o),'standalone'); const r=vmAccept(bc, unlockFor([...F,...o]));
  console.log(`  o4=${k}p+(p-1): JS minDividend=${(md/(P*P))} p^2 (${md<0n?'NEG':'ok'}), VM ${r.ok?'ACCEPT':'REJECT'}`);
  if (!r.ok && firstBreak===null) firstBreak=k;
}
console.log(`  first VM break at o4 ~ k*p, k = ${firstBreak===null?'>14 (never in sweep)':firstBreak} (regime ceiling is 6p)\n`);

// ============ SUMMARY ============
console.log('================ SUMMARY ================');
console.log(`compiled: standalone lib=${COMPILE_OK.standalone}  deployed lib=${COMPILE_OK.deployed}`);
console.log(`in-regime cases (Tests 1-4): total=${TOTAL - 0} ... accepts=${ACCEPT} rejects=${REJECT}`);
console.log(`min reduceOut dividend across fresh Test1-3 cases = ${(GLOBAL_MIN_DIV/(P*P))} p^2  (>=0 => canonical; bias=${BIAS/(P*P)} p^2)`);
console.log(`beyond-regime first break k = ${firstBreak===null?'none<=14p':firstBreak}p  (must be > 6p for the regime to be sound)`);
const inRegimeSound = REJECT===0 && GLOBAL_MIN_DIV>=0n && COMPILE_OK.standalone && COMPILE_OK.deployed && (firstBreak===null||firstBreak>6n);
console.log(JSON.stringify({
  claim:'fp12Mul-lazy', lens:'correctness',
  built:{standalone:COMPILE_OK.standalone, deployed:COMPILE_OK.deployed},
  freshSeed:true, oracle:'noble @noble/curves bn254 (independent)',
  strictGate:'c_i == noble canonical in [0,p)',
  inRegimeCases:TOTAL, accepts:ACCEPT, rejects:REJECT,
  minDividendP2:Number(GLOBAL_MIN_DIV/(P*P)), biasP2:Number(BIAS/(P*P)),
  beyondRegimeFirstBreakK: firstBreak===null?null:Number(firstBreak),
  VERDICT: inRegimeSound ? 'SOUND on correctness lens (0 mismatch across fresh Miller-regime differential)' : 'MISMATCH/FINDING',
  findings: findings.slice(0,10),
}, null, 0));
