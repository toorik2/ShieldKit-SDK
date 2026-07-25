// TRAJECTORY-FORGE skeptic harness (novel). Goal: supply a witnessed slope `lam` that STEERS the
// DERIVED next point to a chosen FALSE target R' (not the true 2R / R+Q) yet passes the on-chain
// division-free slope check. Runs on the real libauth BCH-2026 VM. Also probes out-of-range /
// negative / sign-flipped lam representatives and reads back the DERIVED point to confirm it is
// forced. affDbl/affAdd DERIVE the point (only lam is witnessed), so the slope check is the sole gate.
import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('variants/V3_millerres_lib.cash', 'utf8');
function extract(name){const s=lib.split('\n'),o=[];let p=false,d=0;for(const l of s){if(!p&&l.startsWith(`function ${name}(`))p=true;if(p){o.push(l);d+=(l.match(/\{/g)||[]).length-(l.match(/\}/g)||[]).length;if(d===0&&l.includes('}'))break;}}return o.join('\n');}
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const libtext=need.map(extract).join('\n')+'\n'+readFileSync('_afflib.cash','utf8');
const OP_PUSHDATA2=0x4d, r=(x)=>((x%P)+P)%P;
// run body; returns {accepted, err}
function run(nargs, body, args){
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw; try{raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);}catch(e){return{err:String(e?.message??e).slice(0,90)};}
  const locking=Uint8Array.from(raw),pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(9000),...new Uint8Array(9000)]);
  const argBytes=Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return{accepted:st.error===undefined&&st.stack.length===1&&st.stack[0].length===1&&st.stack[0][0]===1,err:st.error?String(st.error).slice(0,70):undefined};
}
const A=(x,y)=>Fp2.add(x,y),Sub=(x,y)=>Fp2.sub(x,y),M=(x,y)=>Fp2.mul(x,y),SQ=(x)=>Fp2.sqr(x),SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const F2=(a,b)=>Fp2.fromBigTuple([r(a),r(b)]);
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
// honest doubling
const l3=SC(SQ(Q.x),3n),lam=M(l3,Fp2.inv(A(Q.y,Q.y)));
const xnHon=Sub(SQ(lam),A(Q.x,Q.x)), ynHon=Sub(M(lam,Sub(Q.x,Sub(SQ(lam),A(Q.x,Q.x)))),Q.y);
const consume=`require(within(mulFp(c0a,0)+mulFp(c0b,0)+mulFp(c1a,0)+mulFp(c1b,0)+mulFp(c2a,0)+mulFp(c2b,0)+mulFp(nxa,0)+mulFp(nxb,0)+mulFp(nya,0)+mulFp(nyb,0),0,2));`;
// body that DERIVES via affDbl and REQUIRES the derived point equals a chosen target (tx,ty) in Fp2.
const bodyDblTarget=(txa,txb,tya,tyb)=>`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);\n require(nxa==${txa}); require(nxb==${txb}); require(nya==${tya}); require(nyb==${tyb});\n ${consume}`;
const dblArgs=(lm)=>[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,r(lm.c0),r(lm.c1)];

console.log('=== TRAJECTORY-FORGE (affDbl pair0) ===');
// sanity: honest lam derives honest point (target = honest) -> accept
console.log('[H] honest lam derives honest 2R:',
  run(6,bodyDblTarget(xnHon.c0,xnHon.c1,ynHon.c0,ynHon.c1),dblArgs(lam)).accepted);

// FORGE 1: pick a FALSE target R' = (honest.x+1, honest.y). Find lam' with lam'^2 = R'x+2x so the
// DERIVED xn == R'x (steer x). Does slope check pass? Must NOT.
function forgeSteerX(dx){
  const txa=r(xnHon.c0+dx); const target=F2(txa,xnHon.c1);
  const need_l2=A(target,A(Q.x,Q.x)); // lam'^2 must equal target.x + 2x
  let lf; try{ lf=Fp2.sqrt(need_l2);}catch(e){return {noSqrt:true};}
  if(!(SQ(lf).c0===need_l2.c0&&SQ(lf).c1===need_l2.c1)) return {noSqrt:true};
  // derived xn with lf = target.x by construction; derived yn:
  const xnf=Sub(SQ(lf),A(Q.x,Q.x)); const ynf=Sub(M(lf,Sub(Q.x,xnf)),Q.y);
  // Ask VM: does affDbl(Q, lf) pass AND derive (target.x, ynf)?  (target chosen != honest)
  const res=run(6,bodyDblTarget(xnf.c0,xnf.c1,ynf.c0,ynf.c1),dblArgs(lf));
  return {noSqrt:false, isHonest:(xnf.c0===xnHon.c0&&xnf.c1===xnHon.c1), accepted:res.accepted, err:res.err};
}
{ let tried=0, forged=0, rejected=0;
  for(let dx=1n; dx<=4000n && tried<12; dx++){
    const f=forgeSteerX(dx);
    if(f.noSqrt) continue;               // target.x unreachable (not a QR): no lam derives it at all
    tried++; if(f.accepted && !f.isHonest) forged++; else if(!f.accepted) rejected++;
  }
  console.log(`[F1 dbl steer-x] steerable-false-targets TRIED=${tried}  slope-REJECTED=${rejected}  FORGED(accepted-wrong)=${forged}`);
}

// FORGE 2: out-of-range / alt-representative lam. Should either reject, or accept-with-IDENTICAL point.
function repTest(label, lm){
  // target = honest point; check accept
  const res=run(6,bodyDblTarget(xnHon.c0,xnHon.c1,ynHon.c0,ynHon.c1),[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lm.c0,lm.c1]);
  console.log(`[F2 ${label}] accepts(honest-target)=${res.accepted}${res.err?(' err='+res.err):''}`);
  return res.accepted;
}
repTest('lam+p',      {c0:r(lam.c0)+P,        c1:r(lam.c1)});
repTest('lam+64p',    {c0:r(lam.c0)+64n*P,    c1:r(lam.c1)});
repTest('lam-p(neg)', {c0:r(lam.c0)-P,        c1:r(lam.c1)});
repTest('lam c0only+p',{c0:r(lam.c0),         c1:r(lam.c1)+P});
// sign-flip: -lam has same lam^2 (same xn) but slope*(-1) -> must REJECT
console.log('[F2 -lam (same xn, wrong slope sign)] rejects:',
  !run(6,bodyDblTarget(xnHon.c0,xnHon.c1,ynHon.c0,ynHon.c1),dblArgs(Fp2.neg(lam))).accepted);

// FORGE 3 (affAdd): steer R+Q to a false x via lam'^2 = target.x + Rx + Qx. slope must catch it.
const R2=pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const t1=Sub(R2.x,Q.x),t0=Sub(R2.y,Q.y),lamA=M(t0,Fp2.inv(t1));
const xnA=Sub(Sub(SQ(lamA),R2.x),Q.x), ynA=Sub(M(lamA,Sub(R2.x,Sub(Sub(SQ(lamA),R2.x),Q.x))),R2.y);
const bodyAddTarget=(txa,txb,tya,tyb)=>`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\n require(nxa==${txa}); require(nxb==${txb}); require(nya==${tya}); require(nyb==${tyb});\n ${consume}`;
const addArgs=(lm)=>[R2.x.c0,R2.x.c1,R2.y.c0,R2.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,r(lm.c0),r(lm.c1)];
console.log('=== TRAJECTORY-FORGE (affAdd pair0) ===');
console.log('[H] honest lam derives honest R+Q:',
  run(10,bodyAddTarget(xnA.c0,xnA.c1,ynA.c0,ynA.c1),addArgs(lamA)).accepted);
function forgeAddX(dx){
  const target=F2(r(xnA.c0+dx),xnA.c1);
  const need_l2=A(target,A(R2.x,Q.x));
  let lf; try{lf=Fp2.sqrt(need_l2);}catch(e){return{noSqrt:true};}
  if(!(SQ(lf).c0===need_l2.c0&&SQ(lf).c1===need_l2.c1))return{noSqrt:true};
  const xnf=Sub(Sub(SQ(lf),R2.x),Q.x); const ynf=Sub(M(lf,Sub(R2.x,xnf)),R2.y);
  const res=run(10,bodyAddTarget(xnf.c0,xnf.c1,ynf.c0,ynf.c1),addArgs(lf));
  return {noSqrt:false,isHonest:(xnf.c0===xnA.c0&&xnf.c1===xnA.c1),accepted:res.accepted,err:res.err};
}
{ let tried=0, forged=0, rejected=0;
  for(let dx=1n; dx<=4000n && tried<12; dx++){
    const f=forgeAddX(dx);
    if(f.noSqrt) continue;
    tried++; if(f.accepted && !f.isHonest) forged++; else if(!f.accepted) rejected++;
  }
  console.log(`[F3 add steer-x] steerable-false-targets TRIED=${tried}  slope-REJECTED=${rejected}  FORGED(accepted-wrong)=${forged}`);
}
