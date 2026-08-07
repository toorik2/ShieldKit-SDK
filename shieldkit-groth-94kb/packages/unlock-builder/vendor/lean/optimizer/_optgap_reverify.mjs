// Independent FRESH re-verification of a candidate partition: bypass the cache, recompile every chunk,
// measure real bytes + real worst op via the deployed VM. Pass cuts as JSON in argv[2].
import { writeFileSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';
const N = ops.length, VM = createVirtualMachineBch2026(false);
const LIB_ABS='/home/toorik/Projects/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash', LIB_REL='../../../singleton/bn254/lib/lazy/Bn254Lazy.cash', PROBE='/tmp/_optgap_reverify.cash';
const gen=(lo,hi,f,r)=>genChunk(lo,hi,f,r).replace(LIB_REL,LIB_ABS);
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
const padBytes=(t)=>{const b=Math.max(2,t);const n=b<=76?b-1:b<=257?b-2:b-3;return encodeDataPush(new Uint8Array(n));};
const p2shSpk=(r)=>encodeLockingBytecodeP2sh32(hash256(r));
const tok=(c)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:c}});
function buildCtx(lo,hi){const isFinal=hi===N,reloc=lo===0;writeFileSync(PROBE,gen(lo,hi,isFinal,reloc));
  const redeem=Uint8Array.from([...compileFileBytecode(PROBE)]);const rpush=encodeDataPush(redeem),locking=p2shSpk(redeem),tail=rpush.length;
  const inLimbs=inState(lo).map(BigInt),outLimbs=outState(hi).map(BigInt);const covIn=reloc?inState(lo).slice(18,28).map(BigInt):inLimbs;
  const argb=Uint8Array.from([...inLimbs].reverse().flatMap((c)=>[...pushInt(c)]));const floor=argb.length+tail+3;
  const inCommit=commitBin(covIn),outCommit=commitBin(outLimbs);
  const mk=(t)=>Uint8Array.from([...padBytes(t-argb.length-tail),...argb,...rpush]);
  return {tail,argBytes:argb.length,floor,locking,inCommit,outCommit,mk};}
function evalAt(ctx,target){const st=VM.evaluate({inputIndex:0,
  sourceOutputs:[{lockingBytecode:ctx.locking,valueSatoshis:1000n,token:tok(ctx.inCommit)}],
  transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:ctx.mk(target)}],
    outputs:[{lockingBytecode:ctx.locking,valueSatoshis:1000n,token:tok(ctx.outCommit)}],locktime:0}});
  const top=st.stack[st.stack.length-1];
  return {accepted:st.error===undefined&&st.stack.length===1&&top&&top.length===1&&top[0]===1,op:st.metrics.operationCost,completed:st.error===undefined};}
const tunedLen=(a,op)=>Math.min(TARGET_UNLOCK,Math.max(a+3,Math.ceil(op/800)-41+96));
function measure(lo,hi){let ctx;try{ctx=buildCtx(lo,hi);}catch(e){return{feasible:false,err:String(e?.message??e).slice(0,60)};}
  const probe=evalAt(ctx,TARGET_UNLOCK);const op=probe.op;if(!(probe.completed&&op<=OP_BUDGET))return{feasible:false,realWorstOp:op};
  let target=tunedLen(ctx.argBytes+ctx.tail,op);let r=evalAt(ctx,target);
  while(!r.accepted&&target<TARGET_UNLOCK){target=Math.min(TARGET_UNLOCK,target+256);r=evalAt(ctx,target);}
  if(!r.accepted)return{feasible:false,realWorstOp:op};return{feasible:true,realBytes:35+target,realWorstOp:op};}
const cuts=JSON.parse(process.argv[2]);
let total=0,maxOp=0,feasible=true;const rows=[];
for(let i=0;i+1<cuts.length;i++){const m=measure(cuts[i],cuts[i+1]);
  if(!m.feasible||m.realWorstOp>OP_BUDGET){feasible=false;rows.push({lo:cuts[i],hi:cuts[i+1],feasible:false,op:m.realWorstOp??null});continue;}
  total+=m.realBytes;maxOp=Math.max(maxOp,m.realWorstOp);rows.push({lo:cuts[i],hi:cuts[i+1],bytes:m.realBytes,op:m.realWorstOp});}
console.log('FRESH re-verify: chunks',cuts.length-1,'totalRealBytes',feasible?total:'INFEASIBLE','maxRealWorstOp',maxOp,'slack',OP_BUDGET-maxOp,'feasible',feasible);
for(const r of rows)console.log(' ',JSON.stringify(r));
