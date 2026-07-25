import { writeFileSync } from 'node:fs';
import { genChunk, inState, outState, chunkLambdas } from './gen_miller_affine.mjs';
import { compileFileBytecodeRaw, CATEGORY, commitBin, TARGET_UNLOCK } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x)=>((BigInt(x)%P)+P)%P;
const OP_PUSHDATA2=0x4d;
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush=(argLen,target)=>{const N=target-argLen-3;return Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(N),...new Uint8Array(N)]);};
function evalChunk(lo,hi,lambdas){
  const src = genChunk(lo,hi,false,false,null); // interior, no successor pin (isolate lambda forgery)
  writeFileSync('generated/_forge_aff.cash', src);
  const raw = compileFileBytecodeRaw('generated/_forge_aff.cash');
  const locking = Uint8Array.from([...raw]);
  const stateIn = inState(lo).map(red);
  const stateOut = outState(hi).map(red);
  const pushed = [...stateIn, ...lambdas.map(red)];
  const argBytes = Uint8Array.from([...pushed].reverse().flatMap(c=>[...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const tok=(c)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:c}});
  const program={inputIndex:0,
    sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commitBin(stateIn))}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
      outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commitBin(stateOut))}],locktime:0}};
  const st=realVm.evaluate(program);
  const top=st.stack[st.stack.length-1];
  return st.error===undefined && st.stack.length===1 && top!==undefined && top.length===1 && top[0]===1;
}
const [lo,hi]=[18,37];
const honest = chunkLambdas(lo,hi);
console.log('honest affine chunk ['+lo+','+hi+') ACCEPTS:', evalChunk(lo,hi,honest));
// forge: corrupt the FIRST lambda limb
const f1 = honest.slice(); f1[0] = red(f1[0]+1n);
console.log('forged lambda[0]+1 REJECTS:', !evalChunk(lo,hi,f1));
// forge: corrupt a middle lambda
const f2 = honest.slice(); const mid = f2.length>>1; f2[mid]=red(f2[mid]+12345n);
console.log('forged lambda[mid] REJECTS:', !evalChunk(lo,hi,f2));
// forge: zero all lambdas
const f3 = honest.map(()=>0n);
console.log('forged all-zero lambdas REJECTS:', !evalChunk(lo,hi,f3));
