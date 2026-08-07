import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK } from './_millermath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import { bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const GEN='generated';
const PROBE=join(GEN,'_forge_genesis.cash');
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red=x=>((BigInt(x)%P)+P)%P;
const src=genChunk(0,17,false,true); writeFileSync(PROBE,src);
const redeem=Uint8Array.from([...compileFileBytecode(PROBE)]);
const rpush=encodeDataPush(redeem); const locking=encodeLockingBytecodeP2sh32(hash256(redeem)); const tailLen=rpush.length;
const padBytes=t=>{const b=Math.max(2,t);const n=b<=76?b-1:b<=257?b-2:b-3;return encodeDataPush(new Uint8Array(n));};
const pushInt=n=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok=c=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:c}});
const inFull=inState(0).map(BigInt); const points10=inFull.slice(18,28).map(red);
const honestOut=outState(17).map(red); const inCommit=commitBin(points10);
function evalGen(p52,outL){const outCommit=commitBin(outL.map(BigInt));
 const argb=Uint8Array.from([...p52].reverse().flatMap(c=>[...pushInt(c)]));
 const u=Uint8Array.from([...padBytes(TARGET_UNLOCK-argb.length-tailLen),...argb,...rpush]);
 const prog={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
  transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:u}],
  outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}],locktime:0}};
 const st=realVm.evaluate(prog);const t=st.stack[st.stack.length-1];
 return {accepted:st.error===undefined&&st.stack.length===1&&t&&t.length===1&&t[0]===1,error:st.error??null,op:st.metrics.operationCost};}
function variant(K){const p=inFull.slice();for(let i=0;i<12;i++){p[40+i]=BigInt(p[40+i])+K*P;p[0+i]=BigInt(p[0+i])+K*P;}return p;}
for(const [name,K] of [['+1e6 p',1000000n],['+1e12 p',10n**12n],['+1e40 p',10n**40n],['+1e100 p',10n**100n],['+1e300 p',10n**300n],['+1e600 p',10n**600n]]){
  const r=evalGen(variant(K),honestOut);
  console.log(`cInv ${name.padEnd(9)} residue-equiv -> honest covOut : accept=${r.accepted} op=${r.op} err=${r.error}`);
}
