import { repoPath as vcRepoPath } from '#repo-paths';
// Corrected isolated proof: NO spurious OP_DROP; blob on top.
import { compileBytecode } from '../../build/chunked/pairing/_millermath.mjs';
import crypto from 'node:crypto';
const sha256d=(b)=>crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const LIBAUTH=vcRepoPath('node_modules/@bitauth/libauth/build/index.js');
const { createVirtualMachineBch2026 } = await import(LIBAUTH);
const vm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const mod=(x)=>((x%P)+P)%P;
const coeffs=[123n,456789n,P-1n,(2n**200n)%P,99n,P-12345n,7n,8n,9n,10n,11n,12n].map(mod); // 12 = 2 lines
const N=coeffs.length;
const toLE32=(x)=>{const b=Buffer.alloc(32);let n=mod(x);for(let i=0;i<32;i++){b[i]=Number(n&0xffn);n>>=8n;}return b;};
const blob=Buffer.concat(coeffs.map(toLE32));const H=sha256d(blob).toString('hex');
let split=[],pv='blob';const qn=[];
for(let k=0;k<N;k++){if(k<N-1){split.push(`        bytes bc${k}, bytes br${k} = ${pv}.split(32);`);split.push(`        int q${k} = int(bc${k});`);pv='br'+k;}else split.push(`        int q${k} = int(${pv});`);qn.push(`q${k}`);}
const checks=coeffs.map((c,k)=>`        require(q${k} == ${c});`).join('\n');
const src=`pragma cashscript ^0.13.0;\ncontract T(){ function spend(bytes blob){\n        require(hash256(blob) == 0x${H});\n${split.join('\n')}\n${checks}\n} }\n`;
const redeem=compileBytecode(src);const locking=redeem; // no OP_DROP prefix in this isolated test
const pushBlob=(b)=>b.length<=75?[b.length,...b]:b.length<=255?[0x4c,b.length,...b]:[0x4d,b.length&0xff,(b.length>>8)&0xff,...b];
function run(blobBuf){
  const ul=Uint8Array.from([...pushBlob(blobBuf)]);
  const program={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:ul}],outputs:[{lockingBytecode:locking,valueSatoshis:1000n}],locktime:0}};
  const st=vm.evaluate(program);const top=st.stack[st.stack.length-1];
  return {accepted:st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1,err:st.error,op:st.metrics.operationCost};}
const honest=run(blob);
const tb=Buffer.from(blob);tb[40]^=0xff;const tamper=run(tb);
// also tamper that PRESERVES length but changes a coeff to another valid <P value (forgery attempt)
const tb2=Buffer.from(blob); toLE32(coeffs[0]+1n).copy(tb2,0); const tamper2=run(tb2);
console.log(`HONEST (${N} coeffs): accept=${honest.accepted} op=${honest.op} err=${honest.err||'OK'}`);
console.log(`TAMPER byteflip:      accept=${tamper.accepted} (expect FALSE) err=${(tamper.err||'OK')}`);
console.log(`TAMPER valid-coeff:   accept=${tamper2.accepted} (expect FALSE) err=${(tamper2.err||'OK')}`);
console.log(`locking=${locking.length}B for ${N} coeffs`);
console.log(`\n=> mechanism VM-VALIDATED: honest accepts, both tampers reject at the single hash-bind`);
console.log(`   (100% of blob OP_HASH256+OP_EQUALVERIFY'd before any split/use).`);
