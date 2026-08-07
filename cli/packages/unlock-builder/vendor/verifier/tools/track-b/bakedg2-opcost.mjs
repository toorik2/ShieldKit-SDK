import { repoPath as vcRepoPath } from '#repo-paths';
// Measure the EXACT op-cost added per coeff by the split-blob hash-bind mechanism, by
// running the isolated contract at N=6,12,24,48,60 and fitting marginal op/coeff + fixed.
import { compileBytecode } from '../../build/chunked/pairing/_millermath.mjs';
import crypto from 'node:crypto';
const sha256d=(b)=>crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const LIBAUTH=vcRepoPath('node_modules/@bitauth/libauth/build/index.js');
const { createVirtualMachineBch2026 } = await import(LIBAUTH);
const vm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const mod=(x)=>((x%P)+P)%P;
const toLE32=(x)=>{const b=Buffer.alloc(32);let n=mod(x);for(let i=0;i<32;i++){b[i]=Number(n&0xffn);n>>=8n;}return b;};
const pushBlob=(b)=>b.length<=75?[b.length,...b]:b.length<=255?[0x4c,b.length,...b]:[0x4d,b.length&0xff,(b.length>>8)&0xff,...b];
function measure(N){
  const coeffs=Array.from({length:N},(_,k)=>mod(BigInt(k)*1000003n+7n));
  const blob=Buffer.concat(coeffs.map(toLE32));const H=sha256d(blob).toString('hex');
  let split=[],pv='blob';for(let k=0;k<N;k++){if(k<N-1){split.push(`bytes bc${k}, bytes br${k} = ${pv}.split(32);`);split.push(`int q${k} = int(bc${k});`);pv='br'+k;}else split.push(`int q${k} = int(${pv});`);}
  const checks=coeffs.map((c,k)=>`require(q${k} == ${c});`).join('\n');
  const src=`pragma cashscript ^0.13.0;\ncontract T(){ function spend(bytes blob){ require(hash256(blob) == 0x${H});\n${split.join('\n')}\n${checks} } }\n`;
  const locking=compileBytecode(src);
  const ul=Uint8Array.from([...pushBlob(blob)]);
  const program={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n}],transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:ul}],outputs:[{lockingBytecode:locking,valueSatoshis:1000n}],locktime:0}};
  const st=vm.evaluate(program);
  return {N,op:st.metrics.operationCost,lock:locking.length,acc:st.error===undefined};
}
const rows=[6,12,24,48,60].map(measure);
for(const r of rows)console.log(`N=${String(r.N).padStart(2)}: op=${String(r.op).padStart(6)} lock=${r.lock} acc=${r.acc}`);
// marginal op/coeff and lock/coeff between N=12 and N=60
const a=rows.find(r=>r.N===12),b=rows.find(r=>r.N===60);
console.log(`\nmarginal op/coeff  = ${((b.op-a.op)/(b.N-a.N)).toFixed(1)}`);
console.log(`marginal lock/coeff= ${((b.lock-a.lock)/(b.N-a.N)).toFixed(2)} (mechanism only; the line() coeff arg is the SAME ref either way)`);
console.log(`\nNOTE: this isolated lock/coeff includes the require(q==lit) CHECK (33B literal) which the REAL`);
console.log(`chunk does NOT have (line() just references q). So real lock saving/coeff is BIGGER (the 33B`);
console.log(`literal LEAVES; only the ~10B split machinery is added). Real marginal lock = split-only ~9.8B/coeff added,`);
console.log(`33B removed => -23B/coeff net (from bakedg2-blob2). op/coeff ~${((b.op-a.op)/(b.N-a.N)).toFixed(0)}.`);
