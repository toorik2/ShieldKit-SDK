import { repoPath as vcRepoPath } from '#repo-paths';
// Examine the EXACT structure of baked-coeff pushes in restBytes: order, adjacency,
// whether they appear in clean 6-coeff groups (one per baked line) and whether they're
// interspersed with non-push opcodes (OP_INVOKE etc). Determines codegen complexity of
// "split the coeffs blob in order and feed each line from the witness".
import { readFileSync } from 'node:fs';
import { compileBytecode, splitTowerBytecode } from '../../build/chunked/pairing/_millermath.mjs';
const GEN = vcRepoPath('build/chunked/pairing/generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const beToBig=(u8)=>{let n=0n;for(let i=u8.length-1;i>=0;i--)n=(n<<8n)|BigInt(u8[i]);return n;};
const pushLenAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return 1+op;if(op===0x4c)return 2+b[i+1];if(op===0x4d)return 3+(b[i+1]|(b[i+2]<<8));if(op===0x4e)return 5;if(op===0||op===0x4f||(op>=0x51&&op<=0x60))return 1;return -1;};
const pushDataAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return b.slice(i+1,i+1+op);if(op===0x4c)return b.slice(i+2,i+2+b[i+1]);if(op===0x4d){const L=b[i+1]|(b[i+2]<<8);return b.slice(i+3,i+3+L);}if(op===0)return Uint8Array.from([]);return b.slice(i,i+1);};
// OP names of interest
const NM={0x89:'DEFINE',0x8a:'INVOKE',0x76:'DUP',0xaa:'HASH256',0x88:'EQVERIFY',0x7f:'SPLIT',0x7c:'SWAP',0x69:'VERIFY',0x87:'EQUAL',0x9c:'NUMEQUAL',0x6b:'TOALT',0x6c:'FROMALT'};
const f='miller_baked_02.cash';
const inline=compileBytecode(readFileSync(`${GEN}/${f}`,'utf8'));
const {restBytes}=splitTowerBytecode(inline);
console.log(`${f}: restBytes=${restBytes.length}B`);
let i=0,seq=[],fieldPushIdx=[],idx=0;
while(i<restBytes.length){
  const l=pushLenAt(restBytes,i);
  if(l<0){ const op=restBytes[i]; seq.push({k:'op',op,nm:NM[op]||('0x'+op.toString(16))}); i++; idx++; continue;}
  const d=pushDataAt(restBytes,i); const isField=l>=20&&beToBig(d)<P;
  seq.push({k:'push',len:l,dlen:d.length,field:isField}); if(isField)fieldPushIdx.push(idx); idx++; i+=l;
}
// Show a window around the first 3 field pushes to see interspersion
const firstField=fieldPushIdx[0];
console.log(`\nfirst field push at seq idx ${firstField}; total field pushes=${fieldPushIdx.length}`);
console.log('window [first-4 .. first+30]:');
for(let k=Math.max(0,firstField-4);k<Math.min(seq.length,firstField+34);k++){
  const s=seq[k];
  console.log(`  ${String(k).padStart(4)} ${s.k==='op'?('OP '+s.nm):('PUSH '+s.dlen+'B'+(s.field?' <FIELD>':''))}`);
}
// Count: are field pushes contiguous in groups of 6, or split by opcodes?
let groups=[],run=[];
for(let g=0;g<fieldPushIdx.length;g++){
  if(run.length===0||fieldPushIdx[g]===run[run.length-1]+1) run.push(fieldPushIdx[g]);
  else {groups.push(run); run=[fieldPushIdx[g]];}
}
if(run.length)groups.push(run);
const sizes=groups.map(g=>g.length);
console.log(`\ncontiguous field-push runs: ${groups.length} runs, sizes=[${sizes.join(',')}]`);
console.log(`(6 = a full line's coeff set pushed together; the 8 line() args are 6 coeffs + Px,Py(those are vars not literals))`);
