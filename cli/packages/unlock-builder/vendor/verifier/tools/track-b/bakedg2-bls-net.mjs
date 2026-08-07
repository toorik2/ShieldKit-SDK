import { repoPath as vcRepoPath } from '#repo-paths';
// BLS net projection. Forward miller chunks op-bound ~7.5-7.8M (op-pad ~9,400-9,750B), same
// headroom class as BN254. Current BLS miller witness: ~30 state limbs (48B each ~1,470B) +
// tower blob (BLS tower ~similar 2.2-2.8KB). Conservatively model witness=4,000B base.
// coeff blob = 48B/coeff. saving/coeff ~ -37.5B (real-compile would refine; 49B literal -11.5 split).
import { readFileSync, readdirSync } from 'node:fs';
import { compileBytecode } from '../../build/chunked/bls12-381/_pairingmath.mjs';
import { splitTowerBytecode, chunkLockingBytes, setCompiler } from '../../build/chunked/bls12-381/_covenant.mjs';
setCompiler(compileBytecode);
const GEN=vcRepoPath('build/chunked/bls12-381/generated');
const PB=0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const beToBig=(u8)=>{let n=0n;for(let i=u8.length-1;i>=0;i--)n=(n<<8n)|BigInt(u8[i]);return n;};
const pushLenAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return 1+op;if(op===0x4c)return 2+b[i+1];if(op===0x4d)return 3+(b[i+1]|(b[i+2]<<8));if(op===0x4e)return 5;if(op===0||op===0x4f||(op>=0x51&&op<=0x60))return 1;return -1;};
const pushDataAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return b.slice(i+1,i+1+op);if(op===0x4c)return b.slice(i+2,i+2+b[i+1]);if(op===0x4d){const L=b[i+1]|(b[i+2]<<8);return b.slice(i+3,i+3+L);}if(op===0)return Uint8Array.from([]);return b.slice(i,i+1);};
const tower=(src)=>{try{const r=splitTowerBytecode(compileBytecode(src));return r.blocks.reduce((s,b)=>s+b.bodyData.length,0);}catch(e){return 2500;}};
const man=JSON.parse(readFileSync(`${GEN}/manifest_miller_baked.json`,'utf8'));
// estimate op-bound: chunks NOT last 2 -> op-pad ~9500 (huge headroom). last 2 -> low op.
const files=readdirSync(GEN).filter(f=>/^miller_baked_\d+\.cash$/.test(f)).sort();
let T={save:0,claw:0};const SAVE_PER=37.5, BLOB_PER=49; // 48B data + ~1 amortized pushdata
const N=files.length;
console.log('Assume: forward chunks op-pad ~9500B (headroom ~6000B); last 2 chunks low-op.');
for(let k=0;k<files.length;k++){
  const f=files[k];const src=readFileSync(`${GEN}/${f}`,'utf8');
  const inline=compileBytecode(src);const {restBytes}=splitTowerBytecode(inline);
  let i=0,np=0;while(i<restBytes.length){const l=pushLenAt(restBytes,i);if(l<0){i++;continue;}if(l>=40){const d=pushDataAt(restBytes,i);if(beToBig(d)<PB)np++;}i+=l;}
  const isTail = k>=N-2;
  const opPad = isTail ? (k===N-1?1900:3800) : 9500; // BN254-analogous tail op-pads
  const baseWit = 1470 + tower(src) + 5; // state limbs(48B*~30 but many small) ~ use 1470 + tower
  const blobAdd = np*BLOB_PER;
  const newWit = baseWit + blobAdd;
  const clawback = Math.max(0, newWit - opPad) - Math.max(0, baseWit - opPad);
  const save = Math.round(np*SAVE_PER);
  T.save+=save;T.claw+=clawback;
}
console.log(`\nΣ BLS locking saving (projected) = ${T.save} B`);
console.log(`Σ BLS op-pad clawback (projected) = +${T.claw} B`);
console.log(`Σ BLS NET (projected) = ${T.save-T.claw} B`);
console.log(`(conservative; real-compile would refine saving/coeff like BN254's -22.91 measured)`);
