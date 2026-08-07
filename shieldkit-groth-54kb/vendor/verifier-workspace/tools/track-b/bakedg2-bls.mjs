import { repoPath as vcRepoPath } from '#repo-paths';
// BLS analogue attribution: baked-G2 line coeffs in the 30 BLS miller_baked chunks.
// BLS Fp is 381-bit -> coeffs are 48-byte limbs. Measure coeff bytes + project the
// split-blob reloc net (same mechanism; 48B coeffs => bigger lever AND bigger witness).
import { readFileSync, readdirSync } from 'node:fs';
import { compileBytecode } from '../../build/chunked/bls12-381/_pairingmath.mjs';
import { splitTowerBytecode, chunkLockingBytes, setCompiler } from '../../build/chunked/bls12-381/_covenant.mjs';
setCompiler(compileBytecode);
const GEN=vcRepoPath('build/chunked/bls12-381/generated');
// BLS Fp modulus
const PB=0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const beToBig=(u8)=>{let n=0n;for(let i=u8.length-1;i>=0;i--)n=(n<<8n)|BigInt(u8[i]);return n;};
const pushLenAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return 1+op;if(op===0x4c)return 2+b[i+1];if(op===0x4d)return 3+(b[i+1]|(b[i+2]<<8));if(op===0x4e)return 5;if(op===0||op===0x4f||(op>=0x51&&op<=0x60))return 1;return -1;};
const pushDataAt=(b,i)=>{const op=b[i];if(op>=1&&op<=0x4b)return b.slice(i+1,i+1+op);if(op===0x4c)return b.slice(i+2,i+2+b[i+1]);if(op===0x4d){const L=b[i+1]|(b[i+2]<<8);return b.slice(i+3,i+3+L);}if(op===0)return Uint8Array.from([]);return b.slice(i,i+1);};
const files=readdirSync(GEN).filter(f=>/^miller_baked_\d+\.cash$/.test(f)).sort();
let TOT={coeffB:0,np:0,lock:0};const dist=new Set();
console.log('chunk            coeffB #push  lockLen');
for(const f of files){
  const src=readFileSync(`${GEN}/${f}`,'utf8');
  const inline=compileBytecode(src);const {restBytes}=splitTowerBytecode(inline);
  let i=0,cb=0,np=0;
  while(i<restBytes.length){const l=pushLenAt(restBytes,i);if(l<0){i++;continue;}
    if(l>=40){const d=pushDataAt(restBytes,i);if(beToBig(d)<PB){cb+=l;np++;dist.add(Buffer.from(d).toString('hex'));}}i+=l;}
  let lock;try{lock=chunkLockingBytes(src).length;}catch(e){lock=NaN;}
  TOT.coeffB+=cb;TOT.np+=np;TOT.lock+=lock;
  console.log(`${f.padEnd(22)} ${String(cb).padStart(6)} ${String(np).padStart(5)} ${String(lock).padStart(7)}`);
}
console.log(`\nΣ BLS baked-coeff bytes=${TOT.coeffB} pushes=${TOT.np} distinct=${dist.size} Σlock(miller)=${TOT.lock}`);
console.log(`coeff push = 49B each (1 opcode + 48 data) vs BN254 33B`);
// projection: saving/coeff. BN254 net saving/coeff was -22.91B. For BLS the literal is 49B
// (vs 33), split machinery similar (~10-12B), so saving/coeff ~ -37 to -38B.
const SAVE_PER_BLS=37.5; // conservative (49 removed - ~11.5 split machinery)
const lockSaveBLS=Math.round(TOT.np*SAVE_PER_BLS);
console.log(`\nprojected BLS locking saving ~ ${lockSaveBLS} B (${TOT.np} coeffs × ~${SAVE_PER_BLS}B)`);
console.log(`witness added = 48B/coeff = ${48*TOT.np} B blob ⇒ bigger op-pad clawback risk on low-op tail chunks`);
