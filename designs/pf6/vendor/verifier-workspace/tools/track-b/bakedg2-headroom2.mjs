import { repoPath as vcRepoPath } from '#repo-paths';
// Real-op-cost headroom (op-costs captured from gen_miller_baked honest emit pass).
import { readFileSync, readdirSync } from 'node:fs';
import * as M from '../../build/chunked/pairing/_millermath.mjs';
const { compileBytecode, splitTowerBytecode, chunkLockingBytes, towerWitnessFor, stateArgBytes } = M;
const GEN = vcRepoPath('build/chunked/pairing/generated');
const man = JSON.parse(readFileSync(`${GEN}/manifest_miller_baked.json`, 'utf8'));
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const beToBig = (u8) => { let n=0n; for (let i=u8.length-1;i>=0;i--) n=(n<<8n)|BigInt(u8[i]); return n; };
const pushLenAt=(b,i)=>{const op=b[i]; if(op>=1&&op<=0x4b)return 1+op; if(op===0x4c)return 2+b[i+1]; if(op===0x4d)return 3+(b[i+1]|(b[i+2]<<8)); if(op===0x4e)return 5; if(op===0||op===0x4f||(op>=0x51&&op<=0x60))return 1; return -1;};
const pushDataAt=(b,i)=>{const op=b[i]; if(op>=1&&op<=0x4b)return b.slice(i+1,i+1+op); if(op===0x4c)return b.slice(i+2,i+2+b[i+1]); if(op===0x4d){const L=b[i+1]|(b[i+2]<<8); return b.slice(i+3,i+3+L);} if(op===0)return Uint8Array.from([]); return b.slice(i,i+1);};
function coeffBytesOf(src){const inline=compileBytecode(src); const {restBytes}=splitTowerBytecode(inline); let i=0,b=0,n=0;
  while(i<restBytes.length){const l=pushLenAt(restBytes,i); if(l<0){i++;continue;} if(l>=20){const d=pushDataAt(restBytes,i); if(beToBig(d)<P){b+=l;n++;}} i+=l;} return {b,n};}
// real honest op-costs from gen emit pass (chunk idx -> op)
const OP = {0:7525344,1:7451661,2:7340187,3:7684628,4:7453071,5:7456179,6:7683868,7:7451705,8:7684153,9:7451808,10:7683903,11:7457103,12:7681520,13:7340503,14:7451569,15:7685820,16:7456384,17:7452027,18:7677310,19:3007307,20:1444747};
console.log('chunk  op        opPad   stateArg blob  curWit  headroom coeffB  #c  netΔ/chunk');
let T={op:0,opPad:0,stateArg:0,blob:0,headroom:0,coeff:0,nc:0,net:0,posHead:0};
for (const c of man.chunks) {
  const f=`miller_baked_${String(c.idx).padStart(2,'0')}.cash`;
  const src=readFileSync(`${GEN}/${f}`,'utf8');
  const op=OP[c.idx], opPad=Math.ceil(op/800);
  // state args: decl order, 30 ints; use representative in-range limbs for byte length (push len depends on magnitude; real limbs are ~32B → use P-1 sized)
  const args=Array.from({length:30},()=>P-1n);
  const stateArg=stateArgBytes(args);
  const blob=towerWitnessFor(src).length;
  const curWit=stateArg+blob;
  const headroom=opPad-curWit;
  const {b:coeff,n:nc}=coeffBytesOf(src);
  // After reloc: locking loses `coeff` bytes (becomes hash-bind 36B + split overhead).
  // Witness gains `coeff` blob bytes. New witness = curWit + coeff. New unlock-scored =
  // max(opPad, curWit+coeff). Old unlock-scored = max(opPad, curWit). Clawback = newUnlock-oldUnlock.
  const oldUnlock=Math.max(opPad,curWit), newUnlock=Math.max(opPad,curWit+coeff);
  const clawback=newUnlock-oldUnlock;
  const lockSaved=coeff; // approx; minus hash-bind+split overhead added back (computed separately)
  const net=lockSaved-clawback;
  if (headroom>=coeff) T.posHead++;
  T.op+=op;T.opPad+=opPad;T.stateArg+=stateArg;T.blob+=blob;T.headroom+=headroom;T.coeff+=coeff;T.nc+=nc;T.net+=net;
  console.log(`${String(c.idx).padStart(2,'0')}  ${String(op).padStart(9)} ${String(opPad).padStart(6)} ${String(stateArg).padStart(7)} ${String(blob).padStart(5)} ${String(curWit).padStart(6)} ${String(headroom).padStart(7)} ${String(coeff).padStart(6)} ${String(nc).padStart(3)} ${String(net).padStart(7)}`);
}
console.log(`\nΣ op=${T.op.toLocaleString()} ΣopPad=${T.opPad} ΣstateArg=${T.stateArg} Σblob=${T.blob}`);
console.log(`Σheadroom=${T.headroom} Σcoeff=${T.coeff} Σ#coeffpush=${T.nc} chunks headroom>=coeff: ${T.posHead}/21`);
console.log(`Σnet(lockSaved-witnessClawback, BEFORE hash-bind/split overhead)= ${T.net}`);
