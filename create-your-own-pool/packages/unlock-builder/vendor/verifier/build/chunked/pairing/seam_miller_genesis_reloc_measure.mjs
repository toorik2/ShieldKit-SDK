import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw } from './_millermath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex } from '@bitauth/libauth';
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_reloc.cash');
const realVm = createVirtualMachineBch2026(false);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush = (argLen, target) => Uint8Array.from([0x4d, ...numberToBinUint16LE(target-argLen-3), ...new Uint8Array(target-argLen-3)]);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x)=>((BigInt(x)%P)+P)%P;
// binary-search minimal accepting unlock length (deployed convention)
function measureReloc(N) {
  const src = genChunk(0, N, false, true);
  writeFileSync(PROBE, src);
  let raw; try{ raw = compileFileBytecodeRaw(PROBE); }catch(e){ return {N, compileError:String(e?.message??e)}; }
  const locking = Uint8Array.from([...raw]);
  const in0 = inState(0).map(BigInt);
  const ptL = in0.slice(18,28);
  const inCommit = commitBin(ptL.map(red));
  const outCommit = commitBin(outState(N).map(red));
  const argBytes = Uint8Array.from([...in0].reverse().flatMap((v)=>[...pushInt(v)]));
  const tok=(cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
  const evalAt=(target)=>{ const pad=padPush(argBytes.length,target); const unlocking=Uint8Array.from([...pad,...argBytes]);
    const st=realVm.evaluate({inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
      transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
      outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}],locktime:0}});
    const top=st.stack[st.stack.length-1];
    return {accepted: st.error===undefined && st.stack.length===1 && top?.length===1 && top[0]===1, op:st.metrics.operationCost, unlock:unlocking.length, err:st.error??null}; };
  const top=evalAt(TARGET_UNLOCK);
  if(!top.accepted) return {N, accepted:false, op:top.op, lock:locking.length, err:top.err, inCommit:binToHex(inCommit), outCommit:binToHex(outCommit)};
  let lo=argBytes.length+3+2, hi=TARGET_UNLOCK;
  while(lo<hi){ const mid=(lo+hi)>>1; if(evalAt(mid).accepted) hi=mid; else lo=mid+1; }
  const fin=evalAt(hi);
  return {N, accepted:fin.accepted, op:fin.op, lock:locking.length, unlock:fin.unlock, inCommit:binToHex(inCommit), outCommit:binToHex(outCommit)};
}
const args=(process.argv.slice(2).map(Number)); const Ns=args.length?args:[8,10,12,14,16];
for (const N of Ns) {
  const r = measureReloc(N);
  if(r.compileError){console.log(`N=${N}: COMPILE ${r.compileError}`);continue;}
  const interiorCovIn = binToHex(commitBin(inState(N).map(red)));
  console.log(`N=${String(N).padStart(2)}: acc=${r.accepted} op=${String(r.op).padStart(9)} lock=${r.lock} unlock=${r.unlock??'-'} covOut==interiorCovIn(${N})? ${r.outCommit===interiorCovIn} ${r.err?('ERR '+r.err):''}`);
}
