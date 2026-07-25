// Export ONE V3 Miller/residue chunk (window [0,27), the re-chunked V3 chunk 0) as a real
// BCH-2026 covenant tx (wire hex + source-outputs hex) plus libauth's op-cost/accept, so the
// LeanBCH VM (an independent consensus+op-cost implementation) can re-verify it as a SECOND ORACLE.
// Requires LIB_IMPORT='../variants/V3_millerres_lib.cash' so genChunk emits the V3 lib import.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK } from './_millermath.mjs';
import { genChunk, ops, inState, outState } from './gen_miller_residue.mjs';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_xcheck.cash');
const [LO, HI] = [Number(process.env.XLO ?? 0), Number(process.env.XHI ?? 4)];

const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });

const src = genChunk(LO, HI, HI === ops.length);
writeFileSync(PROBE, src);
const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const tail = rpush.length;
const inLimbs = inState(LO).map(BigInt), outLimbs = outState(HI).map(BigInt);
const inCommit = commitBin(inLimbs), outCommit = commitBin(outLimbs);
const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
const mkUnlock = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);

function mkProgram(unlocking) {
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
}
const accepts = (u) => { const st = realVm.evaluate(mkProgram(u)); const t = st.stack[st.stack.length - 1]; return st.error === undefined && st.stack.length === 1 && t !== undefined && t.length === 1 && t[0] === 1; };

// tight minimal accepting unlocking (matches v3_fullverifier)
let loU = argb.length + tail + 2, hiU = TARGET_UNLOCK;
while (loU < hiU) { const mid = (loU + hiU) >> 1; if (accepts(mkUnlock(mid))) hiU = mid; else loU = mid + 1; }
const unlocking = mkUnlock(hiU);
const prog = mkProgram(unlocking);
const st = realVm.evaluate(prog);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;

const txHex = binToHex(encodeTransaction(prog.transaction));
const sourceOutputsHex = binToHex(encodeTransactionOutputs(prog.sourceOutputs));
const out = {
  window: [LO, HI], lockingBytes: locking.length, unlockingBytes: unlocking.length,
  redeemBytes: redeem.length,
  libauthOpCost: st.metrics.operationCost, libauthAccepted: accepted,
  txHex, sourceOutputsHex,
};
writeFileSync('/tmp/xcheck_small.json', JSON.stringify(out));
console.log(JSON.stringify({ window: out.window, lockingBytes: out.lockingBytes, unlockingBytes: out.unlockingBytes, redeemBytes: out.redeemBytes, libauthOpCost: out.libauthOpCost, libauthAccepted: out.libauthAccepted, txHexLen: txHex.length / 2, srcOutsLen: sourceOutputsHex.length / 2 }));
