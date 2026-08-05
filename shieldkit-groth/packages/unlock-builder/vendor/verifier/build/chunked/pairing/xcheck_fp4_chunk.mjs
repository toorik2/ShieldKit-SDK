// Dual-VM cross-check of crown chain chunks from a SAVE_DIR dump (unified_affine.mjs):
// reconstruct the EXACT measured program (spent token UTXO -> chunk P2SH20 lock, unlocking as
// dumped, output[0] -> successor spk + out token) as wire tx + srcouts hex, evaluate on libauth
// BCH-2026, write /tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex, and (caller) run the LeanBCH
// compiled VM (.lake/build/bin/xcheck) as the second oracle. XTAMPER=1 flips one byte of the
// input NFT commitment — BOTH VMs must then reject.
//   node xcheck_fp4_chunk.mjs <dump-dir> <chunk-fname>     e.g. ml_131_150
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  hexToBin, binToHex, encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const [dir, fname] = [process.argv[2], process.argv[3]];
if (!dir || !fname) { console.error('usage: node xcheck_fp4_chunk.mjs <dump-dir> <chunk-fname>'); process.exit(2); }
const TAMPER = process.env.XTAMPER === '1';
const chunks = JSON.parse(readFileSync(join(dir, 'chunks.json'), 'utf8'));
const i = chunks.findIndex((c) => c.fname === fname);
if (i < 0) { console.error(`chunk ${fname} not in dump`); process.exit(2); }
const c = chunks[i];
const succ = i + 1 < chunks.length ? chunks[i + 1] : null;

const CATEGORY = new Uint8Array(32).fill(0xcd);
const tok = (commitHex) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: hexToBin(commitHex) } });
let inCommit = hexToBin(c.inCommit);
if (TAMPER) inCommit[3] ^= 0x01; // tampered committed state -> covIn hash mismatch -> reject
const outLock = succ ? hexToBin(succ.lockingHex) : hexToBin(c.lockingHex);
const program = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: hexToBin(c.lockingHex), valueSatoshis: 1000n, token: { amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: inCommit } } }],
  transaction: {
    version: 2,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: hexToBin(c.unlockingHex) }],
    outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, ...(c.outCommit ? { token: tok(c.outCommit) } : {}) }],
    locktime: 0,
  },
};
const vm = createVirtualMachineBch2026(false);
const st = vm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
writeFileSync('/tmp/xcheck_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xcheck_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log(`chunk=${c.name} tamper=${TAMPER} libauthAccepted=${accepted} libauthOpCost=${st.metrics.operationCost} err=${st.error ?? 'none'}`);
console.log('wrote /tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex (LeanBCH second oracle: .lake/build/bin/xcheck)');
