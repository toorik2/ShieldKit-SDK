// DUAL-VM export: reconstruct a chosen frozen chunk EXACTLY (as the builder's evalCov does), run it on
// the real libauth BCH-2026 VM (accept + op-cost), and write /tmp/xcheck_{tx,srcouts}.hex for the
// LeanBCH twin (LeanBCH/.lake/build/bin/xcheck -> leanVerifyInput + leanFullOpCost). The two VMs must
// AGREE on accept + op-cost.  Self-contained: needs only @bitauth/libauth + the frozen chunks.json.
//   node xcheck_affine_export.mjs [chunks.json] [index]
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { hexToBin, binToHex, createVirtualMachineBch2026, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));
const chunksPath = process.argv[2] ?? join(HERE, 'chunks.json');
const idx = Number(process.argv[3] ?? 8);
const chunks = JSON.parse(readFileSync(chunksPath, 'utf8'));
const c = chunks[idx];
const CATEGORY = new Uint8Array(32).fill(0xcd);
const isTerminal = c.outCommit === null;
const succLockHex = isTerminal ? c.lockingHex : chunks[idx + 1].lockingHex;
const tok = (commitmentHex) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: hexToBin(commitmentHex) } });
const program = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: hexToBin(c.lockingHex), valueSatoshis: 1000n, token: tok(c.inCommit) }],
  transaction: {
    version: 2,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: hexToBin(c.unlockingHex) }],
    outputs: [{ lockingBytecode: hexToBin(succLockHex), valueSatoshis: 1000n, ...(isTerminal ? {} : { token: tok(c.outCommit) }) }],
    locktime: 0,
  },
};
const vm = createVirtualMachineBch2026(false);
const st = vm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
console.log(`CHUNK ${c.name} (idx ${idx}, stage ${c.stage})`);
console.log(`libauthAccept=${accepted} libauthOpCost=${st.metrics.operationCost} err=${st.error ?? 'none'}`);
console.log(`chunks.json recorded op=${c.operationCost} (match=${c.operationCost === st.metrics.operationCost})`);
writeFileSync('/tmp/xcheck_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xcheck_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log('wrote /tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex');
