// DUAL-VM FORGE exporter: reconstruct a frozen chunk, TAMPER its witness (flip the last witness byte,
// exactly as forge_battery.mjs attack A), run libauth (must REJECT), and write /tmp/xcheck_tx.hex +
// /tmp/xcheck_srcouts.hex so the LeanBCH twin (LeanBCH/.lake/build/bin/xcheck) can independently
// confirm leanVerifyInput=false on the SAME forged bytes.
//   node xcheck_forge.mjs [chunks.json] [idx]   then: (cd LeanBCH && .lake/build/bin/xcheck)
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, encodeDataPush, createVirtualMachineBch2026,
  encodeTransaction, encodeTransactionOutputs,
} from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));
const chunksPath = process.argv[2] ?? join(HERE, 'chunks.json');
const idx = Number(process.argv[3] ?? 0);
const chunks = JSON.parse(readFileSync(chunksPath, 'utf8'));
const c = chunks[idx];
const CATEGORY = new Uint8Array(32).fill(0xcd);
const tok = (h) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: hexToBin(h) } });
const rpushLen = (R) => R <= 75 ? 1 + R : R <= 255 ? 2 + R : R <= 65535 ? 3 + R : 5 + R;

const unlocking = hexToBin(c.unlockingHex);
const redeem = hexToBin(c.redeemHex);
const wIdx = unlocking.length - rpushLen(redeem.length) - 1; // last witness byte, before the redeem push
const forged = unlocking.slice(); forged[wIdx] ^= 0x01;

const isTerminal = c.outCommit === null;
const succLockHex = isTerminal ? c.lockingHex : chunks[idx + 1].lockingHex;
const program = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: hexToBin(c.lockingHex), valueSatoshis: 1000n, token: tok(c.inCommit) }],
  transaction: {
    version: 2,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: forged }],
    outputs: [{ lockingBytecode: hexToBin(succLockHex), valueSatoshis: 1000n, ...(isTerminal ? {} : { token: tok(c.outCommit) }) }],
    locktime: 0,
  },
};
const vm = createVirtualMachineBch2026(false);
const st = vm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
console.log(`FORGE chunk ${c.name} (idx ${idx}) witness byte @${wIdx} flipped`);
console.log(`libauthAccept=${accepted} (must be false)  op=${st.metrics.operationCost}  err=${st.error ?? 'none'}`);
writeFileSync('/tmp/xcheck_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xcheck_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log('wrote /tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex — now run the LeanBCH twin');
