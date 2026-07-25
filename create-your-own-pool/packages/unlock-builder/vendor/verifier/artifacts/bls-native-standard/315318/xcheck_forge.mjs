// Export a FORGED group0 tx (flip 1 byte of the ECIP genesis inBlob = tamper public inputs)
// to LeanBCH wire format; libauth must reject input 0, then LeanBCH must independently reject too.
import { readFileSync, writeFileSync } from 'node:fs';
import { createVirtualMachineBch2026, hexToBin, binToHex, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';
const j = JSON.parse(readFileSync('/home/toorik/Projects/verifier.cash/harness/src/bch/groth16-bls12381-grouped-residue-vectors.json', 'utf8'));
const realVm = createVirtualMachineBch2026(false);
const CATEGORY = hexToBin(j.category);
const h = (s) => (s == null ? new Uint8Array(0) : hexToBin(s));
const tokenOf = (t) => (t ? { amount: 0n, category: CATEGORY, nft: { capability: t.capability, commitment: h(t.commitment) } } : undefined);

// flip one byte inside the FIRST data push (inBlob) of step0's unlocking
function tamperInBlob(hex) {
  const b = hexToBin(hex); // step0 push0 is OP_PUSHDATA1(0x4c) len=96 -> data starts at byte 2
  b[2 + 8] ^= 0x01; return b;
}
const g = j.valid.groups[0];
const steps = j.valid.steps.slice(g.lo, g.hi + 1);
const inputs = steps.map((s, n) => ({ locking: h(s.locking), unlocking: n === 0 ? tamperInBlob(s.unlocking) : h(s.unlocking) }));
const program = {
  inputIndex: 0,
  sourceOutputs: inputs.map((inp, n) => ({ lockingBytecode: inp.locking, valueSatoshis: 1000n, token: n === 0 ? tokenOf(g.inToken) : undefined })),
  transaction: {
    version: 2,
    inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
    outputs: [{ lockingBytecode: h(g.outLocking), valueSatoshis: 1000n, token: tokenOf(g.outToken) }],
    locktime: 0,
  },
};
const st = realVm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
writeFileSync('/tmp/xcheck_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xcheck_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log(JSON.stringify({ forge: 'group0 ECIP inBlob byte-flip (false public inputs)', libauthAccepted: accepted, error: st.error ?? null }));
