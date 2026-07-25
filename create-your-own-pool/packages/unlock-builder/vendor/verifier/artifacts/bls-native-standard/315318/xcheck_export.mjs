// Serialize a chosen group's EXACT frozen token-carrying tx to LeanBCH's xcheck wire format
// (/tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex) and report libauth's input-0 accept + op-cost.
// Then `xcheck` (the machine-checked LeanBCH VM) verifies input 0 independently; the two must agree.
import { readFileSync, writeFileSync } from 'node:fs';
import { createVirtualMachineBch2026, hexToBin, binToHex, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';

const gi = Number(process.argv[2] ?? 0);
const j = JSON.parse(readFileSync('/home/toorik/Projects/verifier.cash/harness/src/bch/groth16-bls12381-grouped-residue-vectors.json', 'utf8'));
const realVm = createVirtualMachineBch2026(false);
const CATEGORY = hexToBin(j.category);
const OP_RETURN = Uint8Array.from([0x6a]);
const h = (s) => (s == null ? new Uint8Array(0) : hexToBin(s));
const tokenOf = (t) => (t ? { amount: 0n, category: CATEGORY, nft: { capability: t.capability, commitment: h(t.commitment) } } : undefined);

const g = j.valid.groups[gi];
const steps = j.valid.steps.slice(g.lo, g.hi + 1);
const inputs = steps.map((s) => ({ locking: h(s.locking), unlocking: h(s.unlocking) }));
const program = {
  inputIndex: 0,
  sourceOutputs: inputs.map((inp, n) => ({ lockingBytecode: inp.locking, valueSatoshis: 1000n, token: n === 0 ? tokenOf(g.inToken) : undefined })),
  transaction: {
    version: 2,
    inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
    outputs: g.outToken ? [{ lockingBytecode: h(g.outLocking), valueSatoshis: 1000n, token: tokenOf(g.outToken) }] : [{ lockingBytecode: OP_RETURN, valueSatoshis: 1000n }],
    locktime: 0,
  },
};
const st = realVm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
writeFileSync('/tmp/xcheck_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xcheck_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log(JSON.stringify({ group: gi, input0Step: g.lo, label: steps[0].label, libauthAccepted: accepted, libauthOpCost: st.metrics.operationCost, error: st.error ?? null, txBytes: encodeTransaction(program.transaction).length }));
