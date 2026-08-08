// HP3.10 K3 harness: a 2-input tx where the compute input (index 1) reads the data input's
// (index 0) unlocking bytecode via OP_INPUTBYTECODE (0xca, CHIP-2021-02) and verifies the value
// it carries -- the thin-shard linking that passes a fold-chain intermediate between inputs so
// neither input's scriptSig (redeem + unlock) exceeds 1650B. Args: redeem1, unlock1, unlock0,
// redeem0 (asm files). Evaluates input 1 on the real createVirtualMachineBch2026 and reports the
// input-1 redeem bytes (the linking overhead) + ACCEPT/REJECT. Real VM, no mock (TEST_RULES).
import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();
const asm = (p) => cashAssemblyToBin(readFileSync(p, 'utf8').replace(/\n/g, ' ').trim());
const [r1p, u1p, u0p, r0p] = process.argv.slice(2);
const redeem1 = asm(r1p), unlock1 = asm(u1p), unlock0 = asm(u0p), redeem0 = asm(r0p);
for (const [n, b] of [['redeem1', redeem1], ['unlock1', unlock1], ['unlock0', unlock0], ['redeem0', redeem0]])
  if (typeof b === 'string') { console.log(JSON.stringify({ asmError: n + ': ' + b })); process.exit(0); }

const tx = {
  version: 2,
  inputs: [
    { outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlock0 },
    { outpointIndex: 1, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlock1 },
  ],
  outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }],
  locktime: 0,
};
const sourceOutputs = [
  { lockingBytecode: redeem0, valueSatoshis: 1000n },
  { lockingBytecode: redeem1, valueSatoshis: 1000n },
];
// evaluate one input on the real VM; accept = clean truthy top (fail-closed on error/empty/false)
function evalInput(idx) {
  const tr = vm.debug({ inputIndex: idx, sourceOutputs, transaction: tx });
  const l = tr[tr.length - 1];
  const t = l.stack && l.stack.length ? l.stack[l.stack.length - 1] : undefined;
  return { ok: !l.error && t && t.length > 0 && !(t.length === 1 && t[0] === 0), error: l.error ?? null,
           metrics: l.metrics ?? {} };
}
// input 1 = the compute/consumer input (reads input 0 via OP_INPUTBYTECODE); input 0 = the producer
// (its redeem BINDS the carried value to its own computation, so the carry is not free witness). Both
// must accept for the 2-input tx to be valid -> reporting accept0 proves the producer binding too.
// The bare-script (P2S) model: input i's scriptSig = unlock_i (the redeem is the funding locking
// bytecode, not revealed in the spending tx), so its op-budget = (41+unlock_i)*800 and the <100000B
// whole-tx race is on the UNLOCKS. metrics1 (operationCost vs maximumOperationCost) makes the op-cost
// density check on the consumer input measurable (previously only accept/reject was observable).
const r1 = evalInput(1), r0 = evalInput(0);
console.log(JSON.stringify({ redeem1Bytes: redeem1.length, unlock1Bytes: unlock1.length,
                             unlock0Bytes: unlock0.length, error: r1.error ?? null, accept: r1.ok,
                             accept0: r0.ok, error0: r0.error ?? null, metrics1: r1.metrics }));
