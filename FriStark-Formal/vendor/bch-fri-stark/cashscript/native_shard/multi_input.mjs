// HP3.1 harness: an N-input tx on the real BCH-2026 VM. Generalises linked_input.mjs (2-input) so a
// GENERIC consumer redeem placed at ANY position derives which producer it reads from its own
// OP_INPUTINDEX (the runtime-index / uniform-partition soundness: one script, position-correct reads).
// Args: a JSON spec file describing inputs [{redeem, unlock}] (asm strings) + the indices to evaluate.
// Reports per-evaluated-index accept/error + redeem bytes. Real VM, no mock (TEST_RULES).
import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();
const asm = (s) => cashAssemblyToBin(String(s).replace(/\n/g, ' ').trim());
const spec = JSON.parse(readFileSync(process.argv[2], 'utf8'));

// compile every input's redeem (locking) + unlock (unlocking) bytecode
const compiled = spec.inputs.map((inp, i) => {
  const r = asm(inp.redeem), u = asm(inp.unlock ?? '');
  for (const [n, b] of [[`redeem${i}`, r], [`unlock${i}`, u]])
    if (typeof b === 'string') { console.log(JSON.stringify({ asmError: n + ': ' + b })); process.exit(0); }
  return { redeem: r, unlock: u };
});

const tx = {
  version: 2,
  inputs: compiled.map((c, i) => ({
    outpointIndex: i, outpointTransactionHash: new Uint8Array(32),
    sequenceNumber: 0, unlockingBytecode: c.unlock,
  })),
  outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }],
  locktime: 0,
};
const sourceOutputs = compiled.map((c) => ({ lockingBytecode: c.redeem, valueSatoshis: 1000n }));

// evaluate one input on the real VM; accept = clean truthy top (fail-closed on error/empty/false)
function evalInput(idx) {
  const tr = vm.debug({ inputIndex: idx, sourceOutputs, transaction: tx });
  const l = tr[tr.length - 1];
  const t = l.stack && l.stack.length ? l.stack[l.stack.length - 1] : undefined;
  return { idx, ok: !l.error && t && t.length > 0 && !(t.length === 1 && t[0] === 0),
           error: l.error ?? null, redeemBytes: compiled[idx].redeem.length };
}

const indices = spec.evaluate ?? compiled.map((_, i) => i);
console.log(JSON.stringify({ results: indices.map(evalInput), nInputs: compiled.length }));
