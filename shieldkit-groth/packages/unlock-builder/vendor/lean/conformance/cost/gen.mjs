// LeanBCH consensus op-cost DIFFERENTIAL generator.
//
// Runs each locking script in `battery.txt` (hex, P2S: run from empty stack) through the pinned
// reference implementation @bitauth/libauth 3.1.0-next.8's BCH-2026 VM, extracts the five raw
// consensus cost metrics, and emits BOTH a human-readable `vectors.txt` and the machine-generated
// Lean literal `vectors.lean.txt` that `LeanBCH/Validation/CostDifferential.lean` pins the MODEL against at
// build time. The expected numbers are therefore libauth's ACTUAL output — never hand-typed — so a
// cost-constant transcription slip in the Lean model FAILS `lake build LeanBCHValidation`, and re-running this
// regenerates the ground truth. Metrics: (arithmeticCost, hashDigestIterations, signatureCheckCount,
// stackPushedBytes, evaluatedInstructionCount) — the exact five the op-cost formula sums.
//
// Regenerate:  node conformance/cost/gen.mjs   (needs @bitauth/libauth 3.1.0-next.8 reachable below)
import * as la from '../../../layer1.cash/node_modules/@bitauth/libauth/build/index.js';
import fs from 'node:fs';
const V = '3.1.0-next.8';
const vm = la.createVirtualMachineBch2026(true);
const hexToBin = h => Uint8Array.from(h.match(/../g).map(b => parseInt(b, 16)));
const leanBytes = h => '[' + h.match(/../g).map(b => '0x' + b).join(',') + ']';
const battery = fs.readFileSync(new URL('./battery.txt', import.meta.url), 'utf8').trim().split('\n')
  .map(l => l.trim()).filter(l => l && !l.startsWith('#'));
const txt = [], lean = [];
for (const hex of battery) {
  const prog = { inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: hexToBin(hex), valueSatoshis: 1000n }],
    transaction: { version: 2,
      inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), unlockingBytecode: new Uint8Array(0), sequenceNumber: 0 }],
      outputs: [{ lockingBytecode: new Uint8Array(0), valueSatoshis: 1000n }], locktime: 0 } };
  const m = vm.evaluate(prog).metrics ?? {};
  const t = [m.arithmeticCost, m.hashDigestIterations, m.signatureCheckCount, m.stackPushedBytes, m.evaluatedInstructionCount];
  if (t.some(x => x === undefined)) { console.error('no metrics for', hex); process.exit(1); }
  txt.push(`${hex} ${t.join(' ')}`);
  lean.push(`  (${leanBytes(hex)}, ${t.join(', ')}),`);
}
fs.writeFileSync(new URL('./vectors.txt', import.meta.url),
  `# libauth ${V} BCH-2026 op-cost metrics: hex arithmeticCost hashDigestIterations signatureCheckCount stackPushedBytes evaluatedInstructionCount\n` + txt.join('\n') + '\n');
fs.writeFileSync(new URL('./vectors.lean.txt', import.meta.url), lean.join('\n') + '\n');
console.log(`libauth ${V}: emitted ${battery.length} cost vectors → vectors.txt + vectors.lean.txt`);
