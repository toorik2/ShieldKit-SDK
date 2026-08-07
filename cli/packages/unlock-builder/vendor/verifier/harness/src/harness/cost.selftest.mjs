// C2 self-test: a verifier.cash script imports the cost toolkit FROM the in-repo
// re-export wrapper (NOT the hard-coded LeanBCH absolute path) and measures one real
// deployed chunk on the VM. Proves the clean import path is reachable and delivers a
// working toolkit that returns real VM metrics.  Run: node harness/src/harness/cost.selftest.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { measureRun, measureBody, measureAllBodies, classifyBound, decompose } from './cost.mjs';

const fail = (m) => { console.error('FAIL:', m); process.exit(1); };

// 1) Every advertised symbol must resolve through the wrapper as a function.
for (const [n, f] of Object.entries({ measureRun, measureBody, measureAllBodies, classifyBound, decompose }))
  if (typeof f !== 'function') fail(`re-export ${n} is not a function (got ${typeof f})`);

// 2) Measure one real deployed chunk's bytecode on the VM, through the wrapper.
const here = dirname(fileURLToPath(import.meta.url));
const V = resolve(here, '../../..'); // …/verifier.cash
const chunks = JSON.parse(
  readFileSync(resolve(V, 'artifacts/bn254-native-standard/170366-patha/chunks.json'), 'utf8'),
);
const c = chunks[1]; // an interior Miller-loop chunk
const r = measureRun(c.lockingHex, c.unlockingHex);

console.log(`measured chunk[${c.index}] "${c.name}" via the verifier.cash wrapper:`);
console.log(`  opCost=${r.opCost}  instr=${r.instr}  lockBytes=${r.lockBytes}  unlockBytes=${r.unlockBytes}`);
console.log(`  decompose: ${JSON.stringify(decompose(r))}`);
console.log(`  classifyBound: ${JSON.stringify(classifyBound(r.unlockBytes, r.opCost))}`);
// NOTE: r.ok is false here — deployed chunks are token-threaded (intra-tx introspection
// covenant) and cannot ACCEPT under measureRun's context-free bare-spend harness. That is
// a property of the chunk + measureRun (use evaluatePair with a covenant/intraTx context
// for accept/reject); C2 only asserts the toolkit is reachable and returns real VM metrics.

// 3) measureRun must have actually driven the VM and returned real numeric op-cost.
if (typeof r.opCost !== 'number' || r.opCost <= 0) fail(`measureRun returned no op-cost (${r.opCost})`);
if (typeof r.instr !== 'number' || r.instr <= 0) fail(`measureRun returned no instr count (${r.instr})`);

console.log('SELFTEST PASS — cost toolkit imported cleanly from the verifier.cash wrapper');
console.log('               (measureRun/measureBody/measureAllBodies/classifyBound/decompose all reachable).');
