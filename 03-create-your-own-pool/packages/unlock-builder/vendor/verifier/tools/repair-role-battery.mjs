// Concrete whole-transaction role/topology battery for the 81,801-byte root-pinned
// candidate. Each mutation gets a fresh parent transaction whose outputs are the
// mutated source UTXOs; spending outpoints are recomputed from that parent txid.
// This prevents detached source-output mutations from being misreported as UTXO tests.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import {
  binToHex,
  decodeTransactionBch,
  decodeTransactionOutputs,
  encodeTransaction,
  hash256,
  hexToBin,
  createVirtualMachineBch2026,
  verifyTransactionTokens,
} from '../node_modules/@bitauth/libauth/build/index.js';

const PARENT = process.env.PARENT || '/tmp/verifier-cash-81665-parent-envelope-main';
const OUT = process.env.OUT || '/tmp/verifier-cash-81665-role-battery';
mkdirSync(OUT, { recursive: true });
const read = (p) => hexToBin(readFileSync(p, 'utf8').trim());
const cloneBytes = (x) => Uint8Array.from(x);
const cloneOutput = (o) => ({ ...o, lockingBytecode: cloneBytes(o.lockingBytecode) });
const cloneTx = (tx) => ({
  ...tx,
  inputs: tx.inputs.map((i) => ({ ...i, outpointTransactionHash: cloneBytes(i.outpointTransactionHash), unlockingBytecode: cloneBytes(i.unlockingBytecode) })),
  outputs: tx.outputs.map(cloneOutput),
});
const tx0 = decodeTransactionBch(read(`${PARENT}/spend_tx.hex`));
const so0 = decodeTransactionOutputs(read(`${PARENT}/spend_srcouts.hex`));
const parent0 = decodeTransactionBch(read(`${PARENT}/parent_tx.hex`));
if (typeof tx0 === 'string' || typeof so0 === 'string' || typeof parent0 === 'string') throw new Error('wire decode failed');
const accept = (state) => state.error === undefined && state.stack.length === 1 && state.stack[0]?.length === 1 && state.stack[0][0] === 1;
const txValid = (tx, so) => {
  if (tx.inputs.length !== so.length || ![1, 2].includes(tx.version)) return false;
  const seen = new Set();
  for (const i of tx.inputs) {
    const k = `${binToHex(i.outpointTransactionHash)}:${i.outpointIndex}`;
    if (seen.has(k) || (i.outpointTransactionHash.every((x) => x === 0) && i.outpointIndex === 0xffffffff)) return false;
    seen.add(k);
  }
  return tx.outputs.reduce((n, o) => n + BigInt(o.valueSatoshis), 0n) <= so.reduce((n, o) => n + BigInt(o.valueSatoshis), 0n);
};
const vm = createVirtualMachineBch2026(false);
const cases = [];
const add = (id, roles) => cases.push({ id, roles });

// Six adjacent executor swaps plus every ordered executor role replacement.
for (let i = 0; i < 6; i++) add(`swap-exec-${i}-${i + 1}`, { swap: [i, i + 1] });
for (let dst = 0; dst < 7; dst++) for (let src = 0; src < 7; src++) if (dst !== src) add(`replace-exec-${dst}-with-${src}`, { replace: [dst, src] });

// Boundary/root substitutions exercise the exact root edge and tail order.
add('swap-genesis-finalize', { swap: [7, 8] });
add('swap-finalize-fused', { swap: [8, 9] });
add('drop-genesis-append-fused', { sequence: [0, 1, 2, 3, 4, 5, 6, 8, 9, 9] });
add('drop-genesis-append-finalize', { sequence: [0, 1, 2, 3, 4, 5, 6, 8, 9, 8] });

const runCase = (spec) => {
  const parent = cloneTx(parent0);
  const sourceOutputs = parent.outputs.map(cloneOutput);
  const spending = cloneTx(tx0);
  const role = (index) => ({ lock: sourceOutputs[index].lockingBytecode, unlock: spending.inputs[index].unlockingBytecode });
  const put = (dst, src) => {
    sourceOutputs[dst].lockingBytecode = cloneBytes(role(src).lock);
    spending.inputs[dst].unlockingBytecode = cloneBytes(role(src).unlock);
  };
  if (spec.roles.swap) {
    const [a, b] = spec.roles.swap;
    const ra = role(a), rb = role(b);
    sourceOutputs[a].lockingBytecode = cloneBytes(rb.lock); sourceOutputs[b].lockingBytecode = cloneBytes(ra.lock);
    spending.inputs[a].unlockingBytecode = cloneBytes(rb.unlock); spending.inputs[b].unlockingBytecode = cloneBytes(ra.unlock);
  } else if (spec.roles.replace) {
    put(spec.roles.replace[0], spec.roles.replace[1]);
  } else {
    const sequence = spec.roles.sequence;
    const locks = sourceOutputs.map((o) => cloneBytes(o.lockingBytecode));
    const unlocks = spending.inputs.map((i) => cloneBytes(i.unlockingBytecode));
    for (let i = 0; i < sequence.length; i++) { sourceOutputs[i].lockingBytecode = cloneBytes(locks[sequence[i]]); spending.inputs[i].unlockingBytecode = cloneBytes(unlocks[sequence[i]]); }
  }
  parent.outputs = sourceOutputs;
  const parentHash = hash256(encodeTransaction(parent));
  spending.inputs = spending.inputs.map((i, index) => ({ ...i, outpointTransactionHash: cloneBytes(parentHash), outpointIndex: index }));
  const rows = spending.inputs.map((_, index) => {
    const state = vm.evaluate({ inputIndex: index, sourceOutputs, transaction: spending });
    return { index, accept: accept(state), error: state.error ?? '', opCost: state.metrics.operationCost };
  });
  const tokenValid = verifyTransactionTokens(spending, sourceOutputs, { maximumTokenCommitmentLength: 128 }) === true;
  return { id: spec.id, parentTxid: binToHex(parentHash), txValid: txValid(spending, sourceOutputs), tokenValid, rows, globalAccept: txValid(spending, sourceOutputs) && tokenValid && rows.every((x) => x.accept) };
};
const results = cases.map(runCase);
const out = {
  schema: 'verifier.cash/repair-role-battery/v1',
  candidate: PARENT,
  total: results.length,
  globalAccepts: results.filter((x) => x.globalAccept).map((x) => x.id),
  targetAccepts: results.filter((x) => x.rows.some((r) => r.accept)).map((x) => x.id),
  results,
};
writeFileSync(`${OUT}/role-battery.json`, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ total: out.total, globalAccepts: out.globalAccepts, anyTargetAccept: out.targetAccepts.length > 0, out: `${OUT}/role-battery.json` }, null, 2));
