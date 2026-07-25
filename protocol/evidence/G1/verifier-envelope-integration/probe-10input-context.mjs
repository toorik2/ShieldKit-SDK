/**
 * Negative integration probe: execute the seven real PF7 verifier redeems in a
 * ten-input transaction context. The last three records are deliberately only
 * structural P2PKH UTXOs; they are not labelled binding/state/fee and are never
 * evaluated. This proves whether the existing verifier locks can coexist with
 * an expanded envelope, without fabricating an action covenant.
 *
 * Usage (from a verifier.cash checkout with harness/node_modules installed):
 *   harness/node_modules/.bin/tsx <this-file> <verifier-root> <pf7-build-dir>
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const [verifierRoot, runDir] = process.argv.slice(2);
if (!verifierRoot || !runDir) throw new Error('usage: probe-10input-context.mjs <verifier-root> <pf7-build-dir>');

const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const raw = JSON.parse(readFileSync(resolve(runDir, 'inputs_dump.json'), 'utf8'));
if (raw.length !== 7) throw new Error(`expected a PF7 run, got ${raw.length} inputs`);

const { createRealVm, evaluatePair } = await import(pathToFileURL(resolve(verifierRoot, 'harness/src/harness/vm.ts')).href);
const requireFromVerifier = createRequire(resolve(verifierRoot, 'package.json'));
const { encodeTransaction } = await import(pathToFileURL(requireFromVerifier.resolve('@bitauth/libauth')).href);

const real = raw.map((row) => ({
  lockingBytecode: hex(row.lock),
  unlockingBytecode: hex(row.unlock),
  valueSatoshis: 1000n,
  sequenceNumber: 0xffffffff,
}));
// Valid standard P2PKH locking bytecode. No unlocking bytecode or semantics is
// supplied because external protocol roles are absent from this verifier build.
const structuralP2pkh = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]);
const expanded = [...real, ...Array.from({ length: 3 }, () => ({
  lockingBytecode: structuralP2pkh,
  unlockingBytecode: new Uint8Array(),
  valueSatoshis: 1000n,
  sequenceNumber: 0xffffffff,
}))];
const vm = createRealVm();
const outcomes = real.map((input, index) => {
  const out = evaluatePair(vm, input.lockingBytecode, input.unlockingBytecode, undefined, {
    index,
    inputs: expanded,
    outputValueSatoshis: 1000n,
  });
  return { index, role: raw[index].name, accepted: out.accepted, error: out.error, operationCost: out.operationCost };
});
const structuralTx = {
  version: 2,
  inputs: expanded.map((input, index) => ({
    outpointTransactionHash: new Uint8Array(32).fill(index),
    outpointIndex: index,
    sequenceNumber: input.sequenceNumber,
    unlockingBytecode: input.unlockingBytecode,
  })),
  outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
  locktime: 0,
};
const encoded = encodeTransaction(structuralTx);
console.log(JSON.stringify({
  probe: 'PF7 real-verifier locks in a 10-input structural context',
  sourceRun: resolve(runDir),
  realVerifierInputs: raw.length,
  expandedInputCount: expanded.length,
  addedInputs: [{ kind: 'standard-P2PKH-structural-only', count: 3, lockingBytesEach: structuralP2pkh.length, unlockingBytesEach: 0 }],
  structuralWireBytes: encoded.length,
  verifierOutcomes: outcomes,
  verifierClusterAccepted: outcomes.every((out) => out.accepted),
  rejectingRoles: outcomes.filter((out) => !out.accepted).map((out) => out.role),
  limitation: 'The three added inputs are not a binding, state, or fee covenant. This negative probe establishes only that a 10-input structural context cannot pass every existing PF7 verifier redeem; it does not implement or measure an action transaction.',
}, null, 2));
