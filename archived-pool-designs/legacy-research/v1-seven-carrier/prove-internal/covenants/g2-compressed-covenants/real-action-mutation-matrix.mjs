// Full-input Libauth BCH-2026 mutation conformance over the three public real
// complete-action fixtures. This is intentionally a local VM test: it does
// not claim BCHN relay, miner inclusion, or a proof corpus beyond the exact
// fixture proofs embedded in these transactions.
import { createHash } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createVirtualMachineBch2026 } from '@bitauth/libauth';
import { actionFixturePaths, loadRealDepositFixture } from './real-deposit-leanbch-fixture.mjs';

export const REAL_ACTION_MUTATION_SCHEMA = 'shield.cash/real-action-mutation-matrix/v1';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const accepts = (result) => result.error === undefined && result.stack.length === 1 && result.stack[0].some((byte) => byte !== 0);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const clone = (value) => structuredClone(value);
const packetGroups = Object.freeze([
  ['magic', 0], ['version', 4], ['network', 5], ['kind', 6], ['reserved', 7],
  ['pre-profile', 8], ['pre-instance', 40], ['pre-note-root', 72], ['pre-nullifier-root', 104], ['pre-next-leaf', 136], ['pre-sequence', 140], ['pre-live-count', 148], ['pre-reserve', 152], ['pre-max-reserve', 160], ['pre-state-commitment', 168],
  ['post-profile', 200], ['post-instance', 232], ['post-note-root', 264], ['post-nullifier-root', 296], ['post-next-leaf', 328], ['post-sequence', 332], ['post-live-count', 340], ['post-reserve', 344], ['post-max-reserve', 352], ['post-state-commitment', 360],
  ['input-commitment', 392], ['input-nullifier', 424], ['output-commitment', 456], ['output-record', 488], ['boundary-amount', 680], ['withdrawal-script-hash', 688], ['transaction-context', 720],
]);

function evaluate(transaction, sourceOutputs, indexes) {
  const vm = createVirtualMachineBch2026(true);
  return indexes.map((inputIndex) => {
    const result = vm.evaluate({ inputIndex, sourceOutputs, transaction });
    return { inputIndex, accepted: accepts(result), error: result.error ?? null, operationCost: result.metrics?.operationCost ?? null };
  });
}

function allIndexes(transaction) { return transaction.inputs.map((_, index) => index); }
function roleMutation(rows, name, transaction, sourceOutputs, mutate, indexes = allIndexes(transaction)) {
  const transactionCopy = clone(transaction); const sourceCopy = clone(sourceOutputs); mutate(transactionCopy, sourceCopy);
  const results = evaluate(transactionCopy, sourceCopy, indexes); const rejected = results.filter((row) => !row.accepted).map((row) => row.inputIndex);
  rows.push({ name, evaluatedInputs: results.map((row) => row.inputIndex), rejectedInputs: rejected, accepted: rejected.length === 0, errors: results.filter((row) => row.error !== null).map((row) => ({ inputIndex: row.inputIndex, error: row.error })) });
}

function fixtureMutations(loaded) {
  const { transaction, sourceOutputs } = loaded; const rows = [];
  // Every complete input role has a direct unlock mutation, including the seven
  // real PF7 proof carriers, binding/state, and the fee signature.
  for (let index = 0; index < 10; index += 1) roleMutation(rows, `unlock-role-${index}`, transaction, sourceOutputs, (tx) => {
    const unlock = tx.inputs[index].unlockingBytecode;
    // Input 7's recovery-record middle bytes are intentionally not interpreted
    // by its binding script. Mutate its context commitment instead; the other
    // roles use a proof/helper/signature byte inside their own unlock.
    const offset = index === 7 ? 3 + 720 : index === 8 ? Math.min(3, unlock.length - 1) : index === 9 ? Math.min(10, unlock.length - 1) : Math.floor(unlock.length / 2);
    unlock[offset] ^= 1;
  }, index === 7 ? allIndexes(transaction) : [index]);
  // Each source role is replaced with a rejecting source script. This exercises
  // exact source-role selection without fabricating an accepting alternative.
  for (let index = 0; index < 10; index += 1) roleMutation(rows, `source-lock-role-${index}`, transaction, sourceOutputs, (_tx, sources) => { sources[index].lockingBytecode = Uint8Array.of(0); }, [index]);
  // Every actual input role's serialized outpoint field is changed; all VM
  // inputs are evaluated because proof/context/state binding is transitive.
  for (let index = 0; index < 10; index += 1) roleMutation(rows, `input-outpoint-role-${index}`, transaction, sourceOutputs, (tx) => { tx.inputs[index].outpointTransactionHash[0] ^= 1; });
  for (const [group, offset] of packetGroups) roleMutation(rows, `packet-${group}`, transaction, sourceOutputs, (tx) => { tx.inputs[7].unlockingBytecode[3 + offset] ^= 1; });
  for (let index = 0; index < transaction.outputs.length; index += 1) {
    roleMutation(rows, `successor-output-value-${index}`, transaction, sourceOutputs, (tx) => { tx.outputs[index].valueSatoshis += 1n; });
    roleMutation(rows, `successor-output-lock-${index}`, transaction, sourceOutputs, (tx) => { tx.outputs[index].lockingBytecode = Uint8Array.of(0); });
  }
  roleMutation(rows, 'transaction-version', transaction, sourceOutputs, (tx) => { tx.version = 1; });
  roleMutation(rows, 'transaction-locktime', transaction, sourceOutputs, (tx) => { tx.locktime = 1; });
  roleMutation(rows, 'state-token-category', transaction, sourceOutputs, (_tx, sources) => { sources[8].token.category[0] ^= 1; });
  roleMutation(rows, 'state-token-commitment', transaction, sourceOutputs, (_tx, sources) => { sources[8].token.nft.commitment[40] ^= 1; });
  roleMutation(rows, 'state-token-capability', transaction, sourceOutputs, (_tx, sources) => { sources[8].token.nft.capability = 'minting'; });
  roleMutation(rows, 'fee-source-value', transaction, sourceOutputs, (_tx, sources) => { sources[9].valueSatoshis += 1n; });
  roleMutation(rows, 'fee-change-value', transaction, sourceOutputs, (tx) => { tx.outputs.at(-1).valueSatoshis += 1n; });
  roleMutation(rows, 'input-role-swap-0-1', transaction, sourceOutputs, (tx, sources) => { [tx.inputs[0], tx.inputs[1]] = [tx.inputs[1], tx.inputs[0]]; [sources[0], sources[1]] = [sources[1], sources[0]]; });
  return rows;
}

export async function runRealActionMutationMatrix({ outputDirectory = undefined } = {}) {
  const started = process.hrtime.bigint(); const actions = [];
  for (const fixturePath of actionFixturePaths) {
    const loaded = await loadRealDepositFixture(fixturePath); const baseline = evaluate(loaded.transaction, loaded.sourceOutputs, allIndexes(loaded.transaction));
    assert(baseline.length === 10 && baseline.every((row) => row.accepted), `baseline ${fixturePath.pathname} did not accept all ten roles`);
    const mutations = fixtureMutations(loaded); const falseAccepts = mutations.filter((row) => row.accepted); const unexecuted = mutations.filter((row) => row.evaluatedInputs.length === 0);
    assert(falseAccepts.length === 0, `${fixturePath.pathname} mutation false accepts: ${falseAccepts.map((row) => row.name).join(', ')}`); assert(unexecuted.length === 0, 'unexecuted mutation');
    actions.push({
      action: fixturePath.pathname.split('/').at(-1).split('-')[0], transactionId: loaded.fixture.provenance.transactionId, fixtureSha256: sha256(loaded.fixtureBytes), sourceArtifactSha256: loaded.fixture.provenance.sourceArtifactSha256,
      transactionSha256: loaded.fixture.transaction.sha256, transactionBytes: loaded.transactionBytes.length, sourceOutputsSha256: sha256(loaded.sourceOutputsWire), baseline,
      exactFee: { satoshis: (loaded.sourceOutputs.reduce((sum, output) => sum + output.valueSatoshis, 0n) - loaded.transaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n)).toString(), wireBytes: loaded.transactionBytes.length, exactOneSatPerByte: loaded.sourceOutputs.reduce((sum, output) => sum + output.valueSatoshis, 0n) - loaded.transaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n) === BigInt(loaded.transactionBytes.length) },
      mutations: { total: mutations.length, falseAccepts: falseAccepts.length, unexecuted: unexecuted.length, rows: mutations },
    });
  }
  const result = {
    schema: REAL_ACTION_MUTATION_SCHEMA,
    qualification: 'Local Libauth BCH-2026 standard-VM execution of three public real complete Chipnet transactions. No BCHN relay/miner/reorg/independent-VM claim.',
    profile: actions[0].fixtureSha256 === undefined ? undefined : 'fixture-bound', allTenInputsExecuted: true,
    actions, totals: { actions: actions.length, baselineVmExecutions: actions.reduce((sum, action) => sum + action.baseline.length, 0), mutationFamilies: actions.reduce((sum, action) => sum + action.mutations.total, 0), falseAccepts: actions.reduce((sum, action) => sum + action.mutations.falseAccepts, 0), unexecuted: actions.reduce((sum, action) => sum + action.mutations.unexecuted, 0) },
    limitations: ['Mutations are executed only in Libauth BCH-2026 standard VM.', 'The three fixtures contain real fixed proofs and complete transactions, but the matrix does not generate 256 distinct Groth16 proofs or assert BCHN peer relay.'], elapsedMs: Number(process.hrtime.bigint() - started) / 1e6,
  };
  if (outputDirectory !== undefined) {
    const target = path.resolve(outputDirectory); const staging = `${target}.staging-${process.pid}`; await mkdir(staging);
    try { await writeFile(path.join(staging, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' }); await rename(staging, target); } catch (error) { await rm(staging, { recursive: true, force: true }); throw error; }
  }
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const outputDirectory = process.argv[2];
  if (outputDirectory === undefined) { console.error('usage: node real-action-mutation-matrix.mjs OUTPUT_DIRECTORY'); process.exitCode = 2; }
  else runRealActionMutationMatrix({ outputDirectory }).then((result) => console.log(JSON.stringify({ totals: result.totals, elapsedMs: result.elapsedMs }))).catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
}
