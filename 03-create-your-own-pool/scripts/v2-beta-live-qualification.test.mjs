import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  loadV2BetaLiveQualificationInputsForTest,
  openV2BetaLiveQualificationRunJournalForTest,
  parseV2BetaLiveQualificationArguments,
  parseV2BetaLiveQualificationCliResultForTest,
  runV2BetaLiveQualification,
  sourceOutpointProvenanceSha256,
  V2_BETA_CAPACITY,
} from './v2-beta-live-qualification.mjs';
import { readPrivateUtf8, writePrivateFile } from './v2-beta-private-paths.mjs';

const H = (byte) => byte.repeat(64);
const address = 'bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4d6k7r';
const wallet = Object.freeze({ cashAddress: address, lockingBytecodeHex: `76a914${'11'.repeat(20)}88ac`, privateKeyHex: '12'.repeat(32), publicKeyHex: `02${'33'.repeat(32)}` });
const source = Object.freeze({ txid: H('a'), vout: 0, valueSats: '60000000' });
const le64 = (value) => Buffer.from(Uint8Array.from({ length: 8 }, (_, index) => Number((BigInt(value) >> BigInt(index * 8)) & 0xffn))).toString('hex');
const txidOf = (raw) => createHash('sha256').update(createHash('sha256').update(Buffer.from(raw, 'hex')).digest()).digest().reverse().toString('hex');
const fundingRaw = `0200000001${Buffer.from(source.txid, 'hex').reverse().toString('hex')}0000000000ffffffff02${le64('57001105')}19${wallet.lockingBytecodeHex}${le64(String(60000000 - 57001105 - 119))}19${wallet.lockingBytecodeHex}00000000`;
const fundingTxid = txidOf(fundingRaw);
const rpcCounts = Object.freeze({ getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0, sendrawtransaction: 1, testmempoolaccept: 1 });
const poolRpcCounts = Object.freeze({ getblockhash: 0, getrawtransaction: 2, gettxout: 1, scantxoutset: 0, sendrawtransaction: 2, testmempoolaccept: 2 });
const actionTimings = Object.freeze({ treeAndPreparation: 1, fundingRead: 1, witnessCalculation: 1, proofGeneration: 1, proofVerification: 1, proofTotal: 1, signingAndVm: 1, localVm: 1, admission: 1, commit: 1, total: 1 });
const fullActionTimings = Object.freeze({ ...actionTimings, stateRead: 1, witnessAssembly: 1 });
const cores = availableParallelism();
const vmMetrics = Object.freeze({
  arithmeticCost: '1', definedFunctions: '1', densityControlLength: '100',
  evaluatedInstructionCount: '1', hashDigestIterations: '1',
  maximumHashDigestIterations: '1000', maximumOperationCost: '1000',
  maximumSignatureCheckCount: '100', operationCost: '1',
  signatureCheckCount: '1', stackPushedBytes: '1',
});
const runtimeWork = () => ({
  schema: 'shieldkit-v2-beta-runtime-work-observation-v1',
  counts: {
    'linked-runtime-cache-load': 1, 'cold-runtime-build': 0,
    'full-runtime-verification': 0, 'compiler-child-spawn': 0,
    'instance-specialization': 0,
  },
  events: [{ type: 'linked-runtime-cache-load' }],
});
function actionTelemetry(kind, inputCount) {
  const pre = { schema: 'shieldkit-v2-beta-incremental-store-telemetry-v1', databaseBytes: 4096, walBytes: 8192, noteCount: 10, nullifierCount: 2, liveCount: 8 };
  const delta = kind === 'deposit'
    ? { databaseBytes: 0, walBytes: 4096, noteCount: 1, nullifierCount: 0, liveCount: 1 }
    : { databaseBytes: 0, walBytes: 4096, noteCount: 0, nullifierCount: 1, liveCount: -1 };
  const post = { schema: pre.schema, databaseBytes: pre.databaseBytes + delta.databaseBytes, walBytes: pre.walBytes + delta.walBytes, noteCount: pre.noteCount + delta.noteCount, nullifierCount: pre.nullifierCount + delta.nullifierCount, liveCount: pre.liveCount + delta.liveCount };
  return {
    schema: 'shieldkit-v2-beta-product-action-telemetry-v1',
    proof: { userTicks: 10, systemTicks: 5, totalTicks: 15, observedThreads: cores, activeCpuThreads: cores, ompThreads: cores, peakRssKiB: 1024, proofGenerationMs: 1, cpuTicksPerWallMillisecond: 15, containment: { backend: 'linux-systemd-cgroup-v2', memoryMaxBytes: '4294967296', memorySwapMaxBytes: '0', memoryPeakBytes: '1024', oomDelta: 0, oomKillDelta: 0, terminatedSuccessfully: true } },
    vm: { schema: 'shieldkit-v2-local-vm-telemetry-v1', allInputsAccepted: true, inputs: Array.from({ length: inputCount }, (_, index) => ({ index, accepted: true, metrics: { ...vmMetrics } })) },
    store: { pre, post, delta },
  };
}
const rawWithOneInput = (parentTxid, outputs) => `0200000001${Buffer.from(parentTxid, 'hex').reverse().toString('hex')}0000000000ffffffff${outputs.length.toString(16).padStart(2, '0')}${outputs.map((value) => `${le64(value)}19${wallet.lockingBytecodeHex}`).join('')}00000000`;
const bootstrapSourceRaw = rawWithOneInput(fundingTxid, Array.from({ length: 12 }, () => '546'));
const bootstrapSourceTxid = txidOf(bootstrapSourceRaw);
const genesisRaw = rawWithOneInput(bootstrapSourceTxid, ['546']);
const genesisTxid = txidOf(genesisRaw);
const sha256 = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

function action(kind, operationId, bad = undefined) {
  const txid = H(kind === 'deposit' ? 'd' : 'e');
  const actionKind = kind === 'deposit' ? 'deposit' : 'withdrawal';
  const telemetry = actionTelemetry(kind, 10);
  const work = runtimeWork();
  const nested = {
    schema: 'shieldkit-v2-beta-product-action-result-v1', status: 'accepted-zero-conf-beta-unqualified', kind: actionKind, operationId, transactionId: txid,
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
    cache: { runtimeManifestSha256: H('1'), runtimeMaterialSha256: H('2') },
    proof: { verified: true, resultSha256: H('3'), nativeBackend: 'rapidsnark', nativeProverSha256: H('4'), ompThreads: cores, observedThreads: cores, activeCpuThreads: cores, peakRssKiB: 1024, userCpuTicks: 10, systemCpuTicks: 5, totalCpuTicks: 15, cpuTicksPerWallMillisecond: 15, containment: telemetry.proof.containment },
    vm: { allInputsAccepted: true, inputCount: 10, acceptedInputCount: 10, evidenceHash: H('4') },
    telemetry,
    transaction: { bytes: 100, feeSats: '100', feeRateSatsPerByte: '1', changeVout: 1, changeValueSats: '1000' },
    readback: { rawTransactionSha256: H('5'), stateOutpoint: { txid, vout: 0 }, stateCommitmentSha256: H('6'), stateCategoryWire: H('7') },
    rpcObservation: { backend: 'layer1-bchn-chipnet', genesis: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b', methodCounts: rpcCounts }, timingsMs: fullActionTimings,
  };
  if (bad === 'proof') nested.proof.verified = false;
  if (bad === 'legacy') { nested.rpc = nested.rpcObservation; delete nested.rpcObservation; nested.runtime = { rebuilt: false }; }
  if (bad === 'runtime-work') { work.counts['cold-runtime-build'] = 1; work.events.push({ type: 'cold-runtime-build' }); }
  if (bad === 'vm-telemetry') nested.telemetry.vm.inputs.pop();
  return { schema: 'shieldkit-v2-beta-product-command-result-v1', command: kind, status: nested.status, operationId, transactionId: txid, claims: nested.claims, action: nested, telemetry: nested.telemetry, runtimeWork: work, timingsMs: { sessionOpen: 1, action: 1, commandTotal: 2 } };
}
function pool(bad = undefined) {
  const result = {
    schema: 'shieldkit-v2-beta-product-pool-create-result-v1', command: 'pool-create', profileId: 'v2-beta-chipnet-direct', operationId: 'pool-create-test', status: 'accepted-zero-conf-beta-unqualified', capacity: V2_BETA_CAPACITY, instanceId: H('8'), sourceTransactionId: bootstrapSourceTxid, genesisTransactionId: genesisTxid, zeroConfEvidenceSha256: H('a'), actionFundingOutputs: 10,
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false }, rpcBackend: 'layer1-bchn-chipnet', rpcObservation: { backend: 'layer1-bchn-chipnet', genesis: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b', methodCounts: poolRpcCounts },
    runtimeManifestSha256: H('b'), runtimeMaterialSha256: H('c'), runtimeLinkedDuringCommand: true, runtimeWork: { schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: { 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 1 }, events: [{ type: 'instance-specialization' }, { type: 'linked-runtime-cache-load' }] }, actionFundingSetSha256: H('d'),
    acceptance: { accepted: true, status: 'accepted-zero-conf', evidence: { status: 'accepted-zero-conf-beta-unqualified', claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false } } },
    transactions: { source: { transactionId: bootstrapSourceTxid, serializedBytes: bootstrapSourceRaw.length / 2, rawTransactionSha256: sha256(bootstrapSourceRaw) }, genesis: { transactionId: genesisTxid, serializedBytes: genesisRaw.length / 2, feeSats: '200', feeRateSatsPerByte: '1', bch2026StandardVmAccepted: true, inputMetrics: [] } },
    timingsMs: { funding: 1, genesis: 1, exactReadback: 1, atomicCommit: 1, actionStoreBootstrap: 1, commandTotal: 1 },
  };
  if (bad === 'cache-hit') {
    result.runtimeLinkedDuringCommand = false;
    result.runtimeWork.counts['instance-specialization'] = 0;
    result.runtimeWork.events = [{ type: 'linked-runtime-cache-load' }];
  }
  if (bad === 'legacy') { result.rpc = result.rpcObservation; delete result.rpcObservation; result.cache = { runtimeManifestSha256: result.runtimeManifestSha256, runtimeMaterialSha256: result.runtimeMaterialSha256 }; delete result.runtimeManifestSha256; delete result.runtimeMaterialSha256; }
  return result;
}
function memoryJournal(initial = null) {
  let record = initial; const transitions = [];
  return {
    journal: { load: () => record, async prepare(value) { assert.equal(record, null); record = value; transitions.push(value.state); return record; }, async update(value) { record = value; transitions.push(value.state); return record; }, close() {} },
    transitions, record: () => record,
  };
}
function fixture({ initialRecord = null, reject = false, badAction = undefined, badPool = undefined, wrongMempoolTxid = false, readbackFails = false, vmReject = false, sourceRaw = bootstrapSourceRaw } = {}) {
  const calls = { commands: [], rpc: [] }; const holder = memoryJournal(initialRecord);
  const rpc = {
    async scanAddress() { calls.rpc.push('scanAddress'); return [source]; },
    async getrawtransaction(txid) { calls.rpc.push('getrawtransaction'); if (readbackFails) throw new Error('temporary BCHN readback failure'); if (txid === fundingTxid) return fundingRaw; if (txid === bootstrapSourceTxid) return sourceRaw; if (txid === genesisTxid) return genesisRaw; throw new Error('unexpected txid'); },
    async gettxout() { calls.rpc.push('gettxout'); return { valueSatoshis: '57001105', scriptPubKey: { hex: wallet.lockingBytecodeHex } }; },
    async testmempoolaccept() { calls.rpc.push('testmempoolaccept'); return [{ allowed: !reject, txid: wrongMempoolTxid ? H('f') : fundingTxid }]; },
    async sendrawtransaction() { calls.rpc.push('sendrawtransaction'); return fundingTxid; },
  };
  const resultFor = (tokens) => {
    if (tokens[0] === 'pool') return pool(badPool);
    return action(tokens[0], tokens[tokens.indexOf('--operation-id') + 1], badAction);
  };
  return {
    calls, holder,
    deps: {
      rpc,
      now: (() => { let value = 0; return () => ++value; })(),
      async openRunJournal() { return holder.journal; },
      async validateInstall() { return { dataDirectory: '/private/data/shieldkit/v2-beta-product', receiptSha256: H('f'), releaseId: 'beta-r1', releaseManifestSha256: H('e') }; },
      async runCommand(request) { calls.commands.push(request.literal); return { code: 0, stdout: JSON.stringify({ ok: true, confirmed: false, mined: false, productionQualified: false, result: resultFor(request.literal.slice(1)) }) }; },
      async writeEvidence(directory, evidence) { calls.written = evidence; return `${directory}/evidence.json`; },
    },
  };
}
const inputs = Object.freeze({ dataHome: '/private/data', evidenceDirectory: '/private/evidence', fundingWallet: '/private/funding-wallet.json', fundingUtxo: Object.freeze({ txid: fundingTxid, vout: 0 }), withdrawalAddress: address, wallet: Object.freeze({}) });

test('public live-runner argv parses to the plain object required by input validation', () => {
  const parsed = parseV2BetaLiveQualificationArguments([
    '--execute-live',
    '--data-home', '/private/data',
    '--evidence-dir', '/private/evidence',
    '--funding-wallet', '/private/funding-wallet.json',
    '--funding-utxo', `${fundingTxid}:0`,
    '--withdraw-to', address,
  ]);
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.deepEqual(parsed, {
    dataHome: '/private/data',
    evidenceDirectory: '/private/evidence',
    fundingWallet: '/private/funding-wallet.json',
    fundingUtxo: `${fundingTxid}:0`,
    withdrawalAddress: address,
  });
  assert.throws(
    () => parseV2BetaLiveQualificationArguments([
      '--execute-live',
      '--data-home', '/private/data',
      '--data-home', '/other/data',
      '--evidence-dir', '/private/evidence',
      '--funding-wallet', '/private/funding-wallet.json',
      '--funding-utxo', `${fundingTxid}:0`,
      '--withdraw-to', address,
    ]),
    /usage: node v2-beta-live-qualification\.mjs/u,
  );
});

test('production CLI inputs remain valid across the validation-to-run boundary', async (t) => {
  const root = mkdtempSync(path.join(process.cwd(), '.shieldkit-live-cli-inputs-'));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dataHome = path.join(root, 'data-home');
  const evidenceDirectory = path.join(root, 'evidence');
  const fundingWallet = path.join(root, 'funding-wallet.json');
  mkdirSync(dataHome, { mode: 0o700 });
  mkdirSync(evidenceDirectory, { mode: 0o700 });
  writeFileSync(fundingWallet, '{}', { mode: 0o600 });
  const validated = await loadV2BetaLiveQualificationInputsForTest(
    parseV2BetaLiveQualificationArguments([
      '--execute-live',
      '--data-home', dataHome,
      '--evidence-dir', evidenceDirectory,
      '--funding-wallet', fundingWallet,
      '--funding-utxo', `${fundingTxid}:0`,
      '--withdraw-to', address,
    ]),
  );
  const subject = fixture();
  const result = await runV2BetaLiveQualification(validated, subject.deps);
  assert.equal(result.evidence.capacity, V2_BETA_CAPACITY);
  assert.equal(result.evidence.deposits.length, 5);
  assert.equal(result.evidence.withdrawals.length, 5);
  assert.equal(subject.calls.commands.length, 11);
});

test('child CLI failures preserve their public error code and message', () => {
  assert.throws(
    () => parseV2BetaLiveQualificationCliResultForTest({
      code: 1,
      stdout: JSON.stringify({ ok: false, error: { code: 'BETA_POOL_RUNTIME_REJECTED', message: 'runtime observation failed' } }),
      stderr: 'must not be projected',
    }, 'shieldkit pool create'),
    (error) => error?.code === 'LIVE_QUALIFICATION_CLI_FAILED'
      && error.message === 'shieldkit pool create failed with BETA_POOL_RUNTIME_REJECTED: runtime observation failed',
  );
});

test('the real private qualification journal opens from a missing first-run file', async (t) => {
  const dataDirectory = mkdtempSync(path.join(process.cwd(), '.shieldkit-live-journal-'));
  chmodSync(dataDirectory, 0o700);
  t.after(() => rmSync(dataDirectory, { recursive: true, force: true }));
  const journal = await openV2BetaLiveQualificationRunJournalForTest({ dataDirectory });
  assert.equal(journal.load(), null);
  journal.close();
});

test('private wallet and journal helper rejects symlinks and unsafe ancestors', async () => {
  const root = mkdtempSync(path.join(process.cwd(), '.shieldkit-private-path-')); chmodSync(root, 0o700);
  const walletFile = path.join(root, 'wallet.json'); const link = path.join(root, 'wallet-link.json');
  try {
    writeFileSync(walletFile, '{"safe":true}', { mode: 0o600 }); symlinkSync(walletFile, link);
    await assert.rejects(() => readPrivateUtf8(link, 'symlinked wallet'));
    await assert.rejects(() => writePrivateFile(link, Buffer.from('{}'), 'symlinked journal'));
    chmodSync(root, 0o777);
    await assert.rejects(() => readPrivateUtf8(walletFile, 'unsafe wallet ancestor'));
  } finally { chmodSync(root, 0o700); rmSync(root, { recursive: true, force: true }); }
});

test('records a strict public-CLI five-by-five semantic run without hidden installation', async () => {
  const subject = fixture(); const result = await runV2BetaLiveQualification(inputs, subject.deps);
  assert.equal(subject.calls.commands.some((entry) => entry[0] === 'node'), false);
  assert.equal(subject.calls.commands.filter((entry) => entry[1] === 'deposit').length, 5);
  assert.equal(subject.calls.commands.filter((entry) => entry[1] === 'withdraw').length, 5);
  assert.equal(subject.calls.commands.filter((entry) => entry[1] === 'pool' && entry[2] === 'create').length, 1);
  assert.deepEqual(subject.calls.commands.at(0), ['shieldkit', 'pool', 'create', '--data-home', '/private/data', '--funding-wallet', '/private/funding-wallet.json', '--funding-utxo', `${fundingTxid}:0`, '--json']);
  assert.equal(subject.calls.rpc.includes('scanAddress'), false);
  assert.equal(subject.calls.rpc.includes('testmempoolaccept'), false);
  assert.equal(result.evidence.deposits.length, 5); assert.equal(result.evidence.withdrawals.length, 5);
  assert.equal(result.evidence.scope, 'semantic-five-by-five-only-not-performance-qualification');
  assert.deepEqual(result.evidence.install, { receiptSha256: H('f'), releaseId: 'beta-r1', releaseManifestSha256: H('e') });
  assert.equal(JSON.stringify(result.evidence).includes('/private/data/shieldkit/v2-beta-product'), false);
  assert.equal(JSON.stringify(result.evidence).includes('/private/funding-wallet.json'), false);
  assert.equal(JSON.stringify(result.evidence).includes(`${fundingTxid}:0`), false);
  assert.equal(JSON.stringify(result.evidence).includes(fundingRaw), false);
  assert.deepEqual(subject.holder.transitions.slice(0, 2), ['pool-create-started', 'pool-created']);
});

test('rejects malformed action proof evidence instead of projecting it as a successful story', async () => {
  const subject = fixture({ badAction: 'proof' });
  await assert.rejects(() => runV2BetaLiveQualification(inputs, subject.deps), { code: 'LIVE_QUALIFICATION_RESULT_REJECTED' });
});

test('rejects a warm action rebuild or partial per-input VM telemetry', async () => {
  for (const badAction of ['runtime-work', 'vm-telemetry']) {
    const subject = fixture({ badAction });
    await assert.rejects(
      () => runV2BetaLiveQualification(inputs, subject.deps),
      { code: 'LIVE_QUALIFICATION_RESULT_REJECTED' },
    );
  }
});

test('accepts literal public CLI envelopes and rejects the former synthetic rpc/cache wrapper shape', async () => {
  const accepted = fixture(); await runV2BetaLiveQualification(inputs, accepted.deps);
  const legacyAction = fixture({ badAction: 'legacy' });
  await assert.rejects(() => runV2BetaLiveQualification(inputs, legacyAction.deps), { code: 'LIVE_QUALIFICATION_RESULT_REJECTED' });
  const legacyPool = fixture({ badPool: 'legacy' });
  await assert.rejects(() => runV2BetaLiveQualification(inputs, legacyPool.deps), { code: 'LIVE_QUALIFICATION_POOL_CREATE_REJECTED' });
});

test('rejects a pool package whose bootstrap source does not spend the requested funding outpoint', async () => {
  const unrelatedSourceRaw = rawWithOneInput(H('b'), Array.from({ length: 12 }, () => '546'));
  const subject = fixture({ sourceRaw: unrelatedSourceRaw });
  await assert.rejects(() => runV2BetaLiveQualification(inputs, subject.deps), { code: 'LIVE_QUALIFICATION_POOL_CREATE_REJECTED' });
});

test('does not replay an interrupted pool create', async () => {
  const initialRecord = Object.freeze({ schema: 'shieldkit-v2-beta-live-qualification-run-v1', state: 'pool-create-started', installReceiptSha256: H('f'), sourceOutpointProvenanceSha256: H('1'), poolCreateCommandDurationMs: null, pool: null, actions: [] });
  const subject = fixture({ initialRecord }); await assert.rejects(() => runV2BetaLiveQualification(inputs, subject.deps), { code: 'LIVE_QUALIFICATION_JOURNAL_REJECTED' });
  assert.equal(subject.calls.commands.length, 0);
});

test('an exact interrupted semantic pool create resumes through the inner idempotent journal', async () => {
  const initialRecord = Object.freeze({
    schema: 'shieldkit-v2-beta-live-qualification-run-v1',
    state: 'pool-create-started',
    installReceiptSha256: H('f'),
    sourceOutpointProvenanceSha256: sourceOutpointProvenanceSha256(inputs.fundingUtxo),
    poolCreateCommandDurationMs: null,
    pool: null,
    actions: [],
  });
  const subject = fixture({ initialRecord, badPool: 'cache-hit' });
  const result = await runV2BetaLiveQualification(inputs, subject.deps);
  assert.equal(subject.calls.commands.filter((entry) => entry[1] === 'pool' && entry[2] === 'create').length, 1);
  assert.equal(result.evidence.pool.runtime.linkedDuringCommand, false);
  assert.equal(result.evidence.deposits.length, 5);
  assert.equal(result.evidence.withdrawals.length, 5);
});
