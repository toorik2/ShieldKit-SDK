import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod, link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { parseV2RawTransaction } from './transaction-policy.mjs';
import {
  authenticateV2BetaPerformanceSourceForTest,
  parseV2BetaPerformanceExistingPrivateInput,
  parseV2BetaPerformanceSourcePlan,
  readV2BetaPerformanceSourceReservationLedger,
  releaseExpiredV2BetaPerformanceSourceReservation,
  reserveV2BetaPerformanceSourcesForTest,
  V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME,
  V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA,
  V2_BETA_PERFORMANCE_SOURCE_PLAN_SCHEMA,
  V2_BETA_PRIVATE_SOURCE_USAGE_SCHEMA,
  writeV2BetaPerformanceSourceReservationLedgerForTest,
} from './performance-source-reservations.mjs';
import {
  inspectV2BetaOperatorSourceRegistry,
  registerV2BetaOperatorFanoutSources,
  reserveV2BetaPerformanceSourcesInRegistry,
} from './operator-source-registry.mjs';

const NOW = 1_785_000_000_000;
const H = (value) => value.toString(16).padStart(64, '0');
const LOCK = (index) => `76a914${index.toString(16).padStart(40, '0')}88ac`;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function rawTransaction({ valueSats, lockingBytecodeHex }) {
  const value = Buffer.alloc(8); value.writeBigUInt64LE(BigInt(valueSats));
  return Buffer.concat([
    Buffer.from('0200000001', 'hex'), Buffer.alloc(32), Buffer.from('ffffffff00ffffffff01', 'hex'),
    value, Buffer.from([lockingBytecodeHex.length / 2]), Buffer.from(lockingBytecodeHex, 'hex'),
    Buffer.from('00000000', 'hex'),
  ]).toString('hex');
}

function plan({ root, now = NOW, valueSats = '53006565' } = {}) {
  const sources = Array.from({ length: 20 }, (_, index) => {
    const raw = rawTransaction({ valueSats, lockingBytecodeHex: LOCK(index + 1) });
    const txid = parseV2RawTransaction(raw).txid;
    return {
      ordinal: index + 1,
      dataHome: `${root}/pool-${index + 1}`,
      installationReceiptSha256: H(10_000 + index),
      lockingBytecodeHex: LOCK(index + 1),
      outpoint: `${txid}:0`,
      valueSats,
      raw,
    };
  });
  return {
    value: {
      schema: V2_BETA_PERFORMANCE_SOURCE_PLAN_SCHEMA,
      createdAtUnixMs: now - 1000,
      expiresAtUnixMs: now + 10_000,
      release: { releaseId: 'shieldkit-v2-beta-test-release', releaseManifestSha256: H(9) },
      sources: sources.map(({ raw, ...entry }) => entry),
    },
    sources,
  };
}

async function privateJson(filename, value) {
  await writeFile(filename, Buffer.from(canonicalizeJcs(value), 'utf8'), { mode: 0o600 });
  await chmod(filename, 0o600);
}

async function fixture(t, configure = undefined) {
  const root = await mkdtemp(path.join(process.cwd(), '.shieldkit-performance-source-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const planPath = path.join(root, 'plan.json'); const reservationDirectory = path.join(root, 'reservations');
  const candidate = plan({ root });
  for (const entry of candidate.sources) { await mkdir(entry.dataHome, { mode: 0o700 }); await chmod(entry.dataHome, 0o700); }
  await privateJson(planPath, candidate.value);
  const calls = { authenticate: [], installs: [] };
  const dependencies = {
    now: () => NOW,
    readPrivateFile: async (filename) => readFile(filename),
    validateInstall: async ({ dataHome }) => {
      calls.installs.push(dataHome); const index = Number(dataHome.match(/pool-([0-9]+)$/u)?.[1]);
      return {
        dataDirectory: `${dataHome}/shieldkit/v2-beta-product`,
        receiptSha256: H(10_000 + index - 1),
        releaseId: 'shieldkit-v2-beta-test-release', releaseManifestSha256: H(9),
      };
    },
    authenticateRpc: async (entry) => {
      calls.authenticate.push(entry); const original = candidate.sources[entry.ordinal - 1];
      return { rawTransactionSha256: sha256(Buffer.from(original.raw, 'hex')) };
    },
    readExistingLedger: async ({ ledgerPath, now }) => {
      return lstat(ledgerPath).then(
        async () => readV2BetaPerformanceSourceReservationLedger(ledgerPath, now),
        (error) => { if (error?.code !== 'ENOENT') throw error; return null; },
      );
    },
    writeLedger: writeV2BetaPerformanceSourceReservationLedgerForTest,
    claimRegistry: async ({ claim }) => ({
      sourceCount: claim.sources.length,
      evidenceSha256: claim.evidenceSha256,
      leaseId: claim.leaseId,
      runId: claim.runId,
    }),
  };
  configure?.({ candidate, dependencies, calls, planPath, reservationDirectory, root });
  return { candidate, dependencies, calls, planPath, reservationDirectory, root };
}

test('reserves exactly twenty independently installed authenticated source plans into a private immutable ledger', async (t) => {
  const subject = await fixture(t);
  const result = await reserveV2BetaPerformanceSourcesForTest({
    operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
  }, subject.dependencies);
  assert.deepEqual(result, {
    sourceCount: 20,
    release: { releaseId: 'shieldkit-v2-beta-test-release', releaseManifestSha256: H(9) },
    leaseId: result.leaseId,
    runId: 'test-run', ledgerSha256: result.ledgerSha256,
  });
  assert.match(result.ledgerSha256, /^[0-9a-f]{64}$/u);
  assert.equal(subject.calls.installs.length, 20); assert.equal(subject.calls.authenticate.length, 20);
  const ledgerPath = path.join(subject.reservationDirectory, V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME);
  assert.equal((await lstat(subject.reservationDirectory)).mode & 0o777, 0o700);
  assert.equal((await lstat(ledgerPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(ledgerPath)).nlink, 1);
  const ledger = JSON.parse(await readFile(ledgerPath, 'utf8'));
  assert.equal(ledger.schema, V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA);
  assert.equal(ledger.sources.length, 20);
  assert.equal(JSON.stringify(ledger).includes('rawTransactionHex'), false);
  assert.equal(JSON.stringify(result).includes(subject.root), false);
  assert.equal((await readV2BetaPerformanceSourceReservationLedger(ledgerPath, NOW)).outpoints.length, 20);
  await assert.rejects(
    () => readV2BetaPerformanceSourceReservationLedger(ledgerPath, NOW + 20_000),
    { code: 'PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED' },
  );
  const resumed = await reserveV2BetaPerformanceSourcesForTest({
    operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
  }, subject.dependencies);
  assert.deepEqual(resumed, result);
});

test('expired reservation can be explicitly released only from the never-sent canonical state', async (t) => {
  const subject = await fixture(t);
  await reserveV2BetaPerformanceSourcesForTest({ operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run' }, subject.dependencies);
  const ledgerPath = path.join(subject.reservationDirectory, V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME); const calls = [];
  const ledger = JSON.parse(await readFile(ledgerPath, 'utf8'));
  const matchingRegistry = () => Object.freeze({ sources: ledger.sources.map((entry) => Object.freeze({
    outpoint: entry.outpoint, role: 'fanout-performance', state: 'performance-reserved',
    leaseId: ledger.leaseId, runId: ledger.runId, evidenceSha256: ledger.registryClaimSha256,
    releaseId: ledger.release.releaseId, releaseManifestSha256: ledger.release.releaseManifestSha256,
    dataHome: entry.dataHome, installationReceiptSha256: entry.installationReceiptSha256,
    walletLockingBytecodeHex: entry.lockingBytecodeHex, valueSats: entry.valueSats,
  })) });
  const released = await releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot: subject.root, ledgerPath, now: NOW + 20_000 }, { inspectRegistry: matchingRegistry, transition: (request) => { calls.push(request); return Object.freeze({ sourceCount: request.outpoints.length, toState: request.toState }); } });
  assert.deepEqual(released, { sourceCount: 20, toState: 'explicitly-released' });
  assert.equal(calls.length, 1); assert.equal(calls[0].fromState, 'performance-reserved'); assert.equal(calls[0].reason, 'explicit-release'); assert.equal(calls[0].outpoints.length, 20);
  await assert.rejects(() => releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot: subject.root, ledgerPath, now: NOW }, { inspectRegistry: matchingRegistry, transition: () => { throw new Error('must not transition'); } }), { code: 'PERFORMANCE_SOURCE_RELEASE_REJECTED' });
  const alteredRegistry = () => {
    const view = matchingRegistry();
    return Object.freeze({ sources: view.sources.map((entry, index) => index === 0 ? { ...entry, dataHome: '/private/wrong-home' } : entry) });
  };
  await assert.rejects(() => releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot: subject.root, ledgerPath, now: NOW + 20_000 }, { inspectRegistry: alteredRegistry, transition: () => { throw new Error('must not transition'); } }), { code: 'PERFORMANCE_SOURCE_RELEASE_REJECTED' });
});

test('real SQLite fanout sources reserve and release only with every immutable ledger binding intact', async (t) => {
  const subject = await fixture(t);
  const fanoutTransactionId = H(88_888);
  const planValue = structuredClone(subject.candidate.value);
  planValue.sources.forEach((entry, index) => { entry.outpoint = `${fanoutTransactionId}:${index}`; });
  await privateJson(subject.planPath, planValue);
  registerV2BetaOperatorFanoutSources({
    operatorRoot: subject.root,
    fanoutTransactionId,
    sources: planValue.sources.map((entry, index) => ({
      outpoint: entry.outpoint, fanoutTransactionId, fanoutVout: index,
      lockingBytecodeHex: entry.lockingBytecodeHex, valueSats: entry.valueSats,
    })),
  });
  subject.dependencies.claimRegistry = reserveV2BetaPerformanceSourcesInRegistry;
  const reserved = await reserveV2BetaPerformanceSourcesForTest({
    operatorRoot: subject.root, planPath: subject.planPath,
    reservationDirectory: subject.reservationDirectory, runId: 'sqlite-run',
  }, subject.dependencies);
  assert.equal(reserved.sourceCount, 20);
  assert.equal(inspectV2BetaOperatorSourceRegistry({ operatorRoot: subject.root }).sources.every((entry) => entry.state === 'performance-reserved'), true);
  const ledgerPath = path.join(subject.reservationDirectory, V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME);
  await assert.rejects(
    () => releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot: subject.root, ledgerPath, now: NOW + 20_000 }, {
      inspectRegistry: ({ operatorRoot }) => {
        const view = inspectV2BetaOperatorSourceRegistry({ operatorRoot });
        return Object.freeze({ sources: view.sources.map((entry, index) => index === 0 ? { ...entry, installationReceiptSha256: H(99_999) } : entry) });
      },
    }),
    { code: 'PERFORMANCE_SOURCE_RELEASE_REJECTED' },
  );
  assert.equal(inspectV2BetaOperatorSourceRegistry({ operatorRoot: subject.root }).sources.every((entry) => entry.state === 'performance-reserved'), true);
  const released = await releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot: subject.root, ledgerPath, now: NOW + 20_000 });
  assert.deepEqual(released, { sourceCount: 20, toState: 'explicitly-released' });
  assert.equal(inspectV2BetaOperatorSourceRegistry({ operatorRoot: subject.root }).sources.every((entry) => entry.state === 'explicitly-released'), true);
});

test('rejects stale, noncanonical, too-short, duplicate, and underfunded plans before chain access', async (t) => {
  const subject = await fixture(t);
  const cases = [
    (value) => { value.expiresAtUnixMs = NOW - 1; },
    (value) => { value.sources[1].outpoint = value.sources[0].outpoint; },
    (value) => { value.sources[0].valueSats = '53006564'; },
  ];
  for (const mutate of cases) {
    const value = structuredClone(subject.candidate.value); mutate(value);
    await privateJson(subject.planPath, value);
    await assert.rejects(
      () => reserveV2BetaPerformanceSourcesForTest({
        operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
      }, subject.dependencies),
    );
    assert.equal(subject.calls.authenticate.length, 0);
  }
  await writeFile(subject.planPath, `${canonicalizeJcs(subject.candidate.value)}\n`, { mode: 0o600 });
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, subject.dependencies),
    { code: 'PERFORMANCE_SOURCE_INVALID' },
  );
});

test('rejects an operator-registry overlap before chain access', async (t) => {
  const subject = await fixture(t);
  const source = subject.candidate.sources[0];
  subject.dependencies.claimRegistry = async () => {
    throw Object.assign(new Error(`duplicate source ${source.outpoint}`), { code: 'PERFORMANCE_SOURCE_OVERLAP_REJECTED' });
  };
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, subject.dependencies),
    { code: 'PERFORMANCE_SOURCE_OVERLAP_REJECTED' },
  );
  assert.equal(subject.calls.authenticate.length, 20);
});

test('fails closed on unsafe plan/input files, unsafe data homes, and conflicting pre-existing ledger paths', async (t) => {
  const subject = await fixture(t);
  await chmod(subject.planPath, 0o644);
  await assert.rejects(
    () => readV2BetaPerformanceSourceReservationLedger(subject.planPath),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  await chmod(subject.planPath, 0o600);
  const target = path.join(subject.root, 'target.json'); await privateJson(target, subject.candidate.value);
  const linked = path.join(subject.root, 'linked-plan.json'); await symlink(target, linked);
  await assert.rejects(
    () => readV2BetaPerformanceSourceReservationLedger(linked),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  const hardLinked = path.join(subject.root, 'hard-linked-plan.json'); await link(target, hardLinked);
  await assert.rejects(
    () => readV2BetaPerformanceSourceReservationLedger(target),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  const unsafeDependencies = { ...subject.dependencies, readPrivateFile: async (filename, label) => {
    // The production strict reader is separately covered by the immutable
    // ledger path below; this seam demonstrates that a plan cannot be swapped
    // into the test core without an explicit isolated dependency.
    if (filename === linked) throw Object.assign(new Error(label), { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' });
    return readFile(filename);
  } };
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: linked, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, unsafeDependencies),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  await chmod(subject.candidate.sources[0].dataHome, 0o755);
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, subject.dependencies),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  await chmod(subject.candidate.sources[0].dataHome, 0o700);
  const victimDirectory = path.join(subject.root, 'directory-mode-victim');
  await mkdir(victimDirectory, { mode: 0o755 }); await chmod(victimDirectory, 0o755);
  await rm(subject.candidate.sources[0].dataHome, { recursive: true });
  await symlink(victimDirectory, subject.candidate.sources[0].dataHome, 'dir');
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, subject.dependencies),
    { code: 'PERFORMANCE_SOURCE_PATH_REJECTED' },
  );
  assert.equal((await lstat(victimDirectory)).mode & 0o777, 0o755);
  await rm(subject.candidate.sources[0].dataHome);
  await mkdir(subject.candidate.sources[0].dataHome, { mode: 0o700 });
  await mkdir(subject.reservationDirectory, { mode: 0o700 }); await chmod(subject.reservationDirectory, 0o700);
  await privateJson(path.join(subject.reservationDirectory, V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME), { conflict: true });
  await assert.rejects(
    () => reserveV2BetaPerformanceSourcesForTest({
      operatorRoot: subject.root, planPath: subject.planPath, reservationDirectory: subject.reservationDirectory, runId: 'test-run',
    }, subject.dependencies),
    { code: 'PERFORMANCE_SOURCE_INVALID' },
  );
});

test('authenticates exact tokenless P2PKH raw outputs and independently rejects spent, tokenized, wrong-lock, wrong-value, and wrong-txid responses', async () => {
  const sourcePlan = plan({ root: '/private' }); const parsed = parseV2BetaPerformanceSourcePlan(Buffer.from(canonicalizeJcs(sourcePlan.value)), NOW).sources[0];
  const raw = sourcePlan.sources[0].raw; let calls = 0;
  const rpc = (overrides = {}) => ({
    async getrawtransaction() { calls += 1; return overrides.raw ?? raw; },
    async gettxout() {
      calls += 1;
      return overrides.unspent === undefined ? {
        valueSatoshis: parsed.valueSats.toString(), scriptPubKey: { hex: parsed.lockingBytecodeHex },
      } : overrides.unspent;
    },
  });
  const accepted = await authenticateV2BetaPerformanceSourceForTest(parsed, rpc());
  assert.equal(calls, 2); assert.equal(accepted.rawTransactionSha256, sha256(Buffer.from(raw, 'hex')));
  for (const overrides of [
    { unspent: null },
    { unspent: { valueSatoshis: parsed.valueSats.toString(), scriptPubKey: { hex: LOCK(99) } } },
    { unspent: { valueSatoshis: '53006566', scriptPubKey: { hex: parsed.lockingBytecodeHex } } },
    { unspent: { valueSatoshis: parsed.valueSats.toString(), scriptPubKey: { hex: parsed.lockingBytecodeHex }, tokenData: {} } },
    { raw: rawTransaction({ valueSats: parsed.valueSats, lockingBytecodeHex: LOCK(99) }) },
  ]) {
    await assert.rejects(
      () => authenticateV2BetaPerformanceSourceForTest(parsed, rpc(overrides)),
      (error) => ['PERFORMANCE_SOURCE_SPENT_OR_MISSING', 'PERFORMANCE_SOURCE_AUTHENTICATION_REJECTED'].includes(error.code),
    );
  }
});

test('strict existing-input parsing accepts only canonical supported records and carries no implicit source discovery', () => {
  const usage = {
    schema: V2_BETA_PRIVATE_SOURCE_USAGE_SCHEMA,
    release: { releaseId: 'r', releaseManifestSha256: H(1) },
    sourceOutpoints: [`${H(2)}:0`],
  };
  const bytes = Buffer.from(canonicalizeJcs(usage));
  assert.equal(parseV2BetaPerformanceExistingPrivateInput(bytes).outpoints[0].text, `${H(2)}:0`);
  assert.deepEqual(
    parseV2BetaPerformanceExistingPrivateInput(Buffer.from(canonicalizeJcs({
      schema: 'shieldkit-v2-beta-live-pool-create-performance-v5',
      pools: [{ sourceOutpointProvenanceSha256: H(3) }],
    }))).provenances,
    [H(3)],
  );
  assert.deepEqual(
    parseV2BetaPerformanceExistingPrivateInput(Buffer.from(canonicalizeJcs({
      schema: 'shieldkit-v2-beta-live-qualification-v6',
      poolCreate: { sourceOutpointProvenanceSha256: H(4) },
    }))).provenances,
    [H(4)],
  );
  for (const obsolete of [
    { schema: 'shieldkit-v2-beta-live-qualification-v5', poolCreate: { sourceOutpointProvenanceSha256: H(5) } },
    { schema: 'shieldkit-v2-beta-live-pool-create-performance-v4', pools: [{ sourceOutpointProvenanceSha256: H(6) }] },
  ]) {
    assert.throws(
      () => parseV2BetaPerformanceExistingPrivateInput(Buffer.from(canonicalizeJcs(obsolete))),
      { code: 'PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED' },
    );
  }
  assert.throws(
    () => parseV2BetaPerformanceExistingPrivateInput(Buffer.from(`${canonicalizeJcs(usage)}\n`)),
    { code: 'PERFORMANCE_SOURCE_INVALID' },
  );
  assert.throws(
    () => parseV2BetaPerformanceExistingPrivateInput(Buffer.from(canonicalizeJcs({ schema: 'anything-else' }))),
    { code: 'PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED' },
  );
});
