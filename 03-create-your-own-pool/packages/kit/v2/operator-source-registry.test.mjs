import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync } from 'node:fs';
import { chmod, mkdtemp, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  claimV2BetaSemanticSource,
  inspectV2BetaOperatorSourceRegistry,
  registerV2BetaOperatorSemanticSource,
  registerV2BetaOperatorFanoutSources,
  reserveV2BetaPerformanceSourcesInRegistry,
  createV2BetaOperatorFanoutOperation,
  casV2BetaOperatorFanoutOperation,
  transitionV2BetaOperatorSources,
  V2BetaOperatorSourceRegistryError,
  v2BetaOperatorSourceRegistryLocation,
} from './operator-source-registry.mjs';

const H = (value) => value.toString(16).padStart(64, '0');
const LOCK = (ordinal) => `76a914${ordinal.toString(16).padStart(40, '0')}88ac`;
const release = Object.freeze({ releaseId: 'shieldkit-v2-beta-test-release', releaseManifestSha256: H(2) });

async function root(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-source-registry-'));
  await chmod(directory, 0o700); t.after(() => rm(directory, { recursive: true, force: true })); return directory;
}
function sources(count = 20) {
  const txid = H(900); return Array.from({ length: count }, (_, index) => ({
    outpoint: `${txid}:${index}`, fanoutTransactionId: txid, fanoutVout: index,
    lockingBytecodeHex: LOCK(index + 1), valueSats: '53006565',
  }));
}
function claim(items, { runId = 'run-a', leaseId = 'lease-a', evidenceSha256 = H(33), dataHomeRoot } = {}) {
  if (typeof dataHomeRoot !== 'string') throw new Error('test data-home root is required');
  return { release, runId, leaseId, evidenceSha256, sources: items.map((entry, index) => ({
    outpoint: entry.outpoint, dataHome: (() => {
      const directory = path.join(dataHomeRoot, `pool-${index + 1}`);
      mkdirSync(directory, { mode: 0o700, recursive: true }); chmodSync(directory, 0o700); return directory;
    })(),
    installationReceiptSha256: H(1000 + index),
  })) };
}

test('canonical owner-scoped registry atomically prevents duplicate semantic/performance claims and preserves all transition evidence', async (t) => {
  const operatorRoot = await root(t); const registered = sources();
  registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered, now: () => 10 });
  const semanticSource = { outpoint: `${H(899)}:0`, lockingBytecodeHex: LOCK(99), valueSats: '53006565' };
  registerV2BetaOperatorSemanticSource({ operatorRoot, source: semanticSource, now: () => 11 });
  const semantic = claim([semanticSource], { runId: 'semantic-r1', leaseId: 'semantic-l1', evidenceSha256: H(44), dataHomeRoot: path.join(operatorRoot, 'semantic-homes') });
  assert.equal(claimV2BetaSemanticSource({ operatorRoot, claim: semantic, now: () => 12 }).sourceCount, 1);
  const performance = claim(registered, { runId: 'performance-r1', leaseId: 'performance-l1', evidenceSha256: H(55), dataHomeRoot: path.join(operatorRoot, 'performance-homes') });
  const first = reserveV2BetaPerformanceSourcesInRegistry({ operatorRoot, claim: performance, now: () => 13 });
  assert.equal(first.sourceCount, 20);
  assert.equal(reserveV2BetaPerformanceSourcesInRegistry({ operatorRoot, claim: performance, now: () => 14 }).sourceCount, 20);
  assert.throws(() => reserveV2BetaPerformanceSourcesInRegistry({ operatorRoot, claim: { ...performance, leaseId: 'performance-l2' }, now: () => 14 }), (error) => error instanceof V2BetaOperatorSourceRegistryError && error.code === 'SOURCE_REGISTRY_SOURCE_UNAVAILABLE');
  transitionV2BetaOperatorSources({ operatorRoot, outpoints: [registered[0].outpoint], fromState: 'performance-reserved', toState: 'send-attempted', reason: 'send-boundary', leaseId: 'performance-l1', runId: 'performance-r1', evidenceSha256: H(55), now: () => 15 });
  transitionV2BetaOperatorSources({ operatorRoot, outpoints: [registered[0].outpoint], fromState: 'send-attempted', toState: 'spent', reason: 'chain-reconciled', leaseId: 'performance-l1', runId: 'performance-r1', evidenceSha256: H(55), now: () => 16 });
  transitionV2BetaOperatorSources({ operatorRoot, outpoints: [registered[0].outpoint], fromState: 'spent', toState: 'reconciled', reason: 'chain-reconciled', leaseId: 'performance-l1', runId: 'performance-r1', evidenceSha256: H(55), now: () => 17 });
  const view = inspectV2BetaOperatorSourceRegistry({ operatorRoot });
  assert.equal(view.sourceCount, 21);
  assert.equal(view.sources.find((entry) => entry.outpoint === semanticSource.outpoint).state, 'semantic-claimed');
  assert.equal(view.sources.find((entry) => entry.outpoint === registered[0].outpoint).state, 'reconciled');
  assert.equal(view.transitions.length, 45);
  assert.equal(view.transitions.some((entry) => entry.outpoint === registered[0].outpoint && entry.reason === 'send-boundary'), true);
});

test('registry enforces immutable source roles, global custody homes, and durable fanout-input reservations', async (t) => {
  const operatorRoot = await root(t); const registered = sources();
  registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered, now: () => 10 });
  assert.throws(
    () => registerV2BetaOperatorSemanticSource({ operatorRoot, source: { outpoint: registered[0].outpoint, lockingBytecodeHex: registered[0].lockingBytecodeHex, valueSats: registered[0].valueSats }, now: () => 11 }),
    { code: 'SOURCE_REGISTRY_DUPLICATE_SOURCE' },
  );
  const semanticSource = { outpoint: `${H(899)}:0`, lockingBytecodeHex: LOCK(99), valueSats: '53006565' };
  registerV2BetaOperatorSemanticSource({ operatorRoot, source: semanticSource, now: () => 12 });
  const semantic = claim([semanticSource], { runId: 'semantic-r1', leaseId: 'semantic-l1', evidenceSha256: H(44), dataHomeRoot: path.join(operatorRoot, 'shared-homes') });
  claimV2BetaSemanticSource({ operatorRoot, claim: semantic, now: () => 13 });
  const performance = claim(registered, { runId: 'performance-r1', leaseId: 'performance-l1', evidenceSha256: H(55), dataHomeRoot: path.join(operatorRoot, 'performance-homes') });
  performance.sources[0].dataHome = semantic.sources[0].dataHome;
  assert.throws(() => reserveV2BetaPerformanceSourcesInRegistry({ operatorRoot, claim: performance, now: () => 14 }), { code: 'SOURCE_REGISTRY_DATA_HOME_CONFLICT' });
  assert.throws(
    () => createV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), inputOutpoints: [registered[1].outpoint, `${H(803)}:0`], now: () => 15 }),
    { code: 'SOURCE_REGISTRY_FANOUT_INPUT_UNAVAILABLE' },
  );
  const inputs = [`${H(803)}:0`, `${H(804)}:1`];
  assert.equal(createV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), inputOutpoints: inputs, now: () => 16 }).inputCount, 2);
  assert.throws(
    () => createV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r2', transactionId: H(805), rawTransactionSha256: H(806), journalSha256: H(807), inputOutpoints: [inputs[0], `${H(808)}:0`], now: () => 17 }),
    { code: 'SOURCE_REGISTRY_FANOUT_INPUT_UNAVAILABLE' },
  );
  assert.equal(casV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), fromState: 'prepared', toState: 'send-attempted', now: () => 18 }).inputCount, 2);
  assert.throws(
    () => casV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), fromState: 'send-attempted', toState: 'explicitly-released', now: () => 19 }),
    { code: 'SOURCE_REGISTRY_INVALID' },
  );
});

test('registry rejects source tampering, duplicate fanout registration, unsafe operator roots, and a mismatched CAS transition', async (t) => {
  const operatorRoot = await root(t); const registered = sources();
  registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered, now: () => 10 });
  assert.equal(registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered, now: () => 11 }).sourceCount, 20);
  assert.throws(() => registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered.slice(0, 19), now: () => 11 }), { code: 'SOURCE_REGISTRY_INVALID' });
  assert.throws(() => transitionV2BetaOperatorSources({ operatorRoot, outpoints: [registered[0].outpoint], fromState: 'performance-reserved', toState: 'indeterminate', reason: 'send-indeterminate', now: () => 12 }), { code: 'SOURCE_REGISTRY_INVALID' });
  const link = path.join(operatorRoot, 'linked-root'); await symlink(operatorRoot, link);
  assert.throws(() => v2BetaOperatorSourceRegistryLocation({ operatorRoot: link }), { code: 'SOURCE_REGISTRY_PATH_REJECTED' });
  assert.throws(() => registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: H(900), sources: registered.map((entry, index) => index === 0 ? { ...entry, lockingBytecodeHex: LOCK(99) } : entry), now: () => 13 }), { code: 'SOURCE_REGISTRY_DUPLICATE_SOURCE' });
});

test('semantic claims require an existing canonical private data home and reject aliases', async (t) => {
  const operatorRoot = await root(t);
  const semanticSource = { outpoint: `${H(899)}:0`, lockingBytecodeHex: LOCK(99), valueSats: '53006565' };
  registerV2BetaOperatorSemanticSource({ operatorRoot, source: semanticSource, now: () => 10 });
  const base = {
    release, runId: 'semantic-r1', leaseId: 'semantic-l1', evidenceSha256: H(44),
    sources: [{ outpoint: semanticSource.outpoint, dataHome: path.join(operatorRoot, 'missing-home'), installationReceiptSha256: H(55) }],
  };
  assert.throws(() => claimV2BetaSemanticSource({ operatorRoot, claim: base, now: () => 11 }), { code: 'SOURCE_REGISTRY_PATH_REJECTED' });
  const home = path.join(operatorRoot, 'semantic-home'); mkdirSync(home, { mode: 0o700 }); chmodSync(home, 0o700);
  const alias = path.join(operatorRoot, 'semantic-home-alias'); await symlink(home, alias, 'dir');
  assert.throws(() => claimV2BetaSemanticSource({ operatorRoot, claim: { ...base, sources: [{ ...base.sources[0], dataHome: alias }] }, now: () => 12 }), { code: 'SOURCE_REGISTRY_PATH_REJECTED' });
  assert.equal(claimV2BetaSemanticSource({ operatorRoot, claim: { ...base, sources: [{ ...base.sources[0], dataHome: home }] }, now: () => 13 }).sourceCount, 1);
});

test('registry rejects DDL tampering and refuses a fanout CAS with a missing reservation', async (t) => {
  const operatorRoot = await root(t); const inputs = [`${H(801)}:0`, `${H(802)}:1`, `${H(803)}:2`];
  createV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), inputOutpoints: inputs, now: () => 10 });
  const filename = v2BetaOperatorSourceRegistryLocation({ operatorRoot }).filename;
  const database = new DatabaseSync(filename);
  database.exec(`DELETE FROM fanout_input_reservations WHERE outpoint='${inputs[2]}'`);
  database.close();
  assert.throws(
    () => casV2BetaOperatorFanoutOperation({ operatorRoot, runId: 'fanout-r1', transactionId: H(800), rawTransactionSha256: H(801), journalSha256: H(802), fromState: 'prepared', toState: 'send-attempted', now: () => 11 }),
    { code: 'SOURCE_REGISTRY_CAS_CONFLICT' },
  );
  const tampered = new DatabaseSync(filename);
  tampered.exec('DROP TABLE source_transitions; CREATE TABLE source_transitions (transition_id INTEGER PRIMARY KEY, outpoint TEXT NOT NULL) STRICT;');
  tampered.close();
  assert.throws(() => inspectV2BetaOperatorSourceRegistry({ operatorRoot }), { code: 'SOURCE_REGISTRY_TAMPERED' });
});
