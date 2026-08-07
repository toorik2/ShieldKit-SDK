#!/usr/bin/env node
/** Fresh, one-invocation pool-create latency evidence. Never funds or scans. */
import { chmod, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createPublicChipnetFulcrumRpc } from '../packages/kit/chipnet-rpc.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { readV2BetaPerformanceSourceReservationLedger } from '../packages/kit/v2/performance-source-reservations.mjs';
import { inspectV2BetaOperatorSourceRegistry, transitionV2BetaOperatorSources } from '../packages/kit/v2/operator-source-registry.mjs';
import { assertPrivateDirectory, assertPrivateFile, readPrivateUtf8, writePrivateFile } from './v2-beta-private-paths.mjs';
import { inspectV2BetaLivePoolCreateEvidence, parseFundingOutpoint, sourceOutpointProvenanceSha256, validateV2BetaPinnedInstall } from './v2-beta-live-qualification.mjs';

export const V2_BETA_LIVE_POOL_CREATE_PERFORMANCE_SCHEMA = 'shieldkit-v2-beta-live-pool-create-performance-v5';
export const V2_BETA_POOL_CREATE_PERFORMANCE_MINIMUM = 20;
const JOURNAL_SCHEMA = 'shieldkit-v2-beta-live-pool-create-performance-journal-v3';
const JOURNAL_FILE = 'live-pool-create-performance-run.json';
const HASH = /^[0-9a-f]{64}$/u;
const STATES = new Set(['planned', 'command-started', 'accepted']);

export class V2BetaLivePoolCreatePerformanceError extends Error { constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaLivePoolCreatePerformanceError'; this.code = code; } }
const fail = (code, message, options = undefined) => { throw new V2BetaLivePoolCreatePerformanceError(code, message, options); };
function exact(value, keys, label) { if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('LIVE_POOL_PERFORMANCE_INVALID', `${label} must be a plain object`); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('LIVE_POOL_PERFORMANCE_INVALID', `${label} has missing or unknown fields`); return value; }
function duration(value, label) { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail('LIVE_POOL_PERFORMANCE_INVALID', `${label} must be a finite nonnegative duration`); return value; }
function privateAbsolute(value, label) { if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) fail('LIVE_POOL_PERFORMANCE_PATH_REJECTED', `${label} must be a normalized absolute path`); return value; }
function claims(value, label) { if (value?.confirmed !== false || value?.mined !== false || value?.productionQualified !== false) fail('LIVE_POOL_PERFORMANCE_CLAIM_REJECTED', `${label} is not explicitly beta-only`); return Object.freeze({ confirmed: false, mined: false, productionQualified: false }); }
function cliRequest(tokens) { return Object.freeze({ executable: process.execPath, args: [path.resolve(import.meta.dirname, 'shieldkit.mjs'), ...tokens], literal: Object.freeze(['shieldkit', ...tokens]) }); }
function parseCli(value, label) { if (value?.code !== 0) fail('LIVE_POOL_PERFORMANCE_CLI_FAILED', `${label} exited unsuccessfully`); try { const body = JSON.parse(value.stdout); if (body?.ok !== true) fail('LIVE_POOL_PERFORMANCE_CLI_FAILED', `${label} did not return success JSON`); claims(body, label); return body.result; } catch (error) { if (error instanceof V2BetaLivePoolCreatePerformanceError) throw error; fail('LIVE_POOL_PERFORMANCE_CLI_FAILED', `${label} did not return JSON`, { cause: error }); } }
function percentile(values, probability) { return [...values].sort((a, b) => a - b)[Math.ceil(values.length * probability) - 1]; }
function distributions(samples) { const values = samples.map((entry) => entry.commandDurationMs); return Object.freeze({ sampleCount: samples.length, commandDurationMs: Object.freeze({ p50: percentile(values, 0.5), p95: percentile(values, 0.95), max: Math.max(...values) }) }); }
function assertThresholds(metrics) { if (metrics.commandDurationMs.p50 > 5000 || metrics.commandDurationMs.p95 > 10000) fail('LIVE_POOL_PERFORMANCE_THRESHOLD_REJECTED', 'commandDurationMs exceeds p50 <= 5000ms or p95 <= 10000ms'); }
function releaseIdentity(value, label) { exact(value, ['releaseId', 'releaseManifestSha256'], label); if (typeof value.releaseId !== 'string' || value.releaseId.length === 0 || !HASH.test(value.releaseManifestSha256)) fail('LIVE_POOL_PERFORMANCE_INSTALL_REJECTED', `${label} is malformed`); return Object.freeze({ releaseId: value.releaseId, releaseManifestSha256: value.releaseManifestSha256 }); }
function publicSample(record, installationReceiptSha256) { const pool = record.pool; for (const value of [installationReceiptSha256, record.sourceOutpointProvenanceSha256, pool.sourceTransactionId, pool.genesisTransactionId, pool.instanceId, pool.actionFundingSetSha256]) if (!HASH.test(value)) fail('LIVE_POOL_PERFORMANCE_RESULT_REJECTED', 'sample identity is not lowercase SHA-256'); const result = Object.freeze({ ordinal: record.ordinal, installationReceiptSha256, commandDurationMs: record.commandDurationMs, sourceOutpointProvenanceSha256: record.sourceOutpointProvenanceSha256, sourceTransactionId: pool.sourceTransactionId, genesisTransactionId: pool.genesisTransactionId, instanceId: pool.instanceId, actionFundingSetSha256: pool.actionFundingSetSha256, runtimeWork: pool.runtime.work, claims: pool.claims }); duration(result.commandDurationMs, 'sample.commandDurationMs'); return result; }
function validateJournal(value, count) { exact(value, ['installReceipts', 'release', 'samples', 'schema', 'sourceReservationLedgerSha256'], 'pool performance journal'); const release = releaseIdentity(value.release, 'pool performance journal release'); if (value.schema !== JOURNAL_SCHEMA || !HASH.test(value.sourceReservationLedgerSha256) || !Array.isArray(value.installReceipts) || !Array.isArray(value.samples) || value.installReceipts.length !== count || value.samples.length !== count || value.installReceipts.some((receipt) => !HASH.test(receipt)) || new Set(value.installReceipts).size !== count) fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'pool performance journal is malformed'); const active = value.samples.filter((sample) => sample?.state === 'command-started'); if (active.length > 1 || value.samples.some((sample, index) => !Number.isSafeInteger(sample?.ordinal) || sample.ordinal !== index + 1 || !STATES.has(sample.state) || (sample.sourceOutpointProvenanceSha256 !== undefined && !HASH.test(sample.sourceOutpointProvenanceSha256)))) fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'journal does not retain exactly one canonical in-flight sample'); return Object.freeze({ ...value, release }); }
async function openFileJournal({ journalDirectory, count }) { await mkdir(journalDirectory, { mode: 0o700 }).catch((error) => { if (error?.code !== 'EEXIST') throw error; }); await chmod(journalDirectory, 0o700); await assertPrivateDirectory(journalDirectory, 'pool performance journal directory'); const filename = path.join(journalDirectory, JOURNAL_FILE); let record = null; try { record = validateJournal(JSON.parse(await readPrivateUtf8(filename, 'pool performance journal')), count); } catch (error) { if (error?.code !== 'ENOENT') fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'pool performance journal must be private', { cause: error }); } const save = async () => { try { await writePrivateFile(filename, Buffer.from(canonicalizeJcs(record), 'utf8'), 'pool performance journal'); } catch (error) { fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'cannot persist pool performance journal', { cause: error }); } }; return Object.freeze({ load: () => record, async start(value) { if (record !== null) fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'pool performance journal already exists'); record = validateJournal(value, count); await save(); return record; }, async update(value) { record = validateJournal(value, count); await save(); return record; }, close() {} }); }
function assertDeps(value) { exact(value, ['inspectPool', 'inspectRegistry', 'loadReservationLedger', 'now', 'openJournal', 'registryTransition', 'rpc', 'runCommand', 'validateInstall', 'writeEvidence'], 'pool performance dependencies'); for (const key of ['inspectPool', 'inspectRegistry', 'loadReservationLedger', 'now', 'openJournal', 'registryTransition', 'runCommand', 'validateInstall', 'writeEvidence']) if (typeof value[key] !== 'function') fail('LIVE_POOL_PERFORMANCE_INVALID', `dependency ${key} must be a function`); if (typeof value.rpc?.getrawtransaction !== 'function') fail('LIVE_POOL_PERFORMANCE_INVALID', 'rpc.getrawtransaction must be a function'); return value; }
function replaceSample(record, index, sample) { return Object.freeze({ ...record, samples: Object.freeze(record.samples.map((entry, ordinal) => ordinal === index ? Object.freeze(sample) : entry)) }); }

async function run(options, dependencies) {
  exact(options, ['evidenceDirectory', 'fundingUtxos', 'fundingWallets', 'operatorRoot', 'poolDataHomes', 'sourceReservationLedger'], 'pool performance options'); const deps = assertDeps(dependencies);
  const { poolDataHomes, fundingWallets, fundingUtxos } = options;
  if (!Array.isArray(poolDataHomes) || !Array.isArray(fundingWallets) || !Array.isArray(fundingUtxos) || poolDataHomes.length !== V2_BETA_POOL_CREATE_PERFORMANCE_MINIMUM || fundingWallets.length !== poolDataHomes.length || fundingUtxos.length !== poolDataHomes.length || new Set(poolDataHomes).size !== poolDataHomes.length) fail('LIVE_POOL_PERFORMANCE_POOL_REJECTED', 'exactly twenty distinct data homes with paired wallets and pre-funded outpoints are required');
  const outpoints = fundingUtxos.map(parseFundingOutpoint); if (new Set(outpoints.map((entry) => `${entry.txid}:${entry.vout}`)).size !== outpoints.length) fail('LIVE_POOL_PERFORMANCE_POOL_REJECTED', 'every fresh pool sample requires a distinct pre-funded outpoint');
  let reservation;
  const sourceReservationLedger = privateAbsolute(options.sourceReservationLedger, 'source reservation ledger');
  try { reservation = await deps.loadReservationLedger({ filename: sourceReservationLedger, now: deps.now() }); }
  catch (error) { fail('LIVE_POOL_PERFORMANCE_RESERVATION_REJECTED', 'private source-reservation ledger is unavailable, unsafe, expired, or malformed', { cause: error }); }
  if (!HASH.test(reservation?.sha256) || reservation.ledger === null || typeof reservation.ledger !== 'object' || !Array.isArray(reservation.ledger.sources) || reservation.ledger.sources.length !== V2_BETA_POOL_CREATE_PERFORMANCE_MINIMUM) fail('LIVE_POOL_PERFORMANCE_RESERVATION_REJECTED', 'private source-reservation ledger has an unsupported shape');
  const installed = await Promise.all(poolDataHomes.map((dataHome) => deps.validateInstall({ dataHome })));
  if (installed.some((entry) => !HASH.test(entry?.receiptSha256) || typeof entry.dataDirectory !== 'string' || typeof entry.releaseId !== 'string' || entry.releaseId.length === 0 || !HASH.test(entry.releaseManifestSha256)) || new Set(installed.map((entry) => entry.dataDirectory)).size !== installed.length || new Set(installed.map((entry) => entry.receiptSha256)).size !== installed.length) fail('LIVE_POOL_PERFORMANCE_INSTALL_REJECTED', 'every pool data home requires one distinct completed pinned installation');
  const release = releaseIdentity({ releaseId: installed[0].releaseId, releaseManifestSha256: installed[0].releaseManifestSha256 }, 'pool performance release');
  if (installed.some((entry) => entry.releaseId !== release.releaseId || entry.releaseManifestSha256 !== release.releaseManifestSha256)) fail('LIVE_POOL_PERFORMANCE_INSTALL_REJECTED', 'every pool installation must be pinned to the same release manifest');
  if (canonicalizeJcs(reservation.ledger.release) !== canonicalizeJcs(release) || reservation.ledger.sources.some((entry, index) => entry?.ordinal !== index + 1 || entry?.outpoint?.txid !== outpoints[index].txid || entry?.outpoint?.vout !== outpoints[index].vout || entry?.dataHome !== poolDataHomes[index] || entry?.installationReceiptSha256 !== installed[index].receiptSha256)) fail('LIVE_POOL_PERFORMANCE_RESERVATION_REJECTED', 'private source-reservation ledger does not exactly bind every ordinal outpoint, data home, receipt, and release');
  let registry; try { registry = await deps.inspectRegistry({ operatorRoot: privateAbsolute(options.operatorRoot, 'operator root') }); } catch (error) { fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'canonical operator registry cannot be inspected', { cause: error }); }
  if (!Array.isArray(registry?.sources)) fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'canonical operator registry does not retain sources');
  const registryByOutpoint = new Map();
  for (const entry of reservation.ledger.sources) {
    const matches = registry.sources.filter((source) => source.outpoint === entry.outpoint.text
      && source.leaseId === reservation.ledger.leaseId && source.runId === reservation.ledger.runId
      && source.evidenceSha256 === reservation.ledger.registryClaimSha256);
    if (matches.length !== 1 || !['performance-reserved', 'send-attempted', 'spent', 'reconciled'].includes(matches[0].state)) fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'canonical registry does not retain one exact bound source row for every ordinal');
    registryByOutpoint.set(entry.outpoint.text, { ...matches[0] });
  }
  const journal = await deps.openJournal({ journalDirectory: path.join(options.evidenceDirectory, '.live-pool-create-performance-journal'), count: poolDataHomes.length }); const started = deps.now();
  try {
    let record = journal.load(); const receipts = installed.map((entry) => entry.receiptSha256); if (record === null) record = await journal.start(Object.freeze({ schema: JOURNAL_SCHEMA, release, sourceReservationLedgerSha256: reservation.sha256, installReceipts: Object.freeze(receipts), samples: Object.freeze(poolDataHomes.map((_, index) => Object.freeze({ ordinal: index + 1, state: 'planned' }))) }));
    if (canonicalizeJcs(record.installReceipts) !== canonicalizeJcs(receipts) || canonicalizeJcs(record.release) !== canonicalizeJcs(release) || record.sourceReservationLedgerSha256 !== reservation.sha256) fail('LIVE_POOL_PERFORMANCE_JOURNAL_REJECTED', 'journal belongs to different pinned installations, ledger, or release');
    for (let index = 0; index < record.samples.length; index += 1) {
      let sample = record.samples[index]; const outpoint = outpoints[index]; const outpointText = `${outpoint.txid}:${outpoint.vout}`; const sourceRow = registryByOutpoint.get(outpointText);
      if (sourceRow === undefined) fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'planned source is absent from the canonical bound registry view');
      if (sample.state === 'accepted') { if (sourceRow.state !== 'reconciled') fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'accepted journal sample is not reconciled in canonical registry'); continue; }
      const provenance = sourceOutpointProvenanceSha256(outpoint);
      if (sample.state === 'command-started') {
        // The child result is durably captured before independent inspection.
        // This reconciliation path only reads BCHN and local journals: it does
        // not invoke the child CLI or resend a transaction.
        if (sample.sourceOutpointProvenanceSha256 !== provenance || sample.childResult === undefined || !['send-attempted', 'spent', 'reconciled'].includes(sourceRow.state)) fail('LIVE_POOL_PERFORMANCE_RECONCILIATION_REQUIRED', 'pool create may have been invoked but no exact read-only reconciliation binding is available');
        const pool = await deps.inspectPool(sample.childResult, outpoint, deps.rpc, { requireFreshLink: true });
        if (sourceRow.state === 'send-attempted') { await deps.registryTransition({ operatorRoot: options.operatorRoot, outpoints: [outpointText], fromState: 'send-attempted', toState: 'spent', reason: 'chain-reconciled', leaseId: reservation.ledger.leaseId, runId: reservation.ledger.runId, evidenceSha256: reservation.ledger.registryClaimSha256 }); sourceRow.state = 'spent'; }
        if (sourceRow.state === 'spent') { await deps.registryTransition({ operatorRoot: options.operatorRoot, outpoints: [outpointText], fromState: 'spent', toState: 'reconciled', reason: 'chain-reconciled', leaseId: reservation.ledger.leaseId, runId: reservation.ledger.runId, evidenceSha256: reservation.ledger.registryClaimSha256 }); sourceRow.state = 'reconciled'; }
        sample = { ...sample, state: 'accepted', pool, commandDurationMs: sample.commandDurationMs ?? 0 }; record = await journal.update(replaceSample(record, index, sample)); continue;
      }
      if (sourceRow.state !== 'performance-reserved') fail('LIVE_POOL_PERFORMANCE_REGISTRY_REJECTED', 'planned journal sample is not performance-reserved in canonical registry');
      sample = { ...sample, state: 'command-started', sourceOutpointProvenanceSha256: provenance }; record = await journal.update(replaceSample(record, index, sample));
      await deps.registryTransition({ operatorRoot: options.operatorRoot, outpoints: [`${outpoint.txid}:${outpoint.vout}`], fromState: 'performance-reserved', toState: 'send-attempted', reason: 'send-boundary', leaseId: reservation.ledger.leaseId, runId: reservation.ledger.runId, evidenceSha256: reservation.ledger.registryClaimSha256 });
      sourceRow.state = 'send-attempted';
      const commandStarted = deps.now();
      const cli = await deps.runCommand(cliRequest(['pool', 'create', '--data-home', poolDataHomes[index], '--funding-wallet', fundingWallets[index], '--funding-utxo', `${outpoint.txid}:${outpoint.vout}`, '--json']));
      const commandDurationMs = deps.now() - commandStarted;
      const childResult = parseCli(cli, `pool create ${sample.ordinal}`);
      sample = { ...sample, childResult, commandDurationMs }; record = await journal.update(replaceSample(record, index, sample));
      const pool = await deps.inspectPool(childResult, outpoint, deps.rpc, { requireFreshLink: true });
      await deps.registryTransition({ operatorRoot: options.operatorRoot, outpoints: [`${outpoint.txid}:${outpoint.vout}`], fromState: 'send-attempted', toState: 'spent', reason: 'chain-reconciled', leaseId: reservation.ledger.leaseId, runId: reservation.ledger.runId, evidenceSha256: reservation.ledger.registryClaimSha256 });
      sourceRow.state = 'spent';
      await deps.registryTransition({ operatorRoot: options.operatorRoot, outpoints: [`${outpoint.txid}:${outpoint.vout}`], fromState: 'spent', toState: 'reconciled', reason: 'chain-reconciled', leaseId: reservation.ledger.leaseId, runId: reservation.ledger.runId, evidenceSha256: reservation.ledger.registryClaimSha256 });
      sourceRow.state = 'reconciled';
      sample = { ...sample, state: 'accepted', pool, commandDurationMs }; record = await journal.update(replaceSample(record, index, sample));
    }
    const samples = record.samples.map((sample, index) => publicSample(sample, receipts[index])); for (const key of ['installationReceiptSha256', 'sourceOutpointProvenanceSha256', 'sourceTransactionId', 'genesisTransactionId', 'instanceId', 'actionFundingSetSha256']) if (new Set(samples.map((sample) => sample[key])).size !== samples.length) fail('LIVE_POOL_PERFORMANCE_RESULT_REJECTED', `${key} is duplicated across fresh pool samples`); const metrics = distributions(samples); assertThresholds(metrics);
    const evidence = Object.freeze({ schema: V2_BETA_LIVE_POOL_CREATE_PERFORMANCE_SCHEMA, scope: 'fresh-pool-create-performance-explicitly-unqualified', release, sourceReservationLedgerSha256: reservation.sha256, claims: claims({ confirmed: false, mined: false, productionQualified: false }, 'pool performance claims'), pools: Object.freeze(samples), metrics, elapsedMs: deps.now() - started }); const serialized = JSON.stringify(evidence); if (/(?:dataHome|fundingWallet|fundingUtxo|rawTransaction|privateKey|secret|witness|circuitInput)/iu.test(serialized)) fail('LIVE_POOL_PERFORMANCE_EVIDENCE_SECRET_REJECTED', 'pool performance evidence includes a private path, raw outpoint, transaction, or secret'); return Object.freeze({ evidence, evidencePath: await deps.writeEvidence(options.evidenceDirectory, evidence) });
  } finally { journal.close(); }
}
export async function runV2BetaLivePoolCreatePerformanceForTest(options, dependencies) { return run(options, dependencies); }

async function writePoolCreatePerformanceEvidence(directory, evidence) {
  const filename = path.join(
    directory,
    `v2-beta-live-pool-create-performance-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}.json`,
  );
  await writePrivateFile(
    filename,
    Buffer.from(`${canonicalizeJcs(evidence)}\n`, 'utf8'),
    'pool performance evidence',
  );
  return filename;
}

/** Unit-test seam for the production private evidence writer and returned path. */
export async function writeV2BetaLivePoolCreatePerformanceEvidenceForTest(directory, evidence) {
  return writePoolCreatePerformanceEvidence(directory, evidence);
}

async function loadInputs(values) { exact(values, ['evidenceDirectory', 'fundingUtxos', 'fundingWallets', 'operatorRoot', 'poolDataHomes', 'sourceReservationLedger'], 'pool performance cli options'); await assertPrivateDirectory(privateAbsolute(values.evidenceDirectory, 'evidence directory'), 'evidence directory'); await assertPrivateDirectory(privateAbsolute(values.operatorRoot, 'operator root'), 'operator root'); await Promise.all(values.poolDataHomes.map((home) => assertPrivateDirectory(privateAbsolute(home, 'pool data home'), 'pool data home'))); await Promise.all(values.fundingWallets.map((wallet) => assertPrivateFile(privateAbsolute(wallet, 'funding wallet'), 'funding wallet'))); await assertPrivateFile(privateAbsolute(values.sourceReservationLedger, 'source reservation ledger'), 'source reservation ledger'); values.fundingUtxos.forEach(parseFundingOutpoint); return Object.freeze({ evidenceDirectory: values.evidenceDirectory, operatorRoot: values.operatorRoot, poolDataHomes: Object.freeze(values.poolDataHomes), fundingWallets: Object.freeze(values.fundingWallets), fundingUtxos: Object.freeze(values.fundingUtxos), sourceReservationLedger: values.sourceReservationLedger }); }
function usage() { throw new Error('usage: node v2-beta-live-pool-create-performance.mjs --execute-live --operator-root <private-0700-dir> --evidence-dir <private-absolute-dir> --source-reservation-ledger <private-immutable-ledger.json> --pool-data-home <private-absolute-dir> --funding-wallet <private-canonical-wallet-json> --funding-utxo <txid:vout> [... exactly 20 triples]'); }
function parseArguments(tokens) { if (tokens[0] !== '--execute-live') usage(); const values = { poolDataHomes: [], fundingWallets: [], fundingUtxos: [] }; for (let index = 1; index < tokens.length; index += 2) { const name = tokens[index]; const value = tokens[index + 1]; if (value === undefined) usage(); if (name === '--pool-data-home') values.poolDataHomes.push(value); else if (name === '--funding-wallet') values.fundingWallets.push(value); else if (name === '--funding-utxo') values.fundingUtxos.push(value); else if (name === '--evidence-dir' && values.evidenceDirectory === undefined) values.evidenceDirectory = value; else if (name === '--operator-root' && values.operatorRoot === undefined) values.operatorRoot = value; else if (name === '--source-reservation-ledger' && values.sourceReservationLedger === undefined) values.sourceReservationLedger = value; else usage(); } if (values.evidenceDirectory === undefined || values.sourceReservationLedger === undefined || values.operatorRoot === undefined) usage(); return values; }
if (import.meta.main === true || (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  if (process.version !== 'v22.23.1') throw new Error(`LIVE_POOL_PERFORMANCE_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`);
  const inputs = await loadInputs(parseArguments(process.argv.slice(2)));
  const rpc = await createPublicChipnetFulcrumRpc();
  try {
    const result = await run(inputs, {
      inspectPool: inspectV2BetaLivePoolCreateEvidence,
      inspectRegistry: inspectV2BetaOperatorSourceRegistry,
      loadReservationLedger: ({ filename, now }) => readV2BetaPerformanceSourceReservationLedger(filename, now),
      now: Date.now,
      openJournal: openFileJournal,
      registryTransition: transitionV2BetaOperatorSources,
      rpc,
      runCommand: async (request) => {
        const { spawn } = await import('node:child_process');
        return new Promise((resolve, reject) => {
          const child = spawn(request.executable, request.args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
          const stdout = []; const stderr = [];
          child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
          child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
          child.once('error', reject);
          child.once('close', (code) => resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
        });
      },
      validateInstall: validateV2BetaPinnedInstall,
      writeEvidence: writePoolCreatePerformanceEvidence,
    });
    process.stdout.write(`${JSON.stringify({ evidencePath: result.evidencePath, metrics: result.evidence.metrics, claims: result.evidence.claims })}\n`);
  } finally {
    try { rpc.close?.(); } catch {}
  }
}
