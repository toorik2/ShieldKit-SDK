#!/usr/bin/env node
/** Strict warm-performance evidence; it never creates pools or sends recovery transactions. */
import { chmod, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { decodeCashAddress } from '@bitauth/libauth';

import { loadV2BetaProductConfig } from '../packages/kit/v2/beta-product-config.mjs';
import { loadV2BetaProductArtifactInstallation } from '../packages/profile/v2/beta-product-artifact-installation.mjs';
import {
  V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY,
  V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA,
  loadV2BetaProductTrackedReleasePin,
} from '../packages/profile/v2/beta-product-offline-bootstrap.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { inspectV2BetaLiveActionEvidence } from './v2-beta-live-action-evidence.mjs';
import { assertPrivateDirectory, readPrivateUtf8, writePrivateFile } from './v2-beta-private-paths.mjs';

export const V2_BETA_LIVE_PERFORMANCE_SCHEMA = 'shieldkit-v2-beta-live-performance-v1';
export const V2_BETA_WARM_SAMPLES_PER_POOL = 5;
export const V2_BETA_WARM_POOL_MINIMUM = 4;
const JOURNAL_SCHEMA = 'shieldkit-v2-beta-live-performance-journal-v1';
const JOURNAL_FILE = 'live-performance-run.json';
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export class V2BetaLivePerformanceError extends Error {
  constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaLivePerformanceError'; this.code = code; }
}
const fail = (code, message, options = undefined) => { throw new V2BetaLivePerformanceError(code, message, options); };
const finite = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
function exact(value, keys, label) { if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('LIVE_PERFORMANCE_INVALID', `${label} must be a plain object`); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('LIVE_PERFORMANCE_INVALID', `${label} has missing or unknown properties`); return value; }
function absolute(value, label) { if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) fail('LIVE_PERFORMANCE_PATH_REJECTED', `${label} must be a normalized absolute path`); return value; }
async function privateDirectory(value, label) { try { absolute(value, label); return await assertPrivateDirectory(value, label); } catch (error) { fail('LIVE_PERFORMANCE_PATH_REJECTED', `${label} must be a private canonical directory`, { cause: error }); } }
function claims(value, label) { if (value?.confirmed !== false || value?.mined !== false || value?.productionQualified !== false) fail('LIVE_PERFORMANCE_FALSE_CLAIM_REJECTED', `${label} did not preserve beta-only claims`); return Object.freeze({ confirmed: false, mined: false, productionQualified: false }); }
function p2pkhCashAddress(value) { const decoded = decodeCashAddress(value); if (typeof decoded === 'string' || decoded.prefix !== 'bchtest' || decoded.type !== 'p2pkh' || decoded.payload.length !== 20) fail('LIVE_PERFORMANCE_WITHDRAWAL_REJECTED', 'withdrawal destination must be a Chipnet P2PKH cash address'); return value; }
function cliRequest(tokens) { return Object.freeze({ executable: process.execPath, args: [path.resolve(import.meta.dirname, 'shieldkit.mjs'), ...tokens], literal: Object.freeze(['shieldkit', ...tokens]) }); }
function parseCli(value, label) { if (value?.code !== 0) fail('LIVE_PERFORMANCE_CLI_FAILED', `${label} exited unsuccessfully`); try { const body = JSON.parse(value.stdout); if (body?.ok !== true) fail('LIVE_PERFORMANCE_CLI_FAILED', `${label} did not return success JSON`); claims(body, label); return body.result; } catch (error) { if (error instanceof V2BetaLivePerformanceError) throw error; fail('LIVE_PERFORMANCE_CLI_FAILED', `${label} did not return JSON`, { cause: error }); } }
function strictAction(result, kind, operationId) {
  try {
    return inspectV2BetaLiveActionEvidence(result, { command: kind, operationId });
  } catch (error) {
    fail(
      'LIVE_PERFORMANCE_RESULT_REJECTED',
      `${kind} action evidence is incomplete or inconsistent`,
      { cause: error },
    );
  }
}
function percentile(values, probability) { const sorted = [...values].sort((left, right) => left - right); return sorted[Math.ceil(sorted.length * probability) - 1]; }
function metrics(records) { const command = records.map((entry) => entry.commandTotalMs); const action = records.map((entry) => entry.actionTotalMs); if (command.length < 20 || action.length < 20) fail('LIVE_PERFORMANCE_SAMPLE_REJECTED', 'at least twenty warm samples per action kind are required'); return Object.freeze({ sampleCount: command.length, commandTotalMs: Object.freeze({ p50: percentile(command, 0.5), p95: percentile(command, 0.95) }), actionTotalMs: Object.freeze({ p50: percentile(action, 0.5), p95: percentile(action, 0.95) }) }); }
function assertThresholds(value) { for (const metric of [value.commandTotalMs, value.actionTotalMs]) if (metric.p50 > 5000 || metric.p95 > 10000) fail('LIVE_PERFORMANCE_THRESHOLD_REJECTED', 'warm performance exceeds p50 <= 5000ms or p95 <= 10000ms'); }
async function writeCanonicalPrivate(filename, value) { try { await writePrivateFile(filename, Buffer.from(canonicalizeJcs(value), 'utf8'), 'performance journal'); } catch (error) { fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal cannot be safely written', { cause: error }); } }
function validateJournal(value) { exact(value, ['actions', 'installReceipts', 'schema', 'started'], 'performance journal'); if (value.schema !== JOURNAL_SCHEMA || !Array.isArray(value.actions) || !Array.isArray(value.installReceipts) || value.started !== true) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal is malformed'); return value; }
async function openFileJournal({ journalDirectory }) { await mkdir(journalDirectory, { mode: 0o700 }).catch((error) => { if (error?.code !== 'EEXIST') throw error; }); await chmod(journalDirectory, 0o700); await privateDirectory(journalDirectory, 'performance journal directory'); const filename = path.join(journalDirectory, JOURNAL_FILE); let record = null; try { record = validateJournal(JSON.parse(await readPrivateUtf8(filename, 'performance journal'))); } catch (error) { if (error?.code !== 'ENOENT') fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal must be private', { cause: error }); } const save = async () => writeCanonicalPrivate(filename, record); return Object.freeze({ load: () => record, async start(value) { if (record !== null) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal already exists'); record = validateJournal(value); await save(); return record; }, async update(value) { record = validateJournal(value); await save(); return record; }, close() {} }); }
async function validateInstalledPool({ dataHome }) { const loaded = loadV2BetaProductConfig({ dataHome }); const installation = await loadV2BetaProductArtifactInstallation({ productDataDirectory: loaded.config.dataDirectory }); const pin = await loadV2BetaProductTrackedReleasePin(); let journal; try { journal = JSON.parse(await readPrivateUtf8(path.join(loaded.config.dataDirectory, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY, 'journal.json'), 'offline install journal')); } catch (error) { fail('LIVE_PERFORMANCE_INSTALL_REJECTED', 'a completed pinned offline-install journal is required for every pool', { cause: error }); } if (journal?.schema !== V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA || journal.status !== 'committed' || journal.releaseId !== pin.releaseId || journal.releaseManifestSha256 !== pin.releaseManifestSha256 || journal.receiptSha256 !== installation.receiptSha256) fail('LIVE_PERFORMANCE_INSTALL_REJECTED', 'pool artifact receipt does not match the pinned offline-install journal'); return Object.freeze({ dataDirectory: loaded.config.dataDirectory, receiptSha256: installation.receiptSha256 }); }
function assertDeps(value) { exact(value, ['now', 'openJournal', 'runCommand', 'validateInstalledPool', 'writeEvidence'], 'performance test dependencies'); for (const name of ['now', 'openJournal', 'runCommand', 'validateInstalledPool', 'writeEvidence']) if (typeof value[name] !== 'function') fail('LIVE_PERFORMANCE_INVALID', `dependency ${name} must be a function`); return value; }
function actionPlan(poolOrdinal, dataHome, withdrawalAddress) { const prefix = `warm.${String(poolOrdinal + 1).padStart(2, '0')}`; return Object.freeze([...[...Array(V2_BETA_WARM_SAMPLES_PER_POOL).keys()].map((index) => Object.freeze({ kind: 'deposit', poolOrdinal, ordinal: index + 1, dataHome, operationId: `${prefix}.deposit.${String(index + 1).padStart(2, '0')}` })), ...[...Array(V2_BETA_WARM_SAMPLES_PER_POOL).keys()].map((index) => Object.freeze({ kind: 'withdraw', poolOrdinal, ordinal: index + 1, dataHome, operationId: `${prefix}.withdraw.${String(index + 1).padStart(2, '0')}`, withdrawalAddress }))]); }

async function run(options, dependencies) {
  exact(options, ['evidenceDirectory', 'poolDataHomes', 'withdrawalAddress'], 'live performance options'); const deps = assertDeps(dependencies); await Promise.all([privateDirectory(options.evidenceDirectory, 'evidence directory'), ...options.poolDataHomes.map((entry, index) => privateDirectory(entry, `pool data home ${index + 1}`))]); if (!Array.isArray(options.poolDataHomes) || options.poolDataHomes.length < V2_BETA_WARM_POOL_MINIMUM || new Set(options.poolDataHomes).size !== options.poolDataHomes.length) fail('LIVE_PERFORMANCE_POOL_REJECTED', 'at least four distinct pre-created pool data homes are required'); p2pkhCashAddress(options.withdrawalAddress);
  const installed = await Promise.all(options.poolDataHomes.map((dataHome) => deps.validateInstalledPool({ dataHome }))); if (installed.some((entry) => !HASH.test(entry?.receiptSha256) || typeof entry.dataDirectory !== 'string')) fail('LIVE_PERFORMANCE_INSTALL_REJECTED', 'every pool must have a validated installed receipt');
  const journal = await deps.openJournal({ journalDirectory: path.join(options.evidenceDirectory, '.live-performance-journal') }); const started = deps.now();
  try {
    let record = journal.load(); const receipts = installed.map((entry) => entry.receiptSha256);
    if (record === null) record = await journal.start(Object.freeze({ schema: JOURNAL_SCHEMA, started: true, installReceipts: Object.freeze(receipts), actions: [] }));
    if (canonicalizeJcs(record.installReceipts) !== canonicalizeJcs(receipts)) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal belongs to different pool installations');
    const plan = options.poolDataHomes.flatMap((dataHome, poolOrdinal) => actionPlan(poolOrdinal, dataHome, options.withdrawalAddress));
    const planned = new Map(plan.map((item) => [item.operationId, item]));
    for (const entry of record.actions) {
      const item = planned.get(entry?.operationId);
      if (item === undefined || !['accepted', 'pending'].includes(entry.state) || entry.kind !== item.kind || entry.poolOrdinal !== item.poolOrdinal || entry.ordinal !== item.ordinal) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal action does not bind one exact planned idempotency key');
    }
    const pending = record.actions.filter((entry) => entry.state === 'pending');
    if (pending.length > 1) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal has more than one in-flight deterministic action');
    const seenIds = new Set(record.actions.map((entry) => entry.operationId)); const completed = record.actions.filter((entry) => entry.state === 'accepted'); const seenTxids = new Set(completed.map((entry) => entry.transactionId));
    if (seenIds.size !== record.actions.length || seenTxids.size !== completed.length) fail('LIVE_PERFORMANCE_JOURNAL_REJECTED', 'performance journal reuses an operation or transaction id');
    const invoke = async (item) => {
      const tokens = item.kind === 'deposit' ? ['deposit', '--data-home', item.dataHome, '--operation-id', item.operationId, '--json'] : ['withdraw', '--data-home', item.dataHome, '--operation-id', item.operationId, '--to', item.withdrawalAddress, '--json'];
      return strictAction(parseCli(await deps.runCommand(cliRequest(tokens)), `shieldkit ${item.kind} ${item.poolOrdinal + 1}.${item.ordinal}`), item.kind, item.operationId);
    };
    if (pending.length === 1) {
      const item = planned.get(pending[0].operationId); const action = await invoke(item);
      if (seenTxids.has(action.transactionId)) fail('LIVE_PERFORMANCE_RESULT_REJECTED', 'resumed warm performance action reuses a transaction id');
      record = await journal.update(Object.freeze({ ...record, actions: Object.freeze(record.actions.map((entry) => entry.operationId === item.operationId ? Object.freeze({ kind: item.kind, poolOrdinal: item.poolOrdinal, ordinal: item.ordinal, state: 'accepted', ...action }) : entry)) })); seenTxids.add(action.transactionId);
    }
    for (const item of plan) {
      if (seenIds.has(item.operationId)) continue;
      record = await journal.update(Object.freeze({ ...record, actions: Object.freeze([...record.actions, Object.freeze({ kind: item.kind, poolOrdinal: item.poolOrdinal, ordinal: item.ordinal, operationId: item.operationId, state: 'pending' })]) })); seenIds.add(item.operationId);
      const action = await invoke(item);
      if (seenTxids.has(action.transactionId)) fail('LIVE_PERFORMANCE_RESULT_REJECTED', 'warm performance evidence reuses a transaction id');
      record = await journal.update(Object.freeze({ ...record, actions: Object.freeze(record.actions.map((entry) => entry.operationId === item.operationId ? Object.freeze({ kind: item.kind, poolOrdinal: item.poolOrdinal, ordinal: item.ordinal, state: 'accepted', ...action }) : entry)) })); seenTxids.add(action.transactionId);
    }
    const deposits = record.actions.filter((entry) => entry.kind === 'deposit' && entry.state === 'accepted'); const withdrawals = record.actions.filter((entry) => entry.kind === 'withdraw' && entry.state === 'accepted'); const depositMetrics = metrics(deposits); const withdrawalMetrics = metrics(withdrawals); assertThresholds(depositMetrics); assertThresholds(withdrawalMetrics);
    const evidence = Object.freeze({ schema: V2_BETA_LIVE_PERFORMANCE_SCHEMA, scope: 'warm-performance-only-explicitly-unqualified', claims: Object.freeze({ confirmed: false, mined: false, productionQualified: false }), pools: Object.freeze(installed.map((entry) => Object.freeze({ receiptSha256: entry.receiptSha256 }))), samples: Object.freeze({ deposits: Object.freeze(deposits), withdrawals: Object.freeze(withdrawals) }), metrics: Object.freeze({ deposits: depositMetrics, withdrawals: withdrawalMetrics }), elapsedMs: deps.now() - started }); const serialized = JSON.stringify(evidence);
    if (/"(?:dataHome|privateKey|rawTransactionHex|witness|noteSecret|circuitInput)"/u.test(serialized)) fail('LIVE_PERFORMANCE_EVIDENCE_SECRET_REJECTED', 'performance evidence contains a private path or secret-bearing material');
    return Object.freeze({ evidence, evidencePath: await deps.writeEvidence(options.evidenceDirectory, evidence) });
  } finally { journal.close(); }
}
export async function runV2BetaLivePerformanceForTest(options, dependencies) { return run(options, dependencies); }
export async function runV2BetaLivePerformance(options) { return run(options, { now: performance.now.bind(performance), openJournal: openFileJournal, runCommand: async (request) => { const { spawn } = await import('node:child_process'); return new Promise((resolve, reject) => { const child = spawn(request.executable, request.args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); const stdout = []; const stderr = []; child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk))); child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk))); child.once('error', reject); child.once('close', (code) => resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') })); }); }, validateInstalledPool, writeEvidence: async (directory, evidence) => { const filename = path.join(directory, `v2-beta-live-performance-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}.json`); try { await writePrivateFile(filename, Buffer.from(`${canonicalizeJcs(evidence)}\n`, 'utf8'), 'performance evidence'); return filename; } catch (error) { fail('LIVE_PERFORMANCE_PATH_REJECTED', 'performance evidence cannot be safely written', { cause: error }); } } }); }
function usage() { throw new Error('usage: node v2-beta-live-performance.mjs --execute-live --evidence-dir <private-absolute-dir> --withdraw-to <bchtest-p2pkh> --pool-data-home <private-absolute-dir> [--pool-data-home <private-absolute-dir> ...]'); }
function parseArguments(tokens) { if (tokens[0] !== '--execute-live') usage(); const values = { poolDataHomes: [] }; for (let index = 1; index < tokens.length; index += 2) { const name = tokens[index]; const value = tokens[index + 1]; if (value === undefined) usage(); if (name === '--pool-data-home') values.poolDataHomes.push(value); else if (name === '--evidence-dir' && values.evidenceDirectory === undefined) values.evidenceDirectory = value; else if (name === '--withdraw-to' && values.withdrawalAddress === undefined) values.withdrawalAddress = value; else usage(); } if (values.evidenceDirectory === undefined || values.withdrawalAddress === undefined) usage(); return values; }
if (import.meta.main === true || (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) { if (process.version !== 'v22.23.1') throw new Error(`LIVE_PERFORMANCE_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`); const result = await runV2BetaLivePerformance(parseArguments(process.argv.slice(2))); process.stdout.write(`${JSON.stringify({ evidencePath: result.evidencePath, metrics: result.evidence.metrics, claims: result.evidence.claims })}\n`); }
