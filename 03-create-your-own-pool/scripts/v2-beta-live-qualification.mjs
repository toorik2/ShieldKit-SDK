#!/usr/bin/env node
/**
 * Operator-run, zero-confirmation semantic evidence for the public V2 beta
 * CLI. Installation is deliberately out of scope: a separately completed,
 * pinned installation receipt is verified before this driver does anything.
 * This is not a latency or release qualification.
 */
import { createHash } from 'node:crypto';
import { chmod, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpc } from '../packages/kit/chipnet-rpc.mjs';
import { loadV2BetaProductConfig } from '../packages/kit/v2/beta-product-config.mjs';
import { loadV2BetaProductArtifactInstallation } from '../packages/profile/v2/beta-product-artifact-installation.mjs';
import {
  V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY,
  V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA,
  loadV2BetaProductTrackedReleasePin,
} from '../packages/profile/v2/beta-product-offline-bootstrap.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  inspectV2BetaLiveActionEvidence,
  inspectV2BetaLivePoolRuntimeWork,
} from './v2-beta-live-action-evidence.mjs';
import { assertPrivateDirectory, assertPrivateFile, readPrivateUtf8, writePrivateFile } from './v2-beta-private-paths.mjs';

export const V2_BETA_LIVE_QUALIFICATION_SCHEMA = 'shieldkit-v2-beta-live-qualification-v2';
export const V2_BETA_CAPACITY = '100000';
const RUN_SCHEMA = 'shieldkit-v2-beta-live-qualification-run-v1';
const RUN_FILE = 'live-qualification-run.json';
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const VALIDATED_INPUTS = new WeakSet();

export class V2BetaLiveQualificationError extends Error {
  constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaLiveQualificationError'; this.code = code; }
}
const fail = (code, message, options = undefined) => { throw new V2BetaLiveQualificationError(code, message, options); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const finite = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('LIVE_QUALIFICATION_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('LIVE_QUALIFICATION_INVALID', `${label} has missing or unknown properties`);
  return value;
}
function canonicalAbsolute(value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) fail('LIVE_QUALIFICATION_PATH_REJECTED', `${label} must be a normalized absolute path`);
  return value;
}
async function privatePath(filename, label, kind) {
  try { canonicalAbsolute(filename, label); return kind === 'directory' ? await assertPrivateDirectory(filename, label) : await assertPrivateFile(filename, label); }
  catch (error) { fail('LIVE_QUALIFICATION_PATH_REJECTED', `${label} must be a current-user private canonical ${kind}`, { cause: error }); }
}
async function loadInputs(options) {
  exact(options, ['dataHome', 'evidenceDirectory', 'fundingUtxo', 'fundingWallet', 'withdrawalAddress'], 'live qualification options');
  await Promise.all([privatePath(options.dataHome, 'data home', 'directory'), privatePath(options.evidenceDirectory, 'evidence directory', 'directory'), privatePath(options.fundingWallet, 'funding wallet', 'file')]);
  const inputs = Object.freeze({ ...options, fundingUtxo: parseFundingOutpoint(options.fundingUtxo), withdrawalAddress: chipnetAddress(options.withdrawalAddress) });
  VALIDATED_INPUTS.add(inputs);
  return inputs;
}

/** Unit-test seam for the exact production argv-to-validated-input boundary. */
export async function loadV2BetaLiveQualificationInputsForTest(options) { return loadInputs(options); }

function chipnetAddress(value) { if (typeof value !== 'string' || !value.startsWith('bchtest:') || value.length < 10) fail('LIVE_QUALIFICATION_WALLET_REJECTED', 'withdrawal address must be a Chipnet cash address'); return value; }
export function parseFundingOutpoint(value) {
  if (typeof value !== 'string') fail('LIVE_QUALIFICATION_OUTPOINT_REJECTED', 'funding UTXO must be <lowercase-txid>:<vout>');
  const match = /^([0-9a-f]{64}):(0|[1-9][0-9]*)$/u.exec(value);
  if (match === null || !Number.isSafeInteger(Number(match[2])) || Number(match[2]) > 0xffff_ffff) fail('LIVE_QUALIFICATION_OUTPOINT_REJECTED', 'funding UTXO must be a canonical transaction outpoint');
  return Object.freeze({ txid: match[1], vout: Number(match[2]) });
}
export function sourceOutpointProvenanceSha256(outpoint) {
  if (!HASH.test(outpoint?.txid) || !Number.isSafeInteger(outpoint?.vout) || outpoint.vout < 0 || outpoint.vout > 0xffff_ffff) fail('LIVE_QUALIFICATION_OUTPOINT_REJECTED', 'source outpoint is malformed');
  return sha256(Buffer.from(`shieldkit-v2-beta-source-outpoint-v1:${outpoint.txid}:${outpoint.vout}`, 'utf8'));
}


function claims(value, label) { if (value?.confirmed !== false || value?.mined !== false || value?.productionQualified !== false) fail('LIVE_QUALIFICATION_FALSE_CLAIM_REJECTED', `${label} did not retain exact beta-only claims`); return Object.freeze({ confirmed: false, mined: false, productionQualified: false }); }
function positiveInteger(value, label) { if (!Number.isSafeInteger(value) || value <= 0) fail('LIVE_QUALIFICATION_RESULT_REJECTED', `${label} must be a positive safe integer`); return value; }
function strictAction(result, kind, operationId) {
  try {
    return inspectV2BetaLiveActionEvidence(result, { command: kind, operationId });
  } catch (error) {
    fail(
      'LIVE_QUALIFICATION_RESULT_REJECTED',
      `${kind} action evidence is incomplete or inconsistent`,
      { cause: error },
    );
  }
}
export async function inspectV2BetaLivePoolCreateEvidence(result, fundingOutpoint, rpc, { requireFreshLink = false } = {}) {
  if (!HASH.test(fundingOutpoint?.txid) || !Number.isSafeInteger(fundingOutpoint?.vout) || fundingOutpoint.vout < 0 || fundingOutpoint.vout > 0xffff_ffff) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool create lacks a canonical source outpoint');
  if (result?.schema !== 'shieldkit-v2-beta-product-pool-create-result-v1' || result.command !== 'pool-create' || result.status !== 'accepted-zero-conf-beta-unqualified' || typeof result.profileId !== 'string' || result.profileId.length === 0 || typeof result.operationId !== 'string' || result.operationId.length === 0 || result.capacity !== V2_BETA_CAPACITY || !HASH.test(result.instanceId) || !HASH.test(result.sourceTransactionId) || result.sourceTransactionId === fundingOutpoint.txid || !HASH.test(result.genesisTransactionId) || result.genesisTransactionId === result.sourceTransactionId || !HASH.test(result.zeroConfEvidenceSha256) || !HASH.test(result.actionFundingSetSha256) || result.actionFundingOutputs !== 10) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'one-invocation pool create did not expose a distinct bootstrap source and genesis transaction');
  claims(result.claims, 'pool create');
  if (result.claims.broadcasted !== true || result.rpcBackend !== 'layer1-bchn-chipnet' || result.rpcObservation?.backend !== result.rpcBackend || result.rpcObservation.genesis !== CHIPNET_GENESIS_HASH || result.rpcObservation.methodCounts?.testmempoolaccept !== 2 || result.rpcObservation.methodCounts.sendrawtransaction !== 2 || result.rpcObservation.methodCounts.getrawtransaction !== 2 || result.rpcObservation.methodCounts.gettxout !== 1 || !HASH.test(result.runtimeManifestSha256) || !HASH.test(result.runtimeMaterialSha256) || typeof result.runtimeLinkedDuringCommand !== 'boolean' || result.acceptance?.accepted !== true || result.acceptance.status !== 'accepted-zero-conf' || result.acceptance.evidence?.status !== 'accepted-zero-conf-beta-unqualified' || result.acceptance.evidence.claims?.broadcasted !== true || result.acceptance.evidence.claims?.mined !== false || result.acceptance.evidence.claims?.productionQualified !== false) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool create lacks accepted zero-conf, runtime, or exact two-transaction BCHN evidence');
  let runtimeWork;
  try { runtimeWork = inspectV2BetaLivePoolRuntimeWork(result.runtimeWork, result.runtimeLinkedDuringCommand); }
  catch (error) { fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool create runtime work is missing, hidden, or inconsistent', { cause: error }); }
  if (result.transactions?.source?.transactionId !== result.sourceTransactionId || !HASH.test(result.transactions?.source?.rawTransactionSha256) || !positiveInteger(result.transactions?.source?.serializedBytes, 'pool source bytes') || result.transactions?.genesis?.transactionId !== result.genesisTransactionId || !positiveInteger(result.transactions?.genesis?.serializedBytes, 'pool genesis bytes') || !DECIMAL.test(result.transactions?.genesis?.feeSats) || !DECIMAL.test(result.transactions?.genesis?.feeRateSatsPerByte)) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool create lacks exact transaction byte/fee evidence');
  let source; let genesis;
  try { [source, genesis] = await Promise.all([rpc.getrawtransaction(result.sourceTransactionId, false), rpc.getrawtransaction(result.genesisTransactionId, false)]); } catch (error) { fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'BCHN could not read back the pool source/genesis package', { cause: error }); }
  try {
    const sourceTx = parseV2RawTransaction(source); const genesisTx = parseV2RawTransaction(genesis);
    if (sourceTx.txid !== result.sourceTransactionId || sourceTx.inputs.length !== 1 || sourceTx.inputs[0].outpoint.txid !== fundingOutpoint.txid || sourceTx.inputs[0].outpoint.vout !== fundingOutpoint.vout || sourceTx.bytes.length !== result.transactions.source.serializedBytes || sha256(Buffer.from(source, 'hex')) !== result.transactions.source.rawTransactionSha256 || genesisTx.txid !== result.genesisTransactionId || genesisTx.inputs.length !== 1 || genesisTx.inputs[0].outpoint.txid !== result.sourceTransactionId || genesisTx.inputs[0].outpoint.vout !== 0 || genesisTx.bytes.length !== result.transactions.genesis.serializedBytes) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool source/genesis readback does not bind the requested source outpoint to bootstrap output 0');
  } catch (error) { if (error instanceof V2BetaLiveQualificationError) throw error; fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool source/genesis package could not be parsed exactly', { cause: error }); }
  for (const name of ['funding', 'genesis', 'exactReadback', 'atomicCommit', 'actionStoreBootstrap', 'commandTotal']) if (!finite(result.timingsMs?.[name])) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', `pool create timing ${name} is missing`);
  if (result.transactions.genesis.bch2026StandardVmAccepted !== true || !Array.isArray(result.transactions.genesis.inputMetrics)) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'pool create lacks its available genesis BCH VM evidence');
  if (requireFreshLink !== false && result.runtimeLinkedDuringCommand !== true) fail('LIVE_QUALIFICATION_POOL_CREATE_REJECTED', 'fresh pool-create performance sample did not measure its required instance specialization');
  return Object.freeze({ instanceId: result.instanceId, sourceTransactionId: result.sourceTransactionId, genesisTransactionId: result.genesisTransactionId, zeroConfEvidenceSha256: result.zeroConfEvidenceSha256, actionFundingOutputs: 10, actionFundingSetSha256: result.actionFundingSetSha256, transactions: result.transactions, acceptance: result.acceptance, rpcObservation: result.rpcObservation, runtime: Object.freeze({ runtimeManifestSha256: result.runtimeManifestSha256, runtimeMaterialSha256: result.runtimeMaterialSha256, linkedDuringCommand: result.runtimeLinkedDuringCommand, work: runtimeWork }), timingsMs: result.timingsMs, claims: claims(result.claims, 'pool create') });
}

function cliRequest(tokens) { return Object.freeze({ executable: process.execPath, args: [path.resolve(import.meta.dirname, 'shieldkit.mjs'), ...tokens], literal: Object.freeze(['shieldkit', ...tokens]) }); }
function parseCli(value, label) { if (value?.code !== 0) fail('LIVE_QUALIFICATION_CLI_FAILED', `${label} exited unsuccessfully`); try { const body = JSON.parse(value.stdout); if (body?.ok !== true) fail('LIVE_QUALIFICATION_CLI_FAILED', `${label} did not return success JSON`); claims(body, label); return body.result; } catch (error) { if (error instanceof V2BetaLiveQualificationError) throw error; fail('LIVE_QUALIFICATION_CLI_FAILED', `${label} did not return JSON`, { cause: error }); } }

async function writeCanonicalPrivate(filename, value) {
  try { await writePrivateFile(filename, Buffer.from(canonicalizeJcs(value), 'utf8'), 'qualification journal'); }
  catch (error) { fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'qualification journal cannot be safely written', { cause: error }); }
}
function validateRun(value) {
  exact(value, ['actions', 'installReceiptSha256', 'pool', 'poolCreateCommandDurationMs', 'schema', 'sourceOutpointProvenanceSha256', 'state'], 'qualification run journal');
  if (value.schema !== RUN_SCHEMA || !HASH.test(value.installReceiptSha256) || !HASH.test(value.sourceOutpointProvenanceSha256) || !['pool-create-started', 'pool-created', 'completed'].includes(value.state) || !Array.isArray(value.actions) || (value.poolCreateCommandDurationMs !== null && !finite(value.poolCreateCommandDurationMs))) fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'qualification run journal is malformed');
  if ((value.state === 'pool-created' || value.state === 'completed') && value.pool === null) fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'completed qualification journal lacks pool create evidence');
  return value;
}
async function openFileRunJournal({ dataDirectory }) {
  const directory = path.join(dataDirectory, 'qualification'); await mkdir(directory, { mode: 0o700 }).catch((error) => { if (error?.code !== 'EEXIST') throw error; }); await chmod(directory, 0o700); await privatePath(directory, 'qualification journal directory', 'directory'); const filename = path.join(directory, RUN_FILE);
  let record = null;
  try { record = validateRun(JSON.parse(await readPrivateUtf8(filename, 'qualification run journal'))); } catch (error) { if (error?.code !== 'ENOENT') fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'qualification run journal must be private', { cause: error }); }
  const save = async () => writeCanonicalPrivate(filename, record);
  return Object.freeze({ load: () => record, async prepare(value) { if (record !== null) fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'run journal already exists'); record = validateRun(value); await save(); return record; }, async update(next) { record = validateRun(next); await save(); return record; }, close() {} });
}

export async function validateV2BetaPinnedInstall({ dataHome }) {
  const loaded = loadV2BetaProductConfig({ dataHome }); const installation = await loadV2BetaProductArtifactInstallation({ productDataDirectory: loaded.config.dataDirectory }); const pin = await loadV2BetaProductTrackedReleasePin();
  const journalPath = path.join(loaded.config.dataDirectory, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY, 'journal.json'); let journal;
  try { journal = JSON.parse(await readPrivateUtf8(journalPath, 'offline install journal')); } catch (error) { fail('LIVE_QUALIFICATION_INSTALL_REQUIRED', 'a separately completed pinned offline install journal is required', { cause: error }); }
  if (journal?.schema !== V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA || journal.status !== 'committed' || journal.releaseId !== pin.releaseId || journal.releaseManifestSha256 !== pin.releaseManifestSha256 || journal.receiptSha256 !== installation.receiptSha256) fail('LIVE_QUALIFICATION_INSTALL_REQUIRED', 'installed artifact receipt does not match the pinned offline-install journal');
  return Object.freeze({ dataDirectory: loaded.config.dataDirectory, receiptSha256: installation.receiptSha256, releaseId: pin.releaseId, releaseManifestSha256: pin.releaseManifestSha256 });
}
function assertDeps(value) { exact(value, ['now', 'openRunJournal', 'rpc', 'runCommand', 'validateInstall', 'writeEvidence'], 'live qualification dependencies'); for (const name of ['now', 'openRunJournal', 'runCommand', 'validateInstall', 'writeEvidence']) if (typeof value[name] !== 'function') fail('LIVE_QUALIFICATION_INVALID', `dependency ${name} must be a function`); if (typeof value.rpc?.getrawtransaction !== 'function') fail('LIVE_QUALIFICATION_INVALID', 'rpc.getrawtransaction must be a function'); return value; }
function summaryEvidence(record, install, elapsedMs) { return Object.freeze({ schema: V2_BETA_LIVE_QUALIFICATION_SCHEMA, scope: 'semantic-five-by-five-only-not-performance-qualification', claims: Object.freeze({ confirmed: false, mined: false, productionQualified: false }), capacity: V2_BETA_CAPACITY, install: Object.freeze({ receiptSha256: install.receiptSha256, releaseId: install.releaseId, releaseManifestSha256: install.releaseManifestSha256 }), poolCreate: Object.freeze({ commandDurationMs: record.poolCreateCommandDurationMs, sourceOutpointProvenanceSha256: record.sourceOutpointProvenanceSha256 }), pool: record.pool, deposits: Object.freeze(record.actions.filter((entry) => entry.kind === 'deposit')), withdrawals: Object.freeze(record.actions.filter((entry) => entry.kind === 'withdraw')), timingMs: elapsedMs }); }

/** Testable core. Production passes only real CLI/RPC/install/journal dependencies. */
export async function runV2BetaLiveQualification(options, dependencies) {
  const inputs = options.wallet !== undefined || VALIDATED_INPUTS.has(options) ? options : await loadInputs(options); const deps = assertDeps(dependencies); const started = deps.now(); const install = await deps.validateInstall({ dataHome: inputs.dataHome }); if (!HASH.test(install?.receiptSha256) || typeof install.dataDirectory !== 'string') fail('LIVE_QUALIFICATION_INSTALL_REQUIRED', 'pinned installation receipt validation failed'); const journal = await deps.openRunJournal({ dataDirectory: install.dataDirectory });
  const callCli = async (tokens, label) => parseCli(await deps.runCommand(cliRequest(tokens)), label);
  try {
    let record = journal.load();
    const provenance = sourceOutpointProvenanceSha256(inputs.fundingUtxo);
    if (record === null) record = await journal.prepare(Object.freeze({ schema: RUN_SCHEMA, state: 'pool-create-started', installReceiptSha256: install.receiptSha256, sourceOutpointProvenanceSha256: provenance, poolCreateCommandDurationMs: null, pool: null, actions: [] }));
    if (record.installReceiptSha256 !== install.receiptSha256) fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'run journal belongs to a different installed receipt');
    if (record.sourceOutpointProvenanceSha256 !== provenance) fail('LIVE_QUALIFICATION_JOURNAL_REJECTED', 'run journal belongs to a different source outpoint');
    if (record.state === 'pool-create-started' && record.pool === null && record.poolCreateCommandDurationMs === null) {
      const commandStarted = deps.now();
      const created = await inspectV2BetaLivePoolCreateEvidence(await callCli(['pool', 'create', '--data-home', inputs.dataHome, '--funding-wallet', inputs.fundingWallet, '--funding-utxo', `${inputs.fundingUtxo.txid}:${inputs.fundingUtxo.vout}`, '--json'], 'shieldkit pool create'), inputs.fundingUtxo, deps.rpc);
      record = await journal.update(Object.freeze({ ...record, state: 'pool-created', pool: created, poolCreateCommandDurationMs: deps.now() - commandStarted }));
    } else if (record.state === 'pool-create-started') fail('LIVE_QUALIFICATION_RECONCILIATION_REQUIRED', 'pool create may already have been invoked; inspect the chain before starting a new fresh qualification');
    for (const kind of ['deposit', 'withdraw']) for (let ordinal = 1; ordinal <= 5; ordinal += 1) {
      if (record.actions.some((entry) => entry.kind === kind && entry.ordinal === ordinal)) continue;
      const operationId = `live5x5.${record.sourceOutpointProvenanceSha256.slice(0, 16)}.${kind}.${String(ordinal).padStart(2, '0')}`;
      const tokens = kind === 'deposit' ? ['deposit', '--data-home', inputs.dataHome, '--operation-id', operationId, '--json'] : ['withdraw', '--data-home', inputs.dataHome, '--operation-id', operationId, '--to', inputs.withdrawalAddress, '--json'];
      const action = strictAction(await callCli(tokens, `shieldkit ${kind} ${ordinal}`), kind, operationId);
      record = await journal.update(Object.freeze({ ...record, actions: Object.freeze([...record.actions, Object.freeze({ kind, ordinal, ...action })]) }));
    }
    record = record.state === 'completed' ? record : await journal.update(Object.freeze({ ...record, state: 'completed' }));
    const evidence = summaryEvidence(record, install, deps.now() - started); const serialized = JSON.stringify(evidence);
    if (serialized.includes(inputs.fundingWallet) || /"(?:privateKey(?:Hex)?|rawTransactionHex|noteSecret|circuitInput|fundingUtxo|fundingWallet)"/u.test(serialized)) fail('LIVE_QUALIFICATION_EVIDENCE_SECRET_REJECTED', 'qualification evidence would contain a wallet path, source outpoint, secret, or retained raw transaction material');
    return Object.freeze({ evidence, evidencePath: await deps.writeEvidence(inputs.evidenceDirectory, evidence) });
  } finally { journal.close(); }
}

async function defaultWriteEvidence(directory, evidence) { const filename = path.join(directory, `v2-beta-live-qualification-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}.json`); try { await writePrivateFile(filename, Buffer.from(`${canonicalizeJcs(evidence)}\n`, 'utf8'), 'qualification evidence'); return filename; } catch (error) { fail('LIVE_QUALIFICATION_PATH_REJECTED', 'qualification evidence cannot be safely written', { cause: error }); } }
function usage() { throw new Error('usage: node v2-beta-live-qualification.mjs --execute-live --data-home <private-absolute-dir> --evidence-dir <private-absolute-dir> --funding-wallet <private-canonical-wallet-json> --funding-utxo <txid:vout> --withdraw-to <bchtest:cashaddr>'); }
export function parseV2BetaLiveQualificationArguments(tokens) { const values = {}; const names = new Map([['--data-home', 'dataHome'], ['--evidence-dir', 'evidenceDirectory'], ['--funding-wallet', 'fundingWallet'], ['--funding-utxo', 'fundingUtxo'], ['--withdraw-to', 'withdrawalAddress']]); if (tokens[0] !== '--execute-live') usage(); for (let index = 1; index < tokens.length; index += 2) { const name = names.get(tokens[index]); const value = tokens[index + 1]; if (name === undefined || value === undefined || Object.hasOwn(values, name)) usage(); values[name] = value; } if (Object.keys(values).length !== names.size) usage(); return Object.freeze(values); }
if (import.meta.main === true || (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) { if (process.version !== 'v22.23.1') throw new Error(`LIVE_QUALIFICATION_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`); const options = await loadInputs(parseV2BetaLiveQualificationArguments(process.argv.slice(2))); const result = await runV2BetaLiveQualification(options, { now: performance.now.bind(performance), openRunJournal: openFileRunJournal, rpc: await createLayer1BchnChipnetRpc(), runCommand: async (request) => { const { spawn } = await import('node:child_process'); return new Promise((resolve, reject) => { const child = spawn(request.executable, request.args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); const stdout = []; const stderr = []; child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk))); child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk))); child.once('error', reject); child.once('close', (code) => resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') })); }); }, validateInstall: validateV2BetaPinnedInstall, writeEvidence: defaultWriteEvidence }); process.stdout.write(`${JSON.stringify({ evidencePath: result.evidencePath, claims: result.evidence.claims, scope: result.evidence.scope })}\n`); }
