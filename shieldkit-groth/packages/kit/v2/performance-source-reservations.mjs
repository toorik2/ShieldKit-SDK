/**
 * Private, one-shot reservation of the twenty independent bootstrap UTXOs
 * required by the V2 beta fresh-pool-create performance qualification.
 *
 * This deliberately has no wallet, signing, or broadcast capability. It
 * validates an operator-authored plan against the fixed layer1 BCHN Chipnet
 * capability, then publishes a private immutable ledger with link(2). The
 * ledger is a local concurrency/reuse guard, not a chain reservation.
 */
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, link, lstat, mkdir, open, realpath, rm, unlink,
} from 'node:fs/promises';
import path from 'node:path';

import {
  assertChipnetProductRpc,
  createPublicChipnetFulcrumRpc,
} from '../chipnet-rpc.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  createV2BetaOperatorSourceLeaseId,
  inspectV2BetaOperatorSourceRegistry,
  reserveV2BetaPerformanceSourcesInRegistry,
  transitionV2BetaOperatorSources,
} from './operator-source-registry.mjs';

export const V2_BETA_PERFORMANCE_SOURCE_PLAN_SCHEMA =
  'shieldkit-v2-beta-pool-create-performance-source-plan-v1';
export const V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA =
  'shieldkit-v2-beta-pool-create-performance-source-reservation-ledger-v2';
export const V2_BETA_PRIVATE_SOURCE_USAGE_SCHEMA =
  'shieldkit-v2-beta-private-source-usage-v1';
export const V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME =
  'pool-create-performance-source-reservations.json';
export const V2_BETA_POOL_CREATE_PERFORMANCE_SOURCE_COUNT = 20;
export const V2_BETA_POOL_CREATE_MINIMUM_SOURCE_SATS = 53_006_565n;

const HASH = /^[0-9a-f]{64}$/u;
const OUTPOINT = /^([0-9a-f]{64}):(0|[1-9][0-9]*)$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/u;
const MAX_PLAN_LIFETIME_MS = 30 * 60 * 1000;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const CURRENT_UID = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;

export class V2BetaPerformanceSourceReservationError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaPerformanceSourceReservationError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaPerformanceSourceReservationError(code, message, options);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('PERFORMANCE_SOURCE_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('PERFORMANCE_SOURCE_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function absolute(value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value)
    || path.normalize(value) !== value) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} must be a normalized absolute path`);
  }
  return value;
}

function requireCurrentOwner(stat, label) {
  if (CURRENT_UID === null || stat.uid !== CURRENT_UID) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} must be owned by the current user`);
  }
}

function identity(stat) {
  return Object.freeze({
    dev: stat.dev.toString(), ino: stat.ino.toString(), nlink: stat.nlink.toString(),
    mode: stat.mode.toString(), uid: stat.uid.toString(), size: stat.size.toString(),
    mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString(),
  });
}

function sameIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

async function ownerControlledParent(directory, label) {
  const parent = path.dirname(directory);
  const stat = await lstat(parent, { bigint: true }).catch((error) => fail(
    'PERFORMANCE_SOURCE_PATH_REJECTED', `${label} parent is unavailable`, { cause: error },
  ));
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.nlink < 1n
    || (stat.mode & 0o022n) !== 0n || await realpath(parent) !== parent) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} parent must be a canonical owner-controlled directory`);
  }
  requireCurrentOwner(stat, `${label} parent`);
}

async function strictPrivateFile(filename, label) {
  const target = absolute(filename, label);
  await ownerControlledParent(target, label);
  const before = await lstat(target, { bigint: true }).catch((error) => fail(
    'PERFORMANCE_SOURCE_PATH_REJECTED', `${label} is unavailable`, { cause: error },
  ));
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || (before.mode & 0o777n) !== 0o600n) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} must be a private 0600 single-link regular file`);
  }
  requireCurrentOwner(before, label);
  if (await realpath(target) !== target) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} must be canonical and not a symlink`);
  }
  let handle;
  try {
    handle = await open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const named = await lstat(target, { bigint: true });
    if (!sameIdentity(identity(before), identity(opened))
      || !sameIdentity(identity(opened), identity(after))
      || !sameIdentity(identity(opened), identity(named))) {
      fail('PERFORMANCE_SOURCE_PATH_RACE', `${label} changed while being read`);
    }
    return Buffer.from(bytes);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function strictPrivateDirectory(directory, label, { create = false } = {}) {
  const target = absolute(directory, label);
  await ownerControlledParent(target, label);
  if (create) {
    await mkdir(target, { mode: 0o700 }).catch((error) => {
      if (error?.code !== 'EEXIST') fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} cannot be created`, { cause: error });
    });
  }
  // Never chmod a path before lstat: chmod follows symlinks. Existing paths
  // must already satisfy the private-directory contract; newly created paths
  // use an exact 0700 creation mode.
  const stat = await lstat(target, { bigint: true }).catch((error) => fail(
    'PERFORMANCE_SOURCE_PATH_REJECTED', `${label} is unavailable`, { cause: error },
  ));
  // Directories cannot safely be constrained to one specific link count: a
  // normal empty POSIX directory has nlink=2 while overlay filesystems report
  // nlink=1. Directory hard-links are forbidden by POSIX; reject the only
  // unsafe indirection (symlinks) and require a live inode instead.
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.nlink < 1n
    || (stat.mode & 0o777n) !== 0o700n || await realpath(target) !== target) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', `${label} must be a canonical private 0700 directory`);
  }
  requireCurrentOwner(stat, label);
  return target;
}

function parseCanonicalJson(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch (error) { fail('PERFORMANCE_SOURCE_INVALID', `${label} is not valid JSON`, { cause: error }); }
  let canonical;
  try { canonical = Buffer.from(canonicalizeJcs(value), 'utf8'); }
  catch (error) { fail('PERFORMANCE_SOURCE_INVALID', `${label} cannot be canonicalized`, { cause: error }); }
  if (!bytes.equals(canonical)) {
    fail('PERFORMANCE_SOURCE_INVALID', `${label} must use exact RFC 8785 canonical JSON without trailing bytes`);
  }
  return value;
}

function release(value, label) {
  exact(value, ['releaseId', 'releaseManifestSha256'], label);
  if (typeof value.releaseId !== 'string' || value.releaseId.length === 0
    || !HASH.test(value.releaseManifestSha256)) {
    fail('PERFORMANCE_SOURCE_INVALID', `${label} is malformed`);
  }
  return Object.freeze({ ...value });
}

function outpoint(value, label) {
  if (typeof value !== 'string') fail('PERFORMANCE_SOURCE_INVALID', `${label} must be a canonical outpoint`);
  const match = OUTPOINT.exec(value);
  if (match === null || !Number.isSafeInteger(Number(match[2])) || Number(match[2]) > 0xffff_ffff) {
    fail('PERFORMANCE_SOURCE_INVALID', `${label} must be a canonical outpoint`);
  }
  return Object.freeze({ text: value, txid: match[1], vout: Number(match[2]) });
}

function sourceProvenanceSha256(value) {
  return sha256(Buffer.from(`shieldkit-v2-beta-source-outpoint-v1:${value.txid}:${value.vout}`, 'utf8'));
}

function source(value, index) {
  exact(value, [
    'dataHome', 'installationReceiptSha256', 'lockingBytecodeHex', 'ordinal',
    'outpoint', 'valueSats',
  ], `source ${index + 1}`);
  if (!Number.isSafeInteger(value.ordinal) || value.ordinal !== index + 1
    || !HASH.test(value.installationReceiptSha256) || !P2PKH.test(value.lockingBytecodeHex)
    || typeof value.valueSats !== 'string' || !DECIMAL.test(value.valueSats)) {
    fail('PERFORMANCE_SOURCE_INVALID', `source ${index + 1} is malformed`);
  }
  const parsedOutpoint = outpoint(value.outpoint, `source ${index + 1}.outpoint`);
  const valueSats = BigInt(value.valueSats);
  if (valueSats < V2_BETA_POOL_CREATE_MINIMUM_SOURCE_SATS || valueSats > MAX_MONEY_SATS) {
    fail('PERFORMANCE_SOURCE_INSUFFICIENT_VALUE', `source ${index + 1} is below the minimum bootstrap value`);
  }
  return Object.freeze({
    ordinal: value.ordinal,
    dataHome: absolute(value.dataHome, `source ${index + 1}.dataHome`),
    installationReceiptSha256: value.installationReceiptSha256,
    lockingBytecodeHex: value.lockingBytecodeHex,
    outpoint: parsedOutpoint,
    valueSats,
  });
}

export function parseV2BetaPerformanceSourcePlan(bytes, now = Date.now()) {
  if (!(bytes instanceof Uint8Array)) fail('PERFORMANCE_SOURCE_INVALID', 'source plan must be bytes');
  const value = parseCanonicalJson(Buffer.from(bytes), 'source plan');
  exact(value, ['createdAtUnixMs', 'expiresAtUnixMs', 'release', 'schema', 'sources'], 'source plan');
  if (value.schema !== V2_BETA_PERFORMANCE_SOURCE_PLAN_SCHEMA
    || !Number.isSafeInteger(value.createdAtUnixMs) || !Number.isSafeInteger(value.expiresAtUnixMs)
    || !Number.isSafeInteger(now) || value.expiresAtUnixMs <= value.createdAtUnixMs
    || value.expiresAtUnixMs - value.createdAtUnixMs > MAX_PLAN_LIFETIME_MS
    || now < value.createdAtUnixMs || now > value.expiresAtUnixMs) {
    fail('PERFORMANCE_SOURCE_PLAN_STALE', 'source plan is stale, future-dated, or has an unsafe lifetime');
  }
  if (!Array.isArray(value.sources) || value.sources.length !== V2_BETA_POOL_CREATE_PERFORMANCE_SOURCE_COUNT) {
    fail('PERFORMANCE_SOURCE_INVALID', 'source plan must contain exactly twenty sources');
  }
  const sources = value.sources.map(source);
  const duplicate = (items) => new Set(items).size !== items.length;
  if (duplicate(sources.map((entry) => entry.dataHome))
    || duplicate(sources.map((entry) => entry.installationReceiptSha256))
    || duplicate(sources.map((entry) => entry.outpoint.text))) {
    fail('PERFORMANCE_SOURCE_DUPLICATE', 'source plan reuses a data home, receipt, or outpoint');
  }
  return Object.freeze({
    bytes: Buffer.from(bytes), sha256: sha256(bytes), createdAtUnixMs: value.createdAtUnixMs,
    expiresAtUnixMs: value.expiresAtUnixMs, release: release(value.release, 'source plan release'),
    sources: Object.freeze(sources),
  });
}

function sourceUsageOutpoints(value, label) {
  exact(value, ['release', 'schema', 'sourceOutpoints'], label);
  if (value.schema !== V2_BETA_PRIVATE_SOURCE_USAGE_SCHEMA || !Array.isArray(value.sourceOutpoints)) {
    fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} is not a supported private source usage record`);
  }
  release(value.release, `${label}.release`);
  const items = value.sourceOutpoints.map((entry, index) => outpoint(entry, `${label}.sourceOutpoints[${index}]`));
  if (new Set(items.map((entry) => entry.text)).size !== items.length) {
    fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} contains duplicate outpoints`);
  }
  return items;
}

function ledgerRecord(value, label, now = undefined) {
  exact(value, [
    'createdAtUnixMs', 'expiresAtUnixMs', 'leaseId', 'registryClaimSha256', 'release', 'runId',
    'schema', 'sourcePlanSha256', 'sources',
  ], label);
  if (value.schema !== V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA
    || !Number.isSafeInteger(value.createdAtUnixMs) || !Number.isSafeInteger(value.expiresAtUnixMs)
    || !HASH.test(value.sourcePlanSha256) || !HASH.test(value.registryClaimSha256)
    || typeof value.leaseId !== 'string' || typeof value.runId !== 'string'
    || !Array.isArray(value.sources) || value.expiresAtUnixMs <= value.createdAtUnixMs
    || value.expiresAtUnixMs - value.createdAtUnixMs > MAX_PLAN_LIFETIME_MS
    || (now !== undefined && (!Number.isSafeInteger(now) || now < value.createdAtUnixMs || now > value.expiresAtUnixMs))) {
    fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} is malformed`);
  }
  const parsedRelease = release(value.release, `${label}.release`);
  if (value.sources.length !== V2_BETA_POOL_CREATE_PERFORMANCE_SOURCE_COUNT) {
    fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} does not retain twenty sources`);
  }
  const sources = value.sources.map((entry, index) => {
    exact(entry, [
      'dataHome', 'installationReceiptSha256', 'lockingBytecodeHex', 'ordinal', 'outpoint',
      'rawTransactionSha256', 'valueSats',
    ], `${label}.sources[${index}]`);
    if (!Number.isSafeInteger(entry.ordinal) || entry.ordinal !== index + 1
      || !HASH.test(entry.installationReceiptSha256) || !P2PKH.test(entry.lockingBytecodeHex)
      || !HASH.test(entry.rawTransactionSha256) || typeof entry.valueSats !== 'string'
      || !DECIMAL.test(entry.valueSats)) {
      fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label}.sources[${index}] is malformed`);
    }
    return Object.freeze({
      ordinal: entry.ordinal,
      dataHome: absolute(entry.dataHome, `${label}.sources[${index}].dataHome`),
      installationReceiptSha256: entry.installationReceiptSha256,
      lockingBytecodeHex: entry.lockingBytecodeHex,
      outpoint: outpoint(entry.outpoint, `${label}.sources[${index}].outpoint`),
      rawTransactionSha256: entry.rawTransactionSha256,
      valueSats: entry.valueSats,
    });
  });
  if (new Set(sources.map((entry) => entry.dataHome)).size !== sources.length
    || new Set(sources.map((entry) => entry.installationReceiptSha256)).size !== sources.length
    || new Set(sources.map((entry) => entry.outpoint.text)).size !== sources.length) {
    fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} contains duplicate outpoints`);
  }
  return Object.freeze({
    createdAtUnixMs: value.createdAtUnixMs, expiresAtUnixMs: value.expiresAtUnixMs,
    release: parsedRelease, sourcePlanSha256: value.sourcePlanSha256,
    leaseId: value.leaseId, runId: value.runId, registryClaimSha256: value.registryClaimSha256,
    sources: Object.freeze(sources),
  });
}

function evidenceProvenances(value, label) {
  // The accepted evidence formats carry only domain-separated outpoint hashes,
  // never raw outpoints. They are still sufficient to catch reuse.
  if (value?.schema === 'shieldkit-v2-beta-live-qualification-v6') {
    if (!HASH.test(value?.poolCreate?.sourceOutpointProvenanceSha256)) {
      fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} semantic evidence is malformed`);
    }
    return [value.poolCreate.sourceOutpointProvenanceSha256];
  }
  if (value?.schema === 'shieldkit-v2-beta-live-pool-create-performance-journal-v3') {
    if (!Array.isArray(value.samples)) fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} journal is malformed`);
    return value.samples.flatMap((entry, index) => {
      if (entry?.sourceOutpointProvenanceSha256 === undefined) return [];
      if (!HASH.test(entry.sourceOutpointProvenanceSha256)) fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label}.samples[${index}] is malformed`);
      return [entry.sourceOutpointProvenanceSha256];
    });
  }
  if (value?.schema === 'shieldkit-v2-beta-live-pool-create-performance-v5') {
    if (!Array.isArray(value.pools)) fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} performance evidence is malformed`);
    return value.pools.map((entry, index) => {
      if (!HASH.test(entry?.sourceOutpointProvenanceSha256)) fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label}.pools[${index}] is malformed`);
      return entry.sourceOutpointProvenanceSha256;
    });
  }
  return null;
}

export function parseV2BetaPerformanceExistingPrivateInput(bytes, label = 'existing private input') {
  if (!(bytes instanceof Uint8Array)) fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} must be bytes`);
  const value = parseCanonicalJson(Buffer.from(bytes), label);
  let outpoints = [];
  let provenances = [];
  if (value?.schema === V2_BETA_PRIVATE_SOURCE_USAGE_SCHEMA) {
    outpoints = sourceUsageOutpoints(value, label);
  } else if (value?.schema === V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA) {
    outpoints = ledgerRecord(value, label).sources.map((entry) => entry.outpoint);
  } else {
    const extracted = evidenceProvenances(value, label);
    if (extracted === null) {
      fail('PERFORMANCE_SOURCE_EXISTING_INPUT_REJECTED', `${label} has an unsupported schema`);
    }
    provenances = extracted;
  }
  return Object.freeze({
    sha256: sha256(bytes), outpoints: Object.freeze(outpoints), provenances: Object.freeze(provenances),
  });
}

function observedSatoshis(value) {
  if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) return BigInt(value.valueSatoshis);
  if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) {
    const sats = Math.round(value.value * 1e8);
    if (Number.isSafeInteger(sats) && sats / 1e8 === value.value) return BigInt(sats);
  }
  return null;
}

function observedTokenlessP2pkh(value, expectedLockingBytecodeHex, expectedValueSats) {
  const actualValue = observedSatoshis(value);
  const lockingBytecodeHex = value?.scriptPubKey?.hex;
  const hasToken = value?.tokenData !== undefined && value.tokenData !== null
    || value?.token !== undefined && value.token !== null;
  return actualValue === expectedValueSats
    && lockingBytecodeHex === expectedLockingBytecodeHex
    && !hasToken;
}

async function authenticateSource(entry, rpc) {
  let raw; let unspent;
  try {
    [raw, unspent] = await Promise.all([
      rpc.getrawtransaction(entry.outpoint.txid, false),
      rpc.gettxout(entry.outpoint.txid, entry.outpoint.vout),
    ]);
  } catch (error) {
    fail('PERFORMANCE_SOURCE_CHAIN_UNAVAILABLE', `source ${entry.ordinal} cannot be read from BCHN`, { cause: error });
  }
  if (typeof raw !== 'string' || unspent === null) {
    fail('PERFORMANCE_SOURCE_SPENT_OR_MISSING', `source ${entry.ordinal} is spent or missing`);
  }
  let transaction; let output;
  try {
    transaction = parseV2RawTransaction(raw);
    output = transaction.outputs[entry.outpoint.vout] === undefined ? null
      : parseSerializedSourceOutput(transaction.outputs[entry.outpoint.vout].serializedHex);
  } catch (error) {
    fail('PERFORMANCE_SOURCE_CHAIN_MALFORMED', `source ${entry.ordinal} raw transaction is malformed`, { cause: error });
  }
  if (transaction.txid !== entry.outpoint.txid || output === null
    || output.token !== null || output.lockingBytecodeHex !== entry.lockingBytecodeHex
    || output.valueSatoshis !== entry.valueSats
    || output.valueSatoshis < V2_BETA_POOL_CREATE_MINIMUM_SOURCE_SATS
    || !observedTokenlessP2pkh(unspent, entry.lockingBytecodeHex, entry.valueSats)) {
    fail('PERFORMANCE_SOURCE_AUTHENTICATION_REJECTED', `source ${entry.ordinal} is tokenized, wrong-locked, wrong-valued, or changed`);
  }
  return Object.freeze({ rawTransactionSha256: sha256(Buffer.from(raw, 'hex')) });
}

/** Isolated unit-test seam for exact raw-output plus gettxout authentication. */
export async function authenticateV2BetaPerformanceSourceForTest(entry, rpc) {
  return authenticateSource(entry, rpc);
}

function assertDependencies(dependencies) {
  exact(dependencies, ['authenticateRpc', 'claimRegistry', 'now', 'readExistingLedger', 'readPrivateFile', 'validateInstall', 'writeLedger'], 'reservation dependencies');
  for (const name of ['authenticateRpc', 'claimRegistry', 'now', 'readExistingLedger', 'readPrivateFile', 'validateInstall', 'writeLedger']) {
    if (typeof dependencies[name] !== 'function') fail('PERFORMANCE_SOURCE_INVALID', `dependency ${name} must be a function`);
  }
  return dependencies;
}

function assertResumableLedger(ledger, plan, runId) {
  if (ledger === null || typeof ledger !== 'object'
    || ledger.sourcePlanSha256 !== plan.sha256 || ledger.runId !== runId
    || canonicalizeJcs(ledger.release) !== canonicalizeJcs(plan.release)
    || !Array.isArray(ledger.sources) || ledger.sources.length !== plan.sources.length
    || ledger.sources.some((entry, index) => entry.ordinal !== plan.sources[index].ordinal
      || entry.outpoint.text !== plan.sources[index].outpoint.text
      || entry.lockingBytecodeHex !== plan.sources[index].lockingBytecodeHex
      || entry.valueSats !== plan.sources[index].valueSats.toString()
      || entry.dataHome !== plan.sources[index].dataHome
      || entry.installationReceiptSha256 !== plan.sources[index].installationReceiptSha256)) {
    fail('PERFORMANCE_SOURCE_RESUME_REJECTED', 'existing immutable ledger does not exactly bind this reservation plan and run');
  }
  return ledger;
}

function candidateLedger(plan, authenticatedSources, registryClaim, now) {
  return Object.freeze({
    schema: V2_BETA_PERFORMANCE_SOURCE_LEDGER_SCHEMA,
    createdAtUnixMs: now,
    expiresAtUnixMs: plan.expiresAtUnixMs,
    release: plan.release,
    sourcePlanSha256: plan.sha256,
    leaseId: registryClaim.leaseId,
    runId: registryClaim.runId,
    registryClaimSha256: registryClaim.evidenceSha256,
    sources: Object.freeze(plan.sources.map((entry, index) => Object.freeze({
      ordinal: entry.ordinal,
      dataHome: entry.dataHome,
      installationReceiptSha256: entry.installationReceiptSha256,
      outpoint: entry.outpoint.text,
      lockingBytecodeHex: entry.lockingBytecodeHex,
      valueSats: entry.valueSats.toString(),
      rawTransactionSha256: authenticatedSources[index].rawTransactionSha256,
    }))),
  });
}

async function run(options, dependencies) {
  exact(options, ['operatorRoot', 'planPath', 'reservationDirectory', 'runId'], 'reservation options');
  const deps = assertDependencies(dependencies);
  const now = deps.now();
  const planBytes = await deps.readPrivateFile(absolute(options.planPath, 'source plan'), 'source plan');
  const plan = parseV2BetaPerformanceSourcePlan(planBytes, now);
  const reservationDirectory = absolute(options.reservationDirectory, 'reservation directory');
  const ledgerPath = path.join(reservationDirectory, V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME);
  const operatorRoot = absolute(options.operatorRoot, 'operator root');
  const installations = await Promise.all(plan.sources.map(async (entry) => {
    await strictPrivateDirectory(entry.dataHome, `source ${entry.ordinal} data home`);
    return deps.validateInstall({ dataHome: entry.dataHome });
  }));
  const dataDirectories = [];
  for (let index = 0; index < plan.sources.length; index += 1) {
    const install = installations[index]; const entry = plan.sources[index];
    if (install === null || typeof install !== 'object' || typeof install.dataDirectory !== 'string'
      || !HASH.test(install.receiptSha256) || typeof install.releaseId !== 'string'
      || !HASH.test(install.releaseManifestSha256) || install.receiptSha256 !== entry.installationReceiptSha256
      || install.releaseId !== plan.release.releaseId
      || install.releaseManifestSha256 !== plan.release.releaseManifestSha256) {
      fail('PERFORMANCE_SOURCE_INSTALL_REJECTED', `source ${entry.ordinal} pinned install does not match the stable plan release`);
    }
    dataDirectories.push(install.dataDirectory);
  }
  if (new Set(dataDirectories).size !== V2_BETA_POOL_CREATE_PERFORMANCE_SOURCE_COUNT) {
    fail('PERFORMANCE_SOURCE_INSTALL_REJECTED', 'different data homes resolved to a shared installed data directory');
  }
  const existing = await deps.readExistingLedger({ reservationDirectory, ledgerPath, now });
  let ledger; let ledgerSha256;
  if (existing !== null) {
    if (existing === null || typeof existing !== 'object' || typeof existing.sha256 !== 'string') fail('PERFORMANCE_SOURCE_RESUME_REJECTED', 'existing ledger reader returned an invalid result');
    ledger = assertResumableLedger(existing.ledger, plan, options.runId); ledgerSha256 = existing.sha256;
  } else {
    const authenticatedSources = [];
    for (const entry of plan.sources) authenticatedSources.push(await deps.authenticateRpc(entry));
    // Publish an immutable intent before claiming the registry. If the process
    // dies in either order, the next invocation reuses this lease and exact
    // source binding; it never creates a second reservation.
    const intent = Object.freeze({ leaseId: createV2BetaOperatorSourceLeaseId(), runId: options.runId, evidenceSha256: plan.sha256 });
    ledger = candidateLedger(plan, authenticatedSources, intent, now);
    await deps.writeLedger({ reservationDirectory, ledgerPath, ledger });
    ledgerSha256 = sha256(Buffer.from(canonicalizeJcs(ledger), 'utf8'));
  }
  const registryClaim = await deps.claimRegistry({
    operatorRoot,
    claim: Object.freeze({
      release: plan.release,
      leaseId: ledger.leaseId,
      runId: ledger.runId,
      evidenceSha256: ledger.registryClaimSha256,
      sources: Object.freeze(plan.sources.map((entry) => Object.freeze({
        outpoint: entry.outpoint.text,
        dataHome: entry.dataHome,
        installationReceiptSha256: entry.installationReceiptSha256,
      }))),
    }),
  });
  if (registryClaim?.sourceCount !== V2_BETA_POOL_CREATE_PERFORMANCE_SOURCE_COUNT
    || registryClaim.evidenceSha256 !== plan.sha256) {
    fail('PERFORMANCE_SOURCE_REGISTRY_REJECTED', 'canonical source registry did not claim exactly these twenty sources');
  }
  return Object.freeze({
    sourceCount: plan.sources.length, release: plan.release,
    leaseId: registryClaim.leaseId, runId: registryClaim.runId,
    ledgerSha256,
  });
}

/** Isolated test seam. It cannot brand or create a live BCHN capability. */
export async function reserveV2BetaPerformanceSourcesForTest(options, dependencies) {
  // Compatibility exists only at the isolated unit seam so pre-registry tests
  // can exercise path/authentication logic. The production export and CLI do
  // not accept historical-file inputs; they always use the canonical registry.
  if (options !== null && typeof options === 'object' && Array.isArray(options.existingPrivateInputs)) {
    const existing = await Promise.all(options.existingPrivateInputs.map(async (filename, index) => (
      parseV2BetaPerformanceExistingPrivateInput(
        await dependencies.readPrivateFile(absolute(filename, `existing private input ${index + 1}`), `existing private input ${index + 1}`),
        `existing private input ${index + 1}`,
      )
    )));
    const claimRegistry = async ({ claim }) => {
      const occupiedOutpoints = new Set(existing.flatMap((entry) => entry.outpoints.map((item) => item.text)));
      const occupiedProvenances = new Set(existing.flatMap((entry) => entry.provenances));
      if (claim.sources.some((entry) => occupiedOutpoints.has(entry.outpoint)
        || occupiedProvenances.has(sourceProvenanceSha256(outpoint(entry.outpoint, 'test claim outpoint'))))) {
        fail('PERFORMANCE_SOURCE_OVERLAP_REJECTED', 'source plan overlaps an explicitly supplied test-only private record');
      }
      return Object.freeze({ sourceCount: claim.sources.length, leaseId: claim.leaseId, runId: claim.runId, evidenceSha256: claim.evidenceSha256 });
    };
    return run(Object.freeze({
      operatorRoot: options.reservationDirectory ? path.dirname(options.reservationDirectory) : path.dirname(options.planPath),
      planPath: options.planPath,
      reservationDirectory: options.reservationDirectory,
      runId: 'legacy-unit-seam',
    }), Object.freeze({ ...dependencies, claimRegistry }));
  }
  return run(options, dependencies);
}

async function productionReadPrivateFile(filename, label) {
  return strictPrivateFile(filename, label);
}

async function productionReadExistingLedger({ reservationDirectory, ledgerPath, now }) {
  await strictPrivateDirectory(reservationDirectory, 'reservation directory', { create: true });
  const existing = await lstat(ledgerPath).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', 'reservation ledger cannot be inspected', { cause: error });
  });
  if (existing === null) return null;
  return readV2BetaPerformanceSourceReservationLedger(ledgerPath, now);
}

async function productionWriteLedger({ reservationDirectory, ledgerPath, ledger }) {
  const directory = await strictPrivateDirectory(reservationDirectory, 'reservation directory', { create: true });
  if (path.dirname(ledgerPath) !== directory || path.basename(ledgerPath) !== V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME) {
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', 'reservation ledger path escapes the private reservation directory');
  }
  const targetStat = await lstat(ledgerPath).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    fail('PERFORMANCE_SOURCE_PATH_REJECTED', 'reservation ledger cannot be inspected', { cause: error });
  });
  if (targetStat !== null) {
    fail('PERFORMANCE_SOURCE_LEDGER_EXISTS', 'an immutable reservation ledger already exists in this directory');
  }
  const temporary = path.join(directory, `.${V2_BETA_PERFORMANCE_SOURCE_LEDGER_FILENAME}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    const bytes = Buffer.from(canonicalizeJcs(ledger), 'utf8');
    handle = await open(temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await chmod(temporary, 0o600);
    await strictPrivateDirectory(directory, 'reservation directory');
    try { await link(temporary, ledgerPath); }
    catch (error) {
      if (error?.code === 'EEXIST') fail('PERFORMANCE_SOURCE_LEDGER_EXISTS', 'an immutable reservation ledger already exists in this directory');
      fail('PERFORMANCE_SOURCE_LEDGER_WRITE_REJECTED', 'reservation ledger could not be atomically published', { cause: error });
    }
    await unlink(temporary);
    await strictPrivateFile(ledgerPath, 'reservation ledger');
    const directoryHandle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

/**
 * Production entrypoint. The fixed public TLS capability makes an arbitrary
 * Electrum endpoint, mock, mainnet, regtest, SSH, or credentialed RPC route
 * ineligible for a live reservation.
 */
export async function reserveV2BetaPerformanceSources(options, { validateInstall } = {}) {
  if (typeof validateInstall !== 'function') {
    fail('PERFORMANCE_SOURCE_INVALID', 'production pinned-install validation capability is required');
  }
  const rpc = assertChipnetProductRpc(await createPublicChipnetFulcrumRpc());
  try {
    return await run(options, Object.freeze({
      now: Date.now,
      readPrivateFile: productionReadPrivateFile,
      validateInstall,
      authenticateRpc: (entry) => authenticateSource(entry, rpc),
      claimRegistry: reserveV2BetaPerformanceSourcesInRegistry,
      readExistingLedger: productionReadExistingLedger,
      writeLedger: productionWriteLedger,
    }));
  } finally { try { await rpc.close?.(); } catch {} }
}

/** Production-only exact ledger reader for a subsequent performance driver. */
export async function readV2BetaPerformanceSourceReservationLedger(filename, now = Date.now()) {
  const bytes = await strictPrivateFile(filename, 'reservation ledger');
  const value = parseCanonicalJson(bytes, 'reservation ledger');
  const ledger = ledgerRecord(value, 'reservation ledger', now);
  return Object.freeze({
    sha256: sha256(bytes), ledger,
    outpoints: Object.freeze(ledger.sources.map((entry) => entry.outpoint)),
  });
}

/**
 * Explicitly release an expired, never-sent performance lease. This has no
 * chain capability: the canonical transition itself requires every source to
 * remain `performance-reserved`, so send-attempted/spent/reconciled sources
 * can never be returned to the available set by expiry handling.
 */
export async function releaseExpiredV2BetaPerformanceSourceReservation({ operatorRoot, ledgerPath, now = Date.now() } = {}, { inspectRegistry = inspectV2BetaOperatorSourceRegistry, transition = transitionV2BetaOperatorSources } = {}) {
  if (typeof transition !== 'function' || typeof inspectRegistry !== 'function' || !Number.isSafeInteger(now)) fail('PERFORMANCE_SOURCE_INVALID', 'expired reservation release arguments are invalid');
  const filename = absolute(ledgerPath, 'reservation ledger');
  const bytes = await strictPrivateFile(filename, 'reservation ledger');
  const ledger = ledgerRecord(parseCanonicalJson(bytes, 'reservation ledger'), 'reservation ledger');
  if (now <= ledger.expiresAtUnixMs) fail('PERFORMANCE_SOURCE_RELEASE_REJECTED', 'reservation lease has not expired');
  const root = absolute(operatorRoot, 'operator root');
  const registry = inspectRegistry({ operatorRoot: root });
  for (const entry of ledger.sources) {
    const source = registry?.sources?.find((candidate) => candidate.outpoint === entry.outpoint.text);
    if (source === undefined
      || source.role !== 'fanout-performance'
      || source.state !== 'performance-reserved'
      || source.leaseId !== ledger.leaseId
      || source.runId !== ledger.runId
      || source.evidenceSha256 !== ledger.registryClaimSha256
      || source.releaseId !== ledger.release.releaseId
      || source.releaseManifestSha256 !== ledger.release.releaseManifestSha256
      || source.dataHome !== entry.dataHome
      || source.installationReceiptSha256 !== entry.installationReceiptSha256
      || source.walletLockingBytecodeHex !== entry.lockingBytecodeHex
      || source.valueSats !== entry.valueSats) {
      fail('PERFORMANCE_SOURCE_RELEASE_REJECTED', 'expired reservation ledger does not exactly bind every canonical reserved source');
    }
  }
  return transition({ operatorRoot: root, outpoints: ledger.sources.map((entry) => entry.outpoint.text), fromState: 'performance-reserved', toState: 'explicitly-released', reason: 'explicit-release', leaseId: ledger.leaseId, runId: ledger.runId, evidenceSha256: ledger.registryClaimSha256, immutableBindings: ledger.sources.map((entry) => Object.freeze({ outpoint: entry.outpoint.text, role: 'fanout-performance', releaseId: ledger.release.releaseId, releaseManifestSha256: ledger.release.releaseManifestSha256, dataHome: entry.dataHome, installationReceiptSha256: entry.installationReceiptSha256, lockingBytecodeHex: entry.lockingBytecodeHex, valueSats: entry.valueSats, leaseId: ledger.leaseId, runId: ledger.runId, evidenceSha256: ledger.registryClaimSha256 })) });
}

/** Isolated filesystem test seam for atomic immutable-ledger publication. */
export async function writeV2BetaPerformanceSourceReservationLedgerForTest(value) {
  exact(value, ['ledger', 'ledgerPath', 'reservationDirectory'], 'ledger writer test options');
  return productionWriteLedger(value);
}
