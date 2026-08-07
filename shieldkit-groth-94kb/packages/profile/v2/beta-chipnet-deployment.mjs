/**
 * Explicitly beta-only, no-secret deployment and confirmation boundary for a
 * signed V2 genesis pair. This module never constructs, signs, or broadcasts
 * on its own: sending is delegated to the mandatory staged-operation
 * coordinator after a real BCHN Chipnet capability has been checked.
 */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

import {
  assertLayer1BchnChipnetRpc,
} from '../../kit/chipnet-rpc.mjs';
import {
  broadcastStagedOperation,
  commitStagedOperation,
  loadPendingOperation,
  stageOperation,
  transactionIdFromHex,
} from '../../kit/transaction-coordinator.mjs';
import {
  atomicWriteJson,
  PRIVATE_FILE_MODE,
  readJsonFile,
} from '../../kit/secure-files.mjs';
import {
  inspectV2PackagedGenesisBinding,
} from './genesis.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  canonicalizeJcs,
} from './profile-core.mjs';

export const V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA =
  'shieldkit-v2-beta-chipnet-deployment-v1';
export const V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT =
  'acknowledge-beta-single-contributor-unqualified-chipnet-deployment';
export const V2_BETA_CHIPNET_ZERO_CONF_STATUS =
  'accepted-zero-conf-beta-unqualified';

const HASH = /^[0-9a-f]{64}$/u;
const HEX = /^(?:[0-9a-f]{2})+$/u;
const COMMITMENT = /^[0-9a-f]{256}$/u;
const deploymentCapabilities = new WeakMap();
const committedGenesisCapabilities = new WeakMap();

export class V2BetaChipnetDeploymentError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaChipnetDeploymentError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaChipnetDeploymentError(code, message, options);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));

function plain(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_DEPLOYMENT_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_DEPLOYMENT_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_DEPLOYMENT_INVALID', `${label} must be lowercase 32-byte hexadecimal`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    fail('BETA_DEPLOYMENT_INVALID', `${label} must be a positive supported integer`);
  }
  return value;
}

function deploymentPath(directory) {
  const root = trustedDeploymentDirectory(directory);
  return path.join(root, '.shieldkit', 'v2-beta-chipnet-deployment.json');
}

function trustedDeploymentDirectory(directory) {
  if (typeof directory !== 'string' || directory.length === 0) {
    fail('BETA_DEPLOYMENT_INVALID', 'deploymentDirectory is required');
  }
  const root = path.resolve(directory);
  let metadata;
  try { metadata = lstatSync(root); }
  catch (error) { fail('BETA_DEPLOYMENT_PATH_REJECTED', `deploymentDirectory is not available: ${error.message}`, { cause: error }); }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0 || realpathSync(root) !== root) {
    fail('BETA_DEPLOYMENT_PATH_REJECTED', 'deploymentDirectory must be a private canonical directory');
  }
  const shieldkit = path.join(root, '.shieldkit');
  if (existsSync(shieldkit)) {
    const shieldkitMetadata = lstatSync(shieldkit);
    if (!shieldkitMetadata.isDirectory() || shieldkitMetadata.isSymbolicLink()
      || (shieldkitMetadata.mode & 0o077) !== 0 || realpathSync(shieldkit) !== shieldkit) {
      fail('BETA_DEPLOYMENT_PATH_REJECTED', '.shieldkit deployment ancestry must be a private canonical directory');
    }
  }
  return root;
}

function zeroConfAcceptancePath(directory) {
  return path.join(trustedDeploymentDirectory(directory), '.shieldkit', 'v2-beta-chipnet-zero-conf-acceptance.json');
}

function statePath(directory) {
  return path.join(trustedDeploymentDirectory(directory), '.shieldkit', 'v2-beta-chipnet-state.json');
}

function ledgerPath(directory) {
  return path.join(trustedDeploymentDirectory(directory), '.shieldkit', 'v2-beta-chipnet-ledger.jsonl');
}

function assertBchnRpc(rpc) {
  try { return assertLayer1BchnChipnetRpc(rpc); }
  catch (error) {
    fail('BETA_DEPLOYMENT_RPC_REJECTED', error instanceof Error ? error.message : 'real BCHN Chipnet RPC capability is required', { cause: error });
  }
}

function acknowledgement(value) {
  if (value !== V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT) {
    fail('BETA_DEPLOYMENT_ACKNOWLEDGEMENT_REQUIRED', 'explicit beta-unqualified Chipnet acknowledgement is required');
  }
  return value;
}

function rawHex(value, label) {
  if (typeof value !== 'string' || !HEX.test(value)) {
    fail('BETA_DEPLOYMENT_INVALID', `${label} must be nonempty lowercase transaction hex`);
  }
  return value;
}

function inspectionFor(value) {
  let inspection;
  try { inspection = inspectV2PackagedGenesisBinding(value.packagedGenesis); }
  catch (error) {
    fail('BETA_DEPLOYMENT_PACKAGE_REJECTED', error instanceof Error ? error.message : 'packaged beta genesis inspection failed', { cause: error });
  }
  const sourceHex = rawHex(value.sourceFundingRawTxHex, 'sourceFundingRawTxHex');
  const packagedSource = Buffer.from(value.packagedGenesis.rawSourceTransaction).toString('hex');
  const packagedGenesis = Buffer.from(value.packagedGenesis.rawGenesisTransaction).toString('hex');
  if (sourceHex !== packagedSource
    || transactionIdFromHex(sourceHex) !== inspection.sourceTransactionId
    || transactionIdFromHex(packagedGenesis) !== inspection.genesisTransactionId) {
    fail('BETA_DEPLOYMENT_PACKAGE_REJECTED', 'signed source/genesis bytes differ from independently inspected package pins');
  }
  const commitment = Buffer.from(value.packagedGenesis.descriptor.initialState).toString('hex');
  if (!COMMITMENT.test(commitment)) {
    fail('BETA_DEPLOYMENT_PACKAGE_REJECTED', 'packaged state commitment must be exactly 128 bytes');
  }
  return Object.freeze({
    inspection,
    sourceHex,
    genesisHex: packagedGenesis,
    commitment,
  });
}

function recordCore({ acknowledgement: acknowledgementValue, inspected }) {
  return Object.freeze({
    schema: V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA,
    status: 'prepared',
    acknowledgement: acknowledgementValue,
    eligibility: 'beta-single-contributor-unqualified',
    claims: Object.freeze({
      broadcasted: false,
      confirmed: false,
      mined: false,
      productionQualified: false,
    }),
    profileId: inspected.inspection.profileId,
    instanceId: inspected.inspection.instanceId,
    source: Object.freeze({
      transactionId: inspected.inspection.sourceTransactionId,
      rawTransactionSha256: sha256(Buffer.from(inspected.sourceHex, 'hex')),
    }),
    genesis: Object.freeze({
      transactionId: inspected.inspection.genesisTransactionId,
      rawTransactionSha256: sha256(Buffer.from(inspected.genesisHex, 'hex')),
      stateOutputIndex: 0,
      stateCommitmentSha256: sha256(Buffer.from(inspected.commitment, 'hex')),
    }),
    packageInspection: inspected.inspection,
  });
}

function finalizeRecord(core) {
  return Object.freeze({ ...core, evidenceSha256: canonicalSha256(core) });
}

function recordWithStatus(record, status, claims = record.claims) {
  const { evidenceSha256: _priorEvidenceSha256, ...core } = record;
  return finalizeRecord({ ...core, status, claims });
}

function validateRecord(value) {
  exact(value, ['acknowledgement', 'claims', 'eligibility', 'evidenceSha256', 'genesis', 'instanceId', 'packageInspection', 'profileId', 'schema', 'source', 'status'], 'beta deployment record');
  const { evidenceSha256, ...core } = value;
  if (value.schema !== V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA
    || !['prepared', 'broadcast', 'accepted-zero-conf', 'committed'].includes(value.status)
    || value.acknowledgement !== V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT
    || value.eligibility !== 'beta-single-contributor-unqualified'
    || canonicalSha256(core) !== hash(evidenceSha256, 'deployment evidenceSha256')) {
    fail('BETA_DEPLOYMENT_EVIDENCE_REJECTED', 'beta deployment record is noncanonical or outside the unqualified boundary');
  }
  const legacyBroadcastClaims = matchesCanonical(value.claims, { productionQualified: false });
  let invalidClaims = legacyBroadcastClaims && value.status !== 'broadcast';
  if (!legacyBroadcastClaims) {
    exact(value.claims, ['broadcasted', 'confirmed', 'mined', 'productionQualified'], 'beta deployment claims');
    invalidClaims = typeof value.claims.broadcasted !== 'boolean' || value.claims.confirmed !== false || typeof value.claims.mined !== 'boolean'
      || value.claims.productionQualified !== false
      || (value.status === 'prepared' && (value.claims.broadcasted || value.claims.mined))
      || (['broadcast', 'accepted-zero-conf', 'committed'].includes(value.status)
        && (!value.claims.broadcasted || value.claims.mined));
  }
  if (invalidClaims) {
    fail('BETA_DEPLOYMENT_EVIDENCE_REJECTED', 'beta deployment claims must remain unqualified');
  }
  hash(value.profileId, 'deployment profileId'); hash(value.instanceId, 'deployment instanceId');
  exact(value.source, ['rawTransactionSha256', 'transactionId'], 'deployment source');
  exact(value.genesis, ['rawTransactionSha256', 'stateCommitmentSha256', 'stateOutputIndex', 'transactionId'], 'deployment genesis');
  hash(value.source.transactionId, 'deployment source transactionId'); hash(value.source.rawTransactionSha256, 'deployment source rawTransactionSha256');
  hash(value.genesis.transactionId, 'deployment genesis transactionId'); hash(value.genesis.rawTransactionSha256, 'deployment genesis rawTransactionSha256'); hash(value.genesis.stateCommitmentSha256, 'deployment genesis stateCommitmentSha256');
  if (value.genesis.stateOutputIndex !== 0) fail('BETA_DEPLOYMENT_EVIDENCE_REJECTED', 'beta deployment state output must remain vout 0');
  return value;
}

function writeRecord(directory, record) {
  atomicWriteJson(deploymentPath(directory), record, { mode: PRIVATE_FILE_MODE });
}

function acceptedZeroConfClaims() {
  return Object.freeze({ broadcasted: true, confirmed: false, mined: false, productionQualified: false });
}

function coordinatorPayloadForRecord(record) {
  return Object.freeze({
    nextState: Object.freeze({
      schema: V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA,
      status: V2_BETA_CHIPNET_ZERO_CONF_STATUS,
      eligibility: record.eligibility,
      claims: acceptedZeroConfClaims(),
      profileId: record.profileId,
      instanceId: record.instanceId,
      genesis: Object.freeze({ transactionId: record.genesis.transactionId, outputIndex: 0 }),
    }),
    ledgerRecord: Object.freeze({
      schema: V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA,
      status: V2_BETA_CHIPNET_ZERO_CONF_STATUS,
      eligibility: record.eligibility,
      claims: acceptedZeroConfClaims(),
      profileId: record.profileId,
      instanceId: record.instanceId,
      sourceTransactionId: record.source.transactionId,
      genesisTransactionId: record.genesis.transactionId,
    }),
    publicResult: Object.freeze({
      profileId: record.profileId,
      instanceId: record.instanceId,
      genesisTransactionId: record.genesis.transactionId,
    }),
  });
}

function coordinatorPayload(core, inspected) {
  return Object.freeze({
    ...coordinatorPayloadForRecord(core),
    transactions: Object.freeze([
      Object.freeze({ role: 'source-funding', txid: core.source.transactionId, hex: inspected.sourceHex }),
      Object.freeze({ role: 'beta-genesis', txid: core.genesis.transactionId, hex: inspected.genesisHex }),
    ]),
  });
}

function resumeRejected(message) {
  fail('BETA_DEPLOYMENT_RESUME_REJECTED', message);
}

function matchesCanonical(actual, expected) {
  return canonicalizeJcs(actual) === canonicalizeJcs(expected);
}

/**
 * The coordinator owns a broader journal schema. This narrow recovery accepts
 * only its pristine, exact pre-send representation for this one deployment.
 */
function assertRecoverablePreparedJournal(journal, core, inspected) {
  const expected = coordinatorPayload(core, inspected);
  if (journal.kind !== 'v2-beta-chipnet-genesis' || journal.network !== 'chipnet'
    || journal.setupMode !== 'development-only' || journal.status !== 'prepared'
    || !Array.isArray(journal.transactions) || journal.transactions.length !== expected.transactions.length
    || typeof journal.operationId !== 'string' || journal.operationId.length === 0) {
    resumeRejected('pending operation is not the exact prepared beta Chipnet genesis journal');
  }
  for (let index = 0; index < expected.transactions.length; index += 1) {
    const transaction = journal.transactions[index];
    if (transaction === null || Array.isArray(transaction) || typeof transaction !== 'object'
      || Object.getPrototypeOf(transaction) !== Object.prototype
      || Object.keys(transaction).sort().join(',') !== 'attemptToken,attempts,hex,role,status,txid'
      || transaction.status !== 'prepared' || transaction.attempts !== 0
      || transaction.attemptToken !== null
      || !matchesCanonical({ role: transaction.role, txid: transaction.txid, hex: transaction.hex }, expected.transactions[index])) {
      resumeRejected('pending beta deployment transaction bytes or roles differ from the supplied package');
    }
  }
  const expectedLedgerRecord = { ...expected.ledgerRecord, operationId: journal.operationId };
  if (!matchesCanonical(journal.nextState, expected.nextState)
    || !matchesCanonical(journal.ledgerRecord, expectedLedgerRecord)
    || !matchesCanonical(journal.publicResult, expected.publicResult)) {
    resumeRejected('pending beta deployment state, ledger, or public result differs from the supplied package');
  }
  return expected;
}

export function loadV2BetaChipnetDeployment({ deploymentDirectory } = {}) {
  const filename = deploymentPath(deploymentDirectory);
  if (!existsSync(filename)) return null;
  return Object.freeze({ path: filename, record: validateRecord(readJsonFile(filename)) });
}

/**
 * Recover the exact coordinator-retained transaction pair for product restart.
 * This is read-only and revalidates txids, byte hashes, roles, and the durable
 * deployment binding before exposing either signed transaction.
 */
export function loadV2BetaChipnetDeploymentRecovery({ deploymentDirectory } = {}) {
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null) return null;
  let pending;
  try { pending = loadPendingOperation(deploymentDirectory); }
  catch (error) {
    fail(
      'BETA_DEPLOYMENT_RECOVERY_REJECTED',
      'deployment coordinator journal cannot be parsed for exact recovery',
      { cause: error },
    );
  }
  if (pending === null || pending.journal.kind !== 'v2-beta-chipnet-genesis'
    || pending.journal.network !== 'chipnet'
    || pending.journal.setupMode !== 'development-only'
    || !Array.isArray(pending.journal.transactions)
    || pending.journal.transactions.length !== 2) {
    fail('BETA_DEPLOYMENT_RECOVERY_REJECTED', 'deployment lacks its exact two-transaction coordinator journal');
  }
  const expected = [
    Object.freeze({
      role: 'source-funding',
      transactionId: loaded.record.source.transactionId,
      rawTransactionSha256: loaded.record.source.rawTransactionSha256,
    }),
    Object.freeze({
      role: 'beta-genesis',
      transactionId: loaded.record.genesis.transactionId,
      rawTransactionSha256: loaded.record.genesis.rawTransactionSha256,
    }),
  ];
  for (const [index, pin] of expected.entries()) {
    const transaction = pending.journal.transactions[index];
    if (transaction?.role !== pin.role || transaction.txid !== pin.transactionId
      || typeof transaction.hex !== 'string'
      || transactionIdFromHex(transaction.hex) !== pin.transactionId
      || sha256(Buffer.from(transaction.hex, 'hex')) !== pin.rawTransactionSha256) {
      fail('BETA_DEPLOYMENT_RECOVERY_REJECTED', `deployment recovery transaction ${index} differs from its durable pins`);
    }
  }
  return Object.freeze({
    path: loaded.path,
    journalPath: pending.journalPath,
    record: loaded.record,
    operationId: pending.journal.operationId,
    journalStatus: pending.journal.status,
    sourceFundingRawTxHex: pending.journal.transactions[0].hex,
    genesisRawTxHex: pending.journal.transactions[1].hex,
    ambiguousSend: pending.journal.transactions.some((transaction) =>
      ['sending', 'indeterminate'].includes(transaction.status)),
  });
}

/** Inspect and durably stage exact signed source/genesis bytes before any send. */
export function stageV2BetaChipnetDeployment(value) {
  exact(value, ['acknowledgement', 'deploymentDirectory', 'packagedGenesis', 'rpc', 'sourceFundingRawTxHex'], 'beta deployment stage input');
  const rpc = assertBchnRpc(value.rpc);
  const ack = acknowledgement(value.acknowledgement);
  const inspected = inspectionFor(value);
  const existing = loadV2BetaChipnetDeployment({ deploymentDirectory: value.deploymentDirectory });
  if (existing !== null) {
    const record = existing.record;
    if (record.profileId !== inspected.inspection.profileId || record.instanceId !== inspected.inspection.instanceId
      || record.source.transactionId !== inspected.inspection.sourceTransactionId
      || record.genesis.transactionId !== inspected.inspection.genesisTransactionId
      || record.source.rawTransactionSha256 !== sha256(Buffer.from(inspected.sourceHex, 'hex'))
      || record.genesis.rawTransactionSha256 !== sha256(Buffer.from(inspected.genesisHex, 'hex'))) {
      fail('BETA_DEPLOYMENT_RESUME_REJECTED', 'existing beta deployment journal differs from supplied exact package bytes');
    }
    const recovery = loadV2BetaChipnetDeploymentRecovery({
      deploymentDirectory: value.deploymentDirectory,
    });
    return Object.freeze({
      ...existing,
      journalPath: recovery.journalPath,
      operationId: recovery.operationId,
      rpcBackend: rpc.backend,
      resumed: true,
    });
  }
  const core = recordCore({ acknowledgement: ack, inspected });
  const record = finalizeRecord(core);
  const pending = loadPendingOperation(value.deploymentDirectory);
  if (pending !== null) {
    assertRecoverablePreparedJournal(pending.journal, core, inspected);
    writeRecord(value.deploymentDirectory, record);
    return Object.freeze({
      path: deploymentPath(value.deploymentDirectory),
      record,
      journalPath: pending.journalPath,
      operationId: pending.journal.operationId,
      rpcBackend: rpc.backend,
      resumed: true,
    });
  }
  const coordinator = coordinatorPayload(core, inspected);
  let staged;
  try {
    staged = stageOperation({
      poolDirectory: value.deploymentDirectory,
      kind: 'v2-beta-chipnet-genesis',
      network: 'chipnet',
      setupMode: 'development-only',
      transactions: coordinator.transactions,
      nextState: coordinator.nextState,
      ledgerRecord: coordinator.ledgerRecord,
      publicResult: coordinator.publicResult,
    });
  } catch (error) {
    fail('BETA_DEPLOYMENT_STAGE_REJECTED', error instanceof Error ? error.message : 'could not stage beta deployment', { cause: error });
  }
  writeRecord(value.deploymentDirectory, record);
  return Object.freeze({ path: deploymentPath(value.deploymentDirectory), record, journalPath: staged.journalPath, operationId: staged.journal.operationId, rpcBackend: rpc.backend, resumed: false });
}

/** Run BCHN testmempoolaccept/send only after the source+genesis pair is journaled. */
export async function broadcastV2BetaChipnetDeployment({ acknowledgement: acknowledgementValue, deploymentDirectory, rpc } = {}) {
  const checkedRpc = assertBchnRpc(rpc); acknowledgement(acknowledgementValue);
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null) fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'a staged beta deployment is required before sending');
  if (loaded.record.status === 'accepted-zero-conf' || loaded.record.status === 'committed') return Object.freeze({ ...loaded, broadcast: false, rpcBackend: checkedRpc.backend });
  const pending = loadPendingOperation(deploymentDirectory);
  if (pending === null || pending.journal.kind !== 'v2-beta-chipnet-genesis') {
    fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'exact staged beta deployment journal is absent');
  }
  let journal;
  try { journal = await broadcastStagedOperation({ journalPath: pending.journalPath, rpc: checkedRpc }); }
  catch (error) { throw error instanceof V2BetaChipnetDeploymentError ? error : new V2BetaChipnetDeploymentError('BETA_DEPLOYMENT_BROADCAST_REJECTED', error instanceof Error ? error.message : 'beta deployment BCHN send failed', { cause: error }); }
  const record = recordWithStatus(loaded.record, 'broadcast', acceptedZeroConfClaims());
  writeRecord(deploymentDirectory, record);
  return Object.freeze({ path: loaded.path, record, journalPath: pending.journalPath, operationId: journal.operationId, broadcast: true, rpcBackend: checkedRpc.backend });
}

function tokenObservation(value, record, errorCode) {
  plain(value, 'genesis gettxout');
  const token = value.tokenData ?? value.token;
  plain(token, 'genesis gettxout token');
  const category = token.category;
  const nft = token.nft;
  const commitment = nft?.commitment ?? nft?.commitmentHex;
  if (typeof category !== 'string' || !HASH.test(category)
    || category !== record.source.transactionId
    || Buffer.from(category, 'hex').reverse().toString('hex') !== record.instanceId
    || token.amount !== '0' || nft?.capability !== 'mutable'
    || typeof commitment !== 'string' || !COMMITMENT.test(commitment)
    || sha256(Buffer.from(commitment, 'hex')) !== record.genesis.stateCommitmentSha256) {
    fail(errorCode, 'BCHN genesis vout 0 token/category/commitment differs from the inspected beta package');
  }
  return Object.freeze({ category, amount: token.amount, capability: nft.capability, commitmentSha256: sha256(Buffer.from(commitment, 'hex')) });
}

function zeroConfTransaction(value, expectedTxid, expectedHex, label) {
  if (value === null || value === undefined) return null;
  plain(value, `${label} verbose transaction`);
  if (value.txid !== expectedTxid || value.hex !== expectedHex) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_REJECTED', `${label} BCHN mempool readback differs from the exact staged bytes`);
  }
  return Object.freeze({ transactionId: expectedTxid, rawTransactionSha256: sha256(Buffer.from(expectedHex, 'hex')) });
}

function legacyCoordinatorPayload(record, operationId) {
  const claims = Object.freeze({ productionQualified: false });
  return Object.freeze({
    nextState: Object.freeze({
      schema: V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA,
      status: 'confirmed-beta-unqualified',
      eligibility: record.eligibility,
      claims,
      profileId: record.profileId,
      instanceId: record.instanceId,
      genesis: Object.freeze({ transactionId: record.genesis.transactionId, outputIndex: 0 }),
    }),
    ledgerRecord: Object.freeze({
      schema: V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA,
      status: 'confirmed-beta-unqualified',
      eligibility: record.eligibility,
      profileId: record.profileId,
      instanceId: record.instanceId,
      sourceTransactionId: record.source.transactionId,
      genesisTransactionId: record.genesis.transactionId,
      operationId,
    }),
    publicResult: Object.freeze({ profileId: record.profileId, instanceId: record.instanceId, genesisTransactionId: record.genesis.transactionId }),
  });
}

function assertExactBroadcastJournal(journal, record) {
  if (journal.kind !== 'v2-beta-chipnet-genesis' || journal.network !== 'chipnet'
    || journal.setupMode !== 'development-only' || journal.status !== 'broadcast'
    || !Array.isArray(journal.transactions) || journal.transactions.length !== 2
    || typeof journal.operationId !== 'string' || journal.operationId.length === 0) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'the exact fully broadcast beta Chipnet genesis journal is required');
  }
  const expectedTransactions = [
    { role: 'source-funding', txid: record.source.transactionId, rawTransactionSha256: record.source.rawTransactionSha256 },
    { role: 'beta-genesis', txid: record.genesis.transactionId, rawTransactionSha256: record.genesis.rawTransactionSha256 },
  ];
  let durableReadback = true;
  for (let index = 0; index < expectedTransactions.length; index += 1) {
    const actual = journal.transactions[index]; const expected = expectedTransactions[index];
    if (actual === null || Array.isArray(actual) || typeof actual !== 'object'
      || actual.role !== expected.role || actual.txid !== expected.txid || actual.status !== 'broadcast'
      || !Number.isSafeInteger(actual.attempts) || actual.attempts < 1
      || typeof actual.hex !== 'string' || transactionIdFromHex(actual.hex) !== actual.txid
      || sha256(Buffer.from(actual.hex, 'hex')) !== expected.rawTransactionSha256) {
      fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'the broadcast journal does not contain the exact source-to-genesis transaction pair');
    }
    const expectedReadbackSha256 = sha256(Buffer.from(actual.hex, 'hex'));
    const observedAt = actual.readback?.observedAt;
    if (actual.readback?.rawTransactionSha256 !== expectedReadbackSha256
      || typeof observedAt !== 'string' || !Number.isFinite(Date.parse(observedAt))) {
      durableReadback = false;
    }
  }
  const current = coordinatorPayloadForRecord(record);
  const currentLedger = { ...current.ledgerRecord, operationId: journal.operationId };
  if (matchesCanonical(journal.nextState, current.nextState)
    && matchesCanonical(journal.ledgerRecord, currentLedger)
    && matchesCanonical(journal.publicResult, current.publicResult)) {
    if (!durableReadback) {
      fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'current broadcast journal lacks exact durable BCHN raw-byte readback');
    }
    return Object.freeze({ coordinator: current, durableReadback: true, legacy: false });
  }
  const legacy = legacyCoordinatorPayload(record, journal.operationId);
  if (matchesCanonical(journal.nextState, legacy.nextState)
    && matchesCanonical(journal.ledgerRecord, legacy.ledgerRecord)
    && matchesCanonical(journal.publicResult, legacy.publicResult)) {
    return Object.freeze({ coordinator: current, durableReadback, legacy: true });
  }
  fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'the broadcast journal state/ledger payload is neither the exact zero-conf form nor the supported legacy form');
}

function migrateLegacyBroadcastJournal(pending, checked, observedTransactions = undefined) {
  if (!checked.legacy) return pending;
  const transactions = pending.journal.transactions.map((transaction, index) => {
    if (checked.durableReadback) return transaction;
    const observed = observedTransactions?.[index];
    if (observed?.txid !== transaction.txid || observed.hex !== transaction.hex) {
      fail('BETA_DEPLOYMENT_ZERO_CONF_REJECTED', 'legacy BCHN raw readback differs from the exact staged transaction');
    }
    return {
      ...transaction,
      readback: {
        observedAt: new Date().toISOString(),
        rawTransactionSha256: sha256(Buffer.from(transaction.hex, 'hex')),
      },
    };
  });
  const journal = {
    ...pending.journal,
    transactions,
    nextState: checked.coordinator.nextState,
    ledgerRecord: { ...checked.coordinator.ledgerRecord, operationId: pending.journal.operationId },
    updatedAt: new Date().toISOString(),
  };
  atomicWriteJson(pending.journalPath, journal, { mode: PRIVATE_FILE_MODE });
  return Object.freeze({ journalPath: pending.journalPath, journal });
}

function zeroConfEvidenceCore(record, source, genesis, token) {
  return Object.freeze({
    schema: `${V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA}-zero-conf-acceptance`,
    status: V2_BETA_CHIPNET_ZERO_CONF_STATUS,
    eligibility: record.eligibility,
    claims: acceptedZeroConfClaims(),
    profileId: record.profileId,
    instanceId: record.instanceId,
    source,
    genesis,
    stateOutput: token,
  });
}

/**
 * Supported completion gate: verify both fully-broadcast transactions and the
 * genesis NFT in BCHN's current zero-confirmation view. It never waits for a
 * block and never claims mining or production qualification.
 */
export async function acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: acknowledgementValue, deploymentDirectory, rpc } = {}) {
  const checkedRpc = assertBchnRpc(rpc); acknowledgement(acknowledgementValue);
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null) fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'a staged beta deployment is required before zero-conf acceptance');
  const record = loaded.record;
  if (record.status === 'committed') {
    if (!existsSync(zeroConfAcceptancePath(deploymentDirectory))) {
      fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'committed beta deployment lacks durable exact zero-conf evidence');
    }
    const evidence = validateZeroConfAcceptance(
      readJsonFile(zeroConfAcceptancePath(deploymentDirectory)),
      record,
    );
    return Object.freeze({
      ...loaded,
      accepted: true,
      committed: true,
      evidence,
      status: 'accepted-zero-conf',
      rpcBackend: checkedRpc.backend,
    });
  }
  if (!['broadcast', 'accepted-zero-conf'].includes(record.status)) fail('BETA_DEPLOYMENT_NOT_BROADCAST', 'beta deployment must be fully broadcast before zero-conf acceptance');
  const pending = loadPendingOperation(deploymentDirectory);
  if (pending === null) fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'exact staged beta deployment journal is absent');
  const journalCheck = assertExactBroadcastJournal(pending.journal, record);
  let sourceRaw; let genesisRaw; let state;
  try {
    if (journalCheck.durableReadback) {
      state = await checkedRpc.gettxout(record.genesis.transactionId, 0);
    } else {
      [sourceRaw, genesisRaw, state] = await Promise.all([
        checkedRpc.getrawtransaction(record.source.transactionId, true),
        checkedRpc.getrawtransaction(record.genesis.transactionId, true),
        checkedRpc.gettxout(record.genesis.transactionId, 0),
      ]);
    }
  } catch (error) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_PENDING', error instanceof Error ? error.message : 'BCHN zero-conf readback failed', { cause: error });
  }
  const source = journalCheck.durableReadback
    ? Object.freeze({ transactionId: record.source.transactionId, rawTransactionSha256: record.source.rawTransactionSha256 })
    : zeroConfTransaction(sourceRaw, record.source.transactionId, pending.journal.transactions[0].hex, 'source');
  const genesis = journalCheck.durableReadback
    ? Object.freeze({ transactionId: record.genesis.transactionId, rawTransactionSha256: record.genesis.rawTransactionSha256 })
    : zeroConfTransaction(genesisRaw, record.genesis.transactionId, pending.journal.transactions[1].hex, 'genesis');
  if (source === null || genesis === null || state === null) return Object.freeze({ accepted: false, status: record.status, rpcBackend: checkedRpc.backend });
  const token = tokenObservation(state, record, 'BETA_DEPLOYMENT_ZERO_CONF_REJECTED');
  const migrated = migrateLegacyBroadcastJournal(
    pending,
    journalCheck,
    journalCheck.durableReadback ? undefined : [sourceRaw, genesisRaw],
  );
  const core = zeroConfEvidenceCore(record, source, genesis, token);
  const evidence = Object.freeze({ ...core, evidenceSha256: canonicalSha256(core) });
  atomicWriteJson(zeroConfAcceptancePath(deploymentDirectory), evidence, { mode: PRIVATE_FILE_MODE });
  const acceptedRecord = recordWithStatus(record, 'accepted-zero-conf', acceptedZeroConfClaims());
  writeRecord(deploymentDirectory, acceptedRecord);
  return Object.freeze({ accepted: true, acceptancePath: zeroConfAcceptancePath(deploymentDirectory), evidence, journalPath: migrated.journalPath, operationId: migrated.journal.operationId, status: acceptedRecord.status, rpcBackend: checkedRpc.backend });
}

function validateZeroConfAcceptance(value, record) {
  exact(value, ['claims', 'eligibility', 'evidenceSha256', 'genesis', 'instanceId', 'profileId', 'schema', 'source', 'stateOutput', 'status'], 'beta deployment zero-conf acceptance');
  const { evidenceSha256, ...core } = value;
  if (value.schema !== `${V2_BETA_CHIPNET_DEPLOYMENT_SCHEMA}-zero-conf-acceptance`
    || value.status !== V2_BETA_CHIPNET_ZERO_CONF_STATUS
    || canonicalSha256(core) !== hash(evidenceSha256, 'zero-conf acceptance evidenceSha256')
    || value.eligibility !== record.eligibility || value.profileId !== record.profileId
    || value.instanceId !== record.instanceId || !matchesCanonical(value.claims, acceptedZeroConfClaims())
    || value.source?.transactionId !== record.source.transactionId
    || value.source?.rawTransactionSha256 !== record.source.rawTransactionSha256
    || value.genesis?.transactionId !== record.genesis.transactionId
    || value.genesis?.rawTransactionSha256 !== record.genesis.rawTransactionSha256
    || value.stateOutput?.commitmentSha256 !== record.genesis.stateCommitmentSha256) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_REJECTED', 'stored zero-conf acceptance does not bind the exact beta deployment');
  }
  return value;
}

/**
 * Issue an opaque, clone-resistant binding only from durable zero-conf evidence.
 * Descriptor and runtime-material provenance intentionally remain in the
 * independently branded runtime lane rather than being inferred here.
 */
export function deriveV2BetaChipnetDeploymentBinding({ deploymentDirectory } = {}) {
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null || !['accepted-zero-conf', 'committed'].includes(loaded.record.status)
    || !existsSync(zeroConfAcceptancePath(deploymentDirectory))) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'durable zero-conf acceptance is required to derive a beta deployment capability');
  }
  const acceptance = validateZeroConfAcceptance(readJsonFile(zeroConfAcceptancePath(deploymentDirectory)), loaded.record);
  const binding = Object.freeze({
    eligibility: loaded.record.eligibility,
    profileId: loaded.record.profileId,
    instanceId: loaded.record.instanceId,
    sourceTransactionId: loaded.record.source.transactionId,
    genesisOutpoint: Object.freeze({ txid: loaded.record.genesis.transactionId, vout: 0 }),
    initialStateSha256: loaded.record.genesis.stateCommitmentSha256,
    zeroConfEvidenceSha256: acceptance.evidenceSha256,
  });
  deploymentCapabilities.set(binding, true);
  return binding;
}

export function assertV2BetaChipnetDeploymentCapability(value) {
  if (!deploymentCapabilities.has(value)) {
    fail('BETA_DEPLOYMENT_CAPABILITY_REJECTED', 'a locally derived beta deployment capability is required');
  }
  return value;
}

function committedGenesisTransaction(record) {
  let pending;
  try { pending = loadPendingOperation(record.pathDirectory); }
  catch (error) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', error instanceof Error ? error.message : 'committed beta deployment journal cannot be validated', { cause: error });
  }
  if (pending === null) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', 'committed beta deployment journal is absent');
  }
  const journal = pending.journal;
  if (journal.kind !== 'v2-beta-chipnet-genesis' || journal.network !== 'chipnet'
    || journal.setupMode !== 'development-only' || journal.status !== 'committed'
    || !Array.isArray(journal.transactions) || journal.transactions.length !== 2) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', 'committed beta deployment journal has an unexpected identity or state');
  }
  const expected = [
    { role: 'source-funding', transactionId: record.source.transactionId, rawTransactionSha256: record.source.rawTransactionSha256 },
    { role: 'beta-genesis', transactionId: record.genesis.transactionId, rawTransactionSha256: record.genesis.rawTransactionSha256 },
  ];
  for (const [index, expectedTransaction] of expected.entries()) {
    const actual = journal.transactions[index];
    if (actual === null || Array.isArray(actual) || typeof actual !== 'object'
      || actual.role !== expectedTransaction.role || actual.status !== 'broadcast'
      || actual.txid !== expectedTransaction.transactionId || typeof actual.hex !== 'string'
      || transactionIdFromHex(actual.hex) !== expectedTransaction.transactionId
      || sha256(Buffer.from(actual.hex, 'hex')) !== expectedTransaction.rawTransactionSha256) {
      fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', 'committed beta deployment journal does not retain the exact pinned transaction pair');
    }
  }
  return journal.transactions[1].hex;
}

/**
 * Load the exact genesis anchor only from the committed deployment record,
 * accepted zero-conf evidence, and coordinator-pinned signed transaction.
 * The convenience state/ledger files are deliberately not consulted.
 */
export function loadV2BetaChipnetCommittedGenesis({ deploymentDirectory } = {}) {
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null || loaded.record.status !== 'committed'
    || !existsSync(zeroConfAcceptancePath(deploymentDirectory))) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REQUIRED', 'a committed beta deployment with durable zero-conf acceptance is required');
  }
  const acceptance = validateZeroConfAcceptance(
    readJsonFile(zeroConfAcceptancePath(deploymentDirectory)), loaded.record,
  );
  // Keep the directory out of the durable record, so validation never allows a
  // relocated record to redirect journal lookup.
  const record = Object.freeze({ ...loaded.record, pathDirectory: trustedDeploymentDirectory(deploymentDirectory) });
  const genesisHex = committedGenesisTransaction(record);
  let parsed;
  let stateOutput;
  try {
    parsed = parseV2RawTransaction(genesisHex);
    stateOutput = parseSerializedSourceOutput(parsed.outputs[0].serializedHex);
  } catch (error) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', error instanceof Error ? error.message : 'committed genesis transaction cannot be parsed', { cause: error });
  }
  const initialState = stateOutput.token?.nft?.commitmentHex;
  if (parsed.txid !== loaded.record.genesis.transactionId
    || !COMMITMENT.test(initialState ?? '')
    || stateOutput.token?.categoryWire !== loaded.record.instanceId
    || stateOutput.token?.amount !== '0' || stateOutput.token?.nft?.capability !== 'mutable'
    || sha256(Buffer.from(initialState, 'hex')) !== loaded.record.genesis.stateCommitmentSha256
    || initialState.slice(0, 8) !== Buffer.from('SKS2', 'ascii').toString('hex')
    || initialState.slice(8, 72) !== loaded.record.profileId
    || Buffer.from(initialState, 'hex').readUInt32LE(100) !== 0
    || Buffer.from(initialState, 'hex').readBigUInt64LE(120) !== 0n) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED', 'committed genesis state NFT does not exactly bind the accepted empty beta genesis');
  }
  const genesis = Object.freeze({
    eligibility: loaded.record.eligibility,
    profileId: loaded.record.profileId,
    instanceId: loaded.record.instanceId,
    initialState: Buffer.from(initialState, 'hex'),
    initialStateSha256: loaded.record.genesis.stateCommitmentSha256,
    genesisOutpoint: Object.freeze({ txid: loaded.record.genesis.transactionId, vout: 0 }),
    zeroConfEvidenceSha256: acceptance.evidenceSha256,
  });
  committedGenesisCapabilities.set(genesis, Object.freeze({
    profileId: genesis.profileId,
    instanceId: genesis.instanceId,
    initialStateSha256: genesis.initialStateSha256,
    genesisTransactionId: genesis.genesisOutpoint.txid,
    zeroConfEvidenceSha256: genesis.zeroConfEvidenceSha256,
  }));
  return genesis;
}

export function assertV2BetaChipnetCommittedGenesisCapability(value) {
  const binding = committedGenesisCapabilities.get(value);
  if (!binding || !(value?.initialState instanceof Uint8Array)
    || value.initialState.length !== 128
    || sha256(value.initialState) !== binding.initialStateSha256
    || value.profileId !== binding.profileId || value.instanceId !== binding.instanceId
    || value.genesisOutpoint?.txid !== binding.genesisTransactionId
    || value.genesisOutpoint?.vout !== 0
    || value.zeroConfEvidenceSha256 !== binding.zeroConfEvidenceSha256) {
    fail('BETA_DEPLOYMENT_COMMITTED_GENESIS_CAPABILITY_REJECTED', 'a locally loaded, unmodified committed beta genesis capability is required');
  }
  return value;
}

/** Commit only after durable zero-conf BCHN acceptance has been recorded. */
export function commitV2BetaChipnetDeployment({ acknowledgement: acknowledgementValue, deploymentDirectory } = {}) {
  acknowledgement(acknowledgementValue);
  const loaded = loadV2BetaChipnetDeployment({ deploymentDirectory });
  if (loaded === null) fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'a staged beta deployment is required before commit');
  if (loaded.record.status === 'committed') return Object.freeze({ ...loaded, committed: false });
  if (loaded.record.status !== 'accepted-zero-conf' || !existsSync(zeroConfAcceptancePath(deploymentDirectory))) {
    fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'durable BCHN zero-conf acceptance is required before commit');
  }
  validateZeroConfAcceptance(readJsonFile(zeroConfAcceptancePath(deploymentDirectory)), loaded.record);
  const pending = loadPendingOperation(deploymentDirectory);
  if (pending === null) fail('BETA_DEPLOYMENT_PENDING_REQUIRED', 'exact staged beta deployment journal is absent');
  const journalCheck = assertExactBroadcastJournal(pending.journal, loaded.record);
  if (journalCheck.legacy) fail('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED', 'legacy journal must be migrated by a successful zero-conf acceptance before commit');
  let journal;
  try { journal = commitStagedOperation({ journalPath: pending.journalPath, statePath: statePath(deploymentDirectory), ledgerPath: ledgerPath(deploymentDirectory) }); }
  catch (error) { fail('BETA_DEPLOYMENT_COMMIT_REJECTED', error instanceof Error ? error.message : 'beta deployment commit failed', { cause: error }); }
  const record = recordWithStatus(loaded.record, 'committed');
  writeRecord(deploymentDirectory, record);
  return Object.freeze({ path: loaded.path, record, journalPath: pending.journalPath, operationId: journal.operationId, committed: true });
}
