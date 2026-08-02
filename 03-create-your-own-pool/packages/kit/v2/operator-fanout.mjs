/**
 * Offline, operator-only 20-way funding fanout for the beta performance
 * campaign. Signing never crosses argv/stdout. Production transport is pinned
 * public TLS; broadcast and recovery are separate durable journal/CAS phases.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import {
  createVirtualMachineBch2026, decodeTransaction, encodeDataPush, encodeTransaction,
  generateSigningSerializationBch, hash256, secp256k1, SigningSerializationTypeBch,
} from '@bitauth/libauth';

import {
  assertChipnetProductRpc,
  assertLayer1BchnChipnetRpc,
  createPublicChipnetFulcrumRpc,
} from '../chipnet-rpc.mjs';
import { admitAndSendExactTransactionOnce } from '../transaction-coordinator.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { createV2SecretFile } from '../../profile/v2/instance-descriptor.mjs';
import { loadV2ChipnetFundingWallet, createV2ChipnetFundingWallet } from './funding-wallet.mjs';
import { parseSerializedSourceOutput, parseV2RawTransaction, transactionId } from './transaction-policy.mjs';
import {
  casV2BetaOperatorFanoutOperation, createV2BetaOperatorFanoutOperation,
  inspectV2BetaOperatorSourceRegistry, registerV2BetaOperatorFanoutSources,
  v2BetaOperatorFanoutInputSetSha256, v2BetaOperatorSourceRegistryLocation,
} from './operator-source-registry.mjs';

export const V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA = 'shieldkit-v2-beta-operator-fanout-inventory-v1';
export const V2_BETA_OPERATOR_FANOUT_JOURNAL_SCHEMA = 'shieldkit-v2-beta-operator-fanout-journal-v1';
/** Twenty fanout outputs are reserved for the pool-create campaign. */
export const V2_BETA_OPERATOR_FANOUT_RECIPIENT_COUNT = 20;
/** Provision one extra identity for the separately claimed semantic run. */
export const V2_BETA_OPERATOR_DESTINATION_IDENTITY_COUNT = 21;
export const V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS = 53_006_565n;
const HASH = /^[0-9a-f]{64}$/u; const OUTPOINT = /^([0-9a-f]{64}):(0|[1-9][0-9]*)$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u; const P2PKH = /^76a914[0-9a-f]{40}88ac$/u;
const DUST = 546n; const SIGHASH = SigningSerializationTypeBch.allOutputs;

export class V2BetaOperatorFanoutError extends Error { constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaOperatorFanoutError'; this.code = code; } }
const fail = (code, message, options = undefined) => { throw new V2BetaOperatorFanoutError(code, message, options); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function exact(value, keys, label) { if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('OPERATOR_FANOUT_INVALID', `${label} must be a plain object`); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('OPERATOR_FANOUT_INVALID', `${label} has missing or unknown fields`); return value; }
function absolute(value, label) { if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} must be normalized absolute path`); return value; }
function runId(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) fail('OPERATOR_FANOUT_INVALID', 'runId is invalid'); return value; }
function outpoint(value, label) { const matched = typeof value === 'string' ? OUTPOINT.exec(value) : null; if (matched === null || !Number.isSafeInteger(Number(matched[2])) || Number(matched[2]) > 0xffff_ffff) fail('OPERATOR_FANOUT_INVALID', `${label} must be canonical txid:vout`); return Object.freeze({ text: value, txid: matched[1], vout: Number(matched[2]) }); }
function amount(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value)) fail('OPERATOR_FANOUT_INVALID', `${label} must be a canonical amount`); return BigInt(value); }
function p2pkh(value, label) { if (typeof value !== 'string' || !P2PKH.test(value)) fail('OPERATOR_FANOUT_INVALID', `${label} must be canonical P2PKH`); return value; }
function canonicalJson(bytes, label) { let parsed; try { parsed = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch (error) { fail('OPERATOR_FANOUT_INVALID', `${label} is invalid JSON`, { cause: error }); } if (!Buffer.from(canonicalizeJcs(parsed), 'utf8').equals(Buffer.from(bytes))) fail('OPERATOR_FANOUT_INVALID', `${label} must be canonical JCS without trailing bytes`); return parsed; }

async function strictDir(directory, { create = false } = {}) {
  const target = absolute(directory, 'directory');
  const parent = path.dirname(target);
  const parentStat = await lstat(parent).catch((error) => fail(
    'OPERATOR_FANOUT_PATH_REJECTED', 'directory parent unavailable', { cause: error },
  ));
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || await realpath(parent) !== parent
    || (parentStat.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && parentStat.uid !== process.getuid())) {
    fail('OPERATOR_FANOUT_PATH_REJECTED', 'directory parent must be owner-controlled');
  }
  if (create) {
    await mkdir(target, { mode: 0o700 }).catch((error) => {
      if (error?.code !== 'EEXIST') {
        fail('OPERATOR_FANOUT_PATH_REJECTED', 'directory cannot be created', { cause: error });
      }
    });
  }
  // Inspect before any mode mutation. A pre-existing symlink or wrong-mode
  // directory is rejected without chmod-following an attacker-selected target.
  const stat = await lstat(target).catch((error) => fail(
    'OPERATOR_FANOUT_PATH_REJECTED', 'directory unavailable', { cause: error },
  ));
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(target) !== target
    || (stat.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    fail('OPERATOR_FANOUT_PATH_REJECTED', 'directory must be current-user mode 0700');
  }
  return target;
}
async function strictCanonicalAncestry(directory, label) {
  let current = directory;
  for (;;) {
    const stat = await lstat(current).catch((error) => fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} ancestry unavailable`, { cause: error }));
    if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(current) !== current) {
      fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} ancestry must be canonical directories without symlinks`);
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
async function strictPrivateFile(filename, label) {
  const target = absolute(filename, label);
  await strictCanonicalAncestry(path.dirname(target), label);
  const stat = await lstat(target).catch((error) => fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} unavailable`, { cause: error }));
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || await realpath(target) !== target) fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} must be a canonical private unlinked 0600 file`);
  const handle = await open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch((error) => fail('OPERATOR_FANOUT_PATH_REJECTED', `${label} cannot be opened`, { cause: error }));
  try {
    const openStat = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const named = await lstat(target);
    if (openStat.dev !== stat.dev || openStat.ino !== stat.ino || !openStat.isFile() || openStat.nlink !== 1
      || after.dev !== openStat.dev || after.ino !== openStat.ino || named.dev !== openStat.dev || named.ino !== openStat.ino) {
      fail('OPERATOR_FANOUT_PATH_RACE', `${label} changed while being read`);
    }
    return Buffer.from(bytes);
  } finally { await handle.close(); }
}
function assertOperatorFanoutRpc(value) {
  try { return assertChipnetProductRpc(value); }
  catch (publicError) {
    try { return assertLayer1BchnChipnetRpc(value); }
    catch { fail('OPERATOR_FANOUT_RPC_REJECTED', 'operator fanout requires a pinned public Chipnet capability or explicitly injected BCHN lab capability', { cause: publicError }); }
  }
}
function journalPath(operatorRoot, requestedRunId) { const location = v2BetaOperatorSourceRegistryLocation({ operatorRoot }); return path.join(location.operatorRoot, 'fanout-runs', runId(requestedRunId), 'fanout-journal.json'); }
async function journalDirectory(operatorRoot, requestedRunId) { const location = v2BetaOperatorSourceRegistryLocation({ operatorRoot }); const runs = await strictDir(path.join(location.operatorRoot, 'fanout-runs'), { create: true }); return strictDir(path.join(runs, runId(requestedRunId)), { create: true }); }

export async function provisionV2BetaOperatorFanoutDestinations({ operatorRoot } = {}) {
  const location = v2BetaOperatorSourceRegistryLocation({ operatorRoot }); const walletDirectory = await strictDir(path.join(location.operatorRoot, 'fanout-wallets'), { create: true }); const homeDirectory = await strictDir(path.join(location.operatorRoot, 'fanout-data-homes'), { create: true }); const publicWallets = [];
  for (let index = 0; index < V2_BETA_OPERATOR_DESTINATION_IDENTITY_COUNT; index += 1) {
    const ordinal = String(index + 1).padStart(2, '0'); const walletPath = path.join(walletDirectory, `wallet-${ordinal}.json`); const dataHome = path.join(homeDirectory, `pool-${ordinal}`); await strictDir(dataHome, { create: true });
    // Exclusive creation means a crash can leave a prefix behind. Resume by
    // loading that exact custody record; never generate a replacement key.
    const existing = await lstat(walletPath).then(() => true).catch((error) => {
      if (error?.code === 'ENOENT') return false;
      fail('OPERATOR_FANOUT_PATH_REJECTED', 'destination wallet cannot be inspected safely', { cause: error });
    });
    let wallet;
    if (existing) wallet = await loadV2ChipnetFundingWallet({ filename: walletPath });
    else {
      try { wallet = await createV2ChipnetFundingWallet({ filename: walletPath }); }
      catch (error) {
        // Another same-owner provisioner may have won this one exclusive
        // create. Load and validate it rather than overwriting its key.
        if (error?.code !== 'FUNDING_WALLET_EXISTS') throw error;
        wallet = await loadV2ChipnetFundingWallet({ filename: walletPath });
      }
    }
    publicWallets.push(Object.freeze({ ordinal: index + 1, lockingBytecodeHex: wallet.lockingBytecodeHex, cashAddress: wallet.cashAddress }));
  }
  return Object.freeze({ recipientCount: publicWallets.length, wallets: Object.freeze(publicWallets) });
}

export function parseV2BetaOperatorFanoutInventory(bytes) { const value = canonicalJson(bytes, 'fanout inventory'); exact(value, ['schema', 'sourceOutpoints'], 'fanout inventory'); if (value.schema !== V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA || !Array.isArray(value.sourceOutpoints) || value.sourceOutpoints.length < 2 || value.sourceOutpoints.length > 512) fail('OPERATOR_FANOUT_INVALID', 'fanout inventory must contain 2..512 source outpoints'); const sources = value.sourceOutpoints.map((item, index) => outpoint(item, `sourceOutpoints[${index}]`)); if (new Set(sources.map((item) => item.text)).size !== sources.length) fail('OPERATOR_FANOUT_INVALID', 'fanout inventory duplicates a source outpoint'); return Object.freeze({ sources: Object.freeze([...sources].sort((left, right) => left.text.localeCompare(right.text))) }); }
function observedSats(value) { if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) return BigInt(value.valueSatoshis); if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) { const sats = Math.round(value.value * 1e8); if (Number.isSafeInteger(sats) && sats / 1e8 === value.value) return BigInt(sats); } return null; }
async function authenticateInput(entry, wallet, rpc) { let raw; let live; try { [raw, live] = await Promise.all([rpc.getrawtransaction(entry.txid, false), rpc.gettxout(entry.txid, entry.vout)]); } catch (error) { fail('OPERATOR_FANOUT_CHAIN_UNAVAILABLE', `source ${entry.text} cannot be read`, { cause: error }); } if (typeof raw !== 'string' || live === null) fail('OPERATOR_FANOUT_SOURCE_MISSING', `source ${entry.text} is spent or unavailable`); let transaction; let output; try { transaction = parseV2RawTransaction(raw); output = transaction.outputs[entry.vout] === undefined ? null : parseSerializedSourceOutput(transaction.outputs[entry.vout].serializedHex); } catch (error) { fail('OPERATOR_FANOUT_CHAIN_MALFORMED', `source ${entry.text} is malformed`, { cause: error }); } if (transaction.txid !== entry.txid || output === null || output.token !== null || output.lockingBytecodeHex !== wallet.lockingBytecodeHex || output.valueSatoshis < DUST || live?.scriptPubKey?.hex !== wallet.lockingBytecodeHex || observedSats(live) !== output.valueSatoshis || live?.tokenData !== undefined && live.tokenData !== null || live?.token !== undefined && live.token !== null) fail('OPERATOR_FANOUT_SOURCE_REJECTED', `source ${entry.text} is not a live tokenless output owned by supplied source wallet`); return Object.freeze({ entry, rawTransactionHex: raw, valueSats: output.valueSatoshis, lockingBytecodeHex: output.lockingBytecodeHex }); }
function pushUnlock(signature, publicKey) { const unlock = Buffer.concat([Buffer.from(encodeDataPush(Buffer.concat([Buffer.from(signature), Buffer.from([SIGHASH])]))), Buffer.from(encodeDataPush(Buffer.from(publicKey, 'hex')))]); if (unlock.length !== 100) fail('OPERATOR_FANOUT_INTERNAL', 'P2PKH unlocking bytecode is noncanonical'); return unlock; }
// Libauth transaction objects use display-order txid bytes and reverse them
// while serializing the BCH wire outpoint. Keep this conversion named here:
// reversing at this boundary would serialize the wrong prevout.
function displayTxidToLibauthOutpointHash(displayTxid) { return Uint8Array.from(Buffer.from(displayTxid, 'hex')); }
function unsigned(inputs, outputs, unlocks) { return { version: 2, inputs: inputs.map((entry, index) => ({ outpointTransactionHash: displayTxidToLibauthOutpointHash(entry.entry.txid), outpointIndex: entry.entry.vout, sequenceNumber: 0xffff_ffff, unlockingBytecode: Uint8Array.from(unlocks[index]) })), outputs: outputs.map((entry) => ({ valueSatoshis: entry.valueSats, lockingBytecode: Uint8Array.from(Buffer.from(entry.lockingBytecodeHex, 'hex')) })), locktime: 0 }; }

/** Builds, signs, and exact-BCH_2026_STANDARD-verifies the canonical 20-way fanout offline. */
export function buildV2BetaOperatorFanout({ sourceWallet, authenticatedInputs, recipientWallets } = {}) {
  if (sourceWallet === null || typeof sourceWallet !== 'object' || !Array.isArray(authenticatedInputs) || authenticatedInputs.length < 2 || !Array.isArray(recipientWallets) || recipientWallets.length !== V2_BETA_OPERATOR_FANOUT_RECIPIENT_COUNT) fail('OPERATOR_FANOUT_INVALID', 'fanout build arguments are malformed');
const inputs = [...authenticatedInputs].sort((left, right) => left.entry.text.localeCompare(right.entry.text)); const recipients = recipientWallets.map((wallet, index) => ({ ordinal: index + 1, lockingBytecodeHex: p2pkh(wallet.lockingBytecodeHex, `recipient ${index + 1}`), valueSats: V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS })); const sourceTotal = inputs.reduce((sum, entry) => sum + entry.valueSats, 0n); const placeholder = Buffer.alloc(100);
  const baseOutputs = [...recipients, { lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: DUST }];
  const sized = unsigned(inputs, baseOutputs, inputs.map(() => placeholder));
  const fee = BigInt(Buffer.from(encodeTransaction(sized)).length);
  const change = sourceTotal - recipients.reduce((sum, entry) => sum + entry.valueSats, 0n) - fee;
  if (change < DUST) fail('OPERATOR_FANOUT_INSUFFICIENT', 'source inventory cannot fund 20 required outputs, exact one-sat-per-byte fee, and dust-safe change');
  const outputs = [...recipients, { lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: change }];
  const preimage = unsigned(inputs, outputs, inputs.map(() => Buffer.alloc(0)));
  const sourceOutputs = inputs.map((entry) => ({ valueSatoshis: entry.valueSats, lockingBytecode: Uint8Array.from(Buffer.from(entry.lockingBytecodeHex, 'hex')) }));
  const unlocks = inputs.map((entry, index) => {
    const serialization = Buffer.from(generateSigningSerializationBch({ inputIndex: index, sourceOutputs, transaction: preimage }, { coveredBytecode: Uint8Array.from(Buffer.from(entry.lockingBytecodeHex, 'hex')), signingSerializationType: Uint8Array.of(SIGHASH) }));
    const signature = sourceWallet.signMessageHashSchnorr(Buffer.from(hash256(serialization)));
    if (!(signature instanceof Uint8Array) || signature.length !== 64) fail('OPERATOR_FANOUT_SIGNING_FAILED', 'local Schnorr signing failed');
    return pushUnlock(signature, sourceWallet.compressedPublicKeyHex);
  });
  const transaction = unsigned(inputs, outputs, unlocks); const raw = Buffer.from(encodeTransaction(transaction));
  if (raw.length !== Number(fee)) fail('OPERATOR_FANOUT_INTERNAL', 'fanout signing changed fixed-size transaction');
  const vm = createVirtualMachineBch2026(true);
  if (vm.verify({ sourceOutputs, transaction }) !== true) fail('OPERATOR_FANOUT_VM_REJECTED', 'BCH_2026_STANDARD rejected local fanout');
  for (let index = 0; index < inputs.length; index += 1) {
    const state = vm.evaluate({ inputIndex: index, sourceOutputs, transaction });
    if (vm.stateSuccess(state) !== true) fail('OPERATOR_FANOUT_VM_REJECTED', `local fanout input ${index} fails BCH_2026_STANDARD: ${state.error ?? 'unknown'}`);
  }
  const rawTransactionHex = raw.toString('hex');
  const decoded = decodeTransaction(Uint8Array.from(raw));
  if (typeof decoded === 'string') fail('OPERATOR_FANOUT_INTERNAL', `could not decode signed fanout: ${decoded}`);
  const decodedTransaction = { version: decoded.version, inputs: decoded.inputs.map((entry) => ({ outpointTransactionHash: Uint8Array.from(entry.outpointTransactionHash), outpointIndex: entry.outpointIndex, sequenceNumber: entry.sequenceNumber, unlockingBytecode: Uint8Array.from(entry.unlockingBytecode) })), outputs: decoded.outputs.map((entry) => ({ valueSatoshis: entry.valueSatoshis, lockingBytecode: Uint8Array.from(entry.lockingBytecode), ...(entry.token === undefined ? {} : { token: entry.token }) })), locktime: decoded.locktime };
  if (vm.verify({ sourceOutputs, transaction: decodedTransaction }) !== true) fail('OPERATOR_FANOUT_VM_REJECTED', 'serialized exact fanout bytes fail BCH_2026_STANDARD');
  for (let index = 0; index < inputs.length; index += 1) {
    if (vm.stateSuccess(vm.evaluate({ inputIndex: index, sourceOutputs, transaction: decodedTransaction })) !== true) fail('OPERATOR_FANOUT_VM_REJECTED', `serialized fanout input ${index} fails BCH_2026_STANDARD`);
  }
  const txid = transactionId(raw);
  return Object.freeze({ transactionId: txid, rawTransactionHex, rawTransactionSha256: sha256(raw), feeSats: fee.toString(), serializedBytes: raw.length, sourceOutpoints: Object.freeze(inputs.map((entry) => entry.entry.text)), sourceTransactionSha256s: Object.freeze(inputs.map((entry) => sha256(Buffer.from(entry.rawTransactionHex, 'hex')))), recipients: Object.freeze(recipients.map((entry, index) => Object.freeze({ ordinal: entry.ordinal, outpoint: `${txid}:${index}`, lockingBytecodeHex: entry.lockingBytecodeHex, valueSats: entry.valueSats.toString() }))), change: Object.freeze({ outpoint: `${txid}:${recipients.length}`, lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: change.toString() }) });
}

async function canonicalRecipientWallets(operatorRoot) { const location = v2BetaOperatorSourceRegistryLocation({ operatorRoot }); const wallets = []; for (let index = 0; index < V2_BETA_OPERATOR_FANOUT_RECIPIENT_COUNT; index += 1) wallets.push(await loadV2ChipnetFundingWallet({ filename: path.join(location.operatorRoot, 'fanout-wallets', `wallet-${String(index + 1).padStart(2, '0')}.json`) })); return Object.freeze(wallets); }
function journalRecord({ requestedRunId, fanout, sourceWallet }) { return Object.freeze({ schema: V2_BETA_OPERATOR_FANOUT_JOURNAL_SCHEMA, runId: requestedRunId, state: 'prepared', transactionId: fanout.transactionId, rawTransactionHex: fanout.rawTransactionHex, rawTransactionSha256: fanout.rawTransactionSha256, sourceWalletLockingBytecodeHex: sourceWallet.lockingBytecodeHex, sourceOutpoints: fanout.sourceOutpoints, recipients: fanout.recipients, change: fanout.change, feeSats: fanout.feeSats, serializedBytes: fanout.serializedBytes, createdAtUnixMs: 0 }); }
export async function prepareV2BetaOperatorFanout({ operatorRoot, runId: requestedRunId, sourceWalletPath, inventoryPath } = {}, { rpc = undefined } = {}) {
  const id = runId(requestedRunId); const canonicalSourceWalletPath = absolute(sourceWalletPath, 'source wallet'); await strictPrivateFile(canonicalSourceWalletPath, 'source wallet'); const wallet = await loadV2ChipnetFundingWallet({ filename: canonicalSourceWalletPath }); const inventory = parseV2BetaOperatorFanoutInventory(await strictPrivateFile(inventoryPath, 'fanout inventory')); const ownsRpc = rpc === undefined; const capability = assertOperatorFanoutRpc(rpc ?? await createPublicChipnetFulcrumRpc()); const authenticatedInputs = [];
  try {
  for (const entry of inventory.sources) authenticatedInputs.push(await authenticateInput(entry, wallet, capability));
  const fanout = buildV2BetaOperatorFanout({ sourceWallet: { ...wallet, signMessageHashSchnorr: (digest) => secp256k1.signMessageHashSchnorr(Buffer.from(wallet.privateKeyHex, 'hex'), digest) }, authenticatedInputs, recipientWallets: await canonicalRecipientWallets(operatorRoot) });
  const directory = await journalDirectory(operatorRoot, id); const filename = path.join(directory, 'fanout-journal.json'); const record = journalRecord({ requestedRunId: id, fanout, sourceWallet: wallet }); const bytes = Buffer.from(canonicalizeJcs(record), 'utf8'); const journalSha256 = sha256(bytes);
  const named = await lstat(filename).then(() => true).catch((error) => error?.code === 'ENOENT' ? false : fail('OPERATOR_FANOUT_PATH_REJECTED', 'fanout journal cannot be inspected', { cause: error }));
  if (named) {
    const existing = parseJournal(await strictPrivateFile(filename, 'fanout journal'));
    if (existing.transactionId !== fanout.transactionId || existing.rawTransactionSha256 !== fanout.rawTransactionSha256 || existing.rawTransactionHex !== fanout.rawTransactionHex) fail('OPERATOR_FANOUT_PREPARE_CONFLICT', 'existing journal does not bind this exact deterministic fanout');
  }
  let operation = inspectV2BetaOperatorSourceRegistry({ operatorRoot }).fanoutOperations.find((entry) => entry.runId === id);
  if (operation === undefined) {
    try { createV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: fanout.transactionId, rawTransactionSha256: fanout.rawTransactionSha256, journalSha256, inputOutpoints: fanout.sourceOutpoints }); }
    catch (error) {
      if (error?.code !== 'SOURCE_REGISTRY_CAS_CONFLICT') throw error;
      // A concurrent preparer may have won the exclusive operation insert.
      // Re-read and accept only its exact same prepared operation.
      operation = inspectV2BetaOperatorSourceRegistry({ operatorRoot }).fanoutOperations.find((entry) => entry.runId === id);
      if (operation === undefined) throw error;
    }
  }
  operation = inspectV2BetaOperatorSourceRegistry({ operatorRoot }).fanoutOperations.find((entry) => entry.runId === id);
  const reservedInputs = inspectV2BetaOperatorSourceRegistry({ operatorRoot }).fanoutInputReservations.filter((entry) => entry.runId === id).map((entry) => entry.outpoint);
  if (operation === undefined || operation.transactionId !== fanout.transactionId || operation.rawTransactionSha256 !== fanout.rawTransactionSha256 || operation.journalSha256 !== journalSha256 || operation.state !== 'prepared' || operation.inputCount !== fanout.sourceOutpoints.length || operation.inputSetSha256 !== v2BetaOperatorFanoutInputSetSha256(fanout.sourceOutpoints) || canonicalizeJcs(reservedInputs) !== canonicalizeJcs(fanout.sourceOutpoints)) fail('OPERATOR_FANOUT_PREPARE_CONFLICT', 'canonical operation does not bind this exact prepared fanout and input reservations');
  // Operation-first and journal-first crash windows both repair only if every
  // exact binding matches. createV2SecretFile is exclusive and never replaces.
  if (!named) await createV2SecretFile(filename, bytes);
  return Object.freeze({ runId: id, transactionId: fanout.transactionId, serializedBytes: fanout.serializedBytes, feeSats: fanout.feeSats, recipientCount: fanout.recipients.length });
  } finally { if (ownsRpc) { try { await capability.close?.(); } catch {} } }
}

function parseJournal(bytes) {
  const value = canonicalJson(bytes, 'fanout journal'); exact(value, ['change', 'createdAtUnixMs', 'feeSats', 'rawTransactionHex', 'rawTransactionSha256', 'recipients', 'runId', 'schema', 'serializedBytes', 'sourceOutpoints', 'sourceWalletLockingBytecodeHex', 'state', 'transactionId'], 'fanout journal');
  if (value.schema !== V2_BETA_OPERATOR_FANOUT_JOURNAL_SCHEMA || value.state !== 'prepared' || !HASH.test(value.transactionId) || !HASH.test(value.rawTransactionSha256) || typeof value.rawTransactionHex !== 'string' || !/^[0-9a-f]+$/u.test(value.rawTransactionHex) || sha256(Buffer.from(value.rawTransactionHex, 'hex')) !== value.rawTransactionSha256 || transactionId(Buffer.from(value.rawTransactionHex, 'hex')) !== value.transactionId || !Number.isSafeInteger(value.serializedBytes) || value.serializedBytes * 2 !== value.rawTransactionHex.length || !Array.isArray(value.sourceOutpoints) || value.sourceOutpoints.length < 2 || !Array.isArray(value.recipients) || value.recipients.length !== V2_BETA_OPERATOR_FANOUT_RECIPIENT_COUNT || !P2PKH.test(value.sourceWalletLockingBytecodeHex)) fail('OPERATOR_FANOUT_JOURNAL_REJECTED', 'fanout journal is malformed or does not bind exact transaction bytes');
  const recipients = value.recipients.map((entry, index) => { exact(entry, ['lockingBytecodeHex', 'ordinal', 'outpoint', 'valueSats'], `recipient ${index}`); if (entry.ordinal !== index + 1 || outpoint(entry.outpoint, 'recipient outpoint').txid !== value.transactionId || outpoint(entry.outpoint, 'recipient outpoint').vout !== index || !P2PKH.test(entry.lockingBytecodeHex) || amount(entry.valueSats, 'recipient value') < V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS) fail('OPERATOR_FANOUT_JOURNAL_REJECTED', 'fanout recipient is malformed'); return Object.freeze(entry); });
  value.sourceOutpoints.forEach((entry) => outpoint(entry, 'source outpoint')); if (new Set(value.sourceOutpoints).size !== value.sourceOutpoints.length) fail('OPERATOR_FANOUT_JOURNAL_REJECTED', 'fanout journal duplicates sources'); return Object.freeze({ ...value, recipients: Object.freeze(recipients) });
}
async function readJournal(operatorRoot, requestedRunId) {
  const filename = journalPath(operatorRoot, requestedRunId);
  // The parser and digest must bind one immutable file snapshot. Reading it
  // twice could otherwise parse one journal and transition the registry using
  // a digest from another after a hostile replacement attempt.
  const bytes = await strictPrivateFile(filename, 'fanout journal');
  const record = parseJournal(bytes);
  if (record.runId !== requestedRunId) fail('OPERATOR_FANOUT_JOURNAL_REJECTED', 'fanout journal run identifier does not match its canonical path');
  return Object.freeze({ filename, bytes, sha256: sha256(bytes), record });
}
async function verifyExactFanoutOutputs(record, rpc) { const raw = await rpc.getrawtransaction(record.transactionId, false); if (raw !== record.rawTransactionHex) fail('OPERATOR_FANOUT_READBACK_REJECTED', 'Chipnet raw readback differs from durable fanout bytes'); const parsed = parseV2RawTransaction(raw); if (parsed.txid !== record.transactionId) fail('OPERATOR_FANOUT_READBACK_REJECTED', 'Chipnet raw readback transaction identity differs'); for (const recipient of record.recipients) { const parsedOutpoint = outpoint(recipient.outpoint, 'recipient outpoint'); const output = parsed.outputs[parsedOutpoint.vout] === undefined ? null : parseSerializedSourceOutput(parsed.outputs[parsedOutpoint.vout].serializedHex); const live = await rpc.gettxout(record.transactionId, parsedOutpoint.vout); if (output === null || output.token !== null || output.lockingBytecodeHex !== recipient.lockingBytecodeHex || output.valueSatoshis !== amount(recipient.valueSats, 'recipient value') || live === null || live?.scriptPubKey?.hex !== recipient.lockingBytecodeHex || observedSats(live) !== amount(recipient.valueSats, 'recipient value') || live?.tokenData !== undefined && live.tokenData !== null || live?.token !== undefined && live.token !== null) fail('OPERATOR_FANOUT_READBACK_REJECTED', 'fanout output readback is not the exact tokenless registered output'); }
  return Object.freeze({ transactionId: record.transactionId, rawTransactionSha256: record.rawTransactionSha256 });
}
function registrySources(record) { return record.recipients.map((recipient) => ({ outpoint: recipient.outpoint, fanoutTransactionId: record.transactionId, fanoutVout: recipient.ordinal - 1, lockingBytecodeHex: recipient.lockingBytecodeHex, valueSats: recipient.valueSats })); }

/** One explicit network mutation; no retry or automatic rebroadcast. */
export async function broadcastPreparedV2BetaOperatorFanout({ operatorRoot, runId: requestedRunId } = {}, { rpc = undefined } = {}) {
  const id = runId(requestedRunId); const journal = await readJournal(operatorRoot, id); const journalSha256 = journal.sha256; const ownsRpc = rpc === undefined; const capability = assertOperatorFanoutRpc(rpc ?? await createPublicChipnetFulcrumRpc());
  try {
  try {
    await admitAndSendExactTransactionOnce({ rpc: capability, rawTransactionHex: journal.record.rawTransactionHex, expectedTransactionId: journal.record.transactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => casV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: journal.record.transactionId, rawTransactionSha256: journal.record.rawTransactionSha256, journalSha256, fromState: 'prepared', toState: 'send-attempted' }) });
  } catch (error) {
    // Mempool/durability failures occur before a send and leave the operation
    // prepared. Only the coordinator's explicit post-send marker is allowed
    // to consume this source into an indeterminate state.
    if (error?.sendAttempted === true) {
      try { casV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: journal.record.transactionId, rawTransactionSha256: journal.record.rawTransactionSha256, journalSha256, fromState: 'send-attempted', toState: 'indeterminate' }); } catch { /* preserve original send error */ }
      fail('OPERATOR_FANOUT_SEND_INDETERMINATE', 'fanout broadcast is not known accepted; run explicit inspected recovery before any further action', { cause: error });
    }
    fail('OPERATOR_FANOUT_SEND_REJECTED', 'fanout was rejected before any send attempt; the prepared journal remains unchanged', { cause: error });
  }
  try {
    await verifyExactFanoutOutputs(journal.record, capability);
  } catch (error) {
    try { casV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: journal.record.transactionId, rawTransactionSha256: journal.record.rawTransactionSha256, journalSha256, fromState: 'send-attempted', toState: 'indeterminate' }); } catch { /* preserve exact readback failure */ }
    fail('OPERATOR_FANOUT_SEND_INDETERMINATE', 'fanout send completed but exact zero-conf readback failed; run explicit inspected recovery before any further action', { cause: error });
  }
  registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: journal.record.transactionId, sources: registrySources(journal.record) }); casV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: journal.record.transactionId, rawTransactionSha256: journal.record.rawTransactionSha256, journalSha256, fromState: 'send-attempted', toState: 'reconciled' }); return Object.freeze({ runId: id, transactionId: journal.record.transactionId, recipientCount: journal.record.recipients.length, status: 'accepted-zero-conf' });
  } finally { if (ownsRpc) { try { await capability.close?.(); } catch {} } }
}

/** Read-only exact recovery. It performs no broadcast and never retries a send. */
export async function recoverV2BetaOperatorFanout({ operatorRoot, runId: requestedRunId } = {}, { rpc = undefined } = {}) {
  const id = runId(requestedRunId); const journal = await readJournal(operatorRoot, id); const journalSha256 = journal.sha256; const ownsRpc = rpc === undefined; const capability = assertOperatorFanoutRpc(rpc ?? await createPublicChipnetFulcrumRpc());
  try {
  const operation = inspectV2BetaOperatorSourceRegistry({ operatorRoot }).fanoutOperations.find((entry) => entry.runId === id);
  if (operation === undefined || operation.transactionId !== journal.record.transactionId || operation.rawTransactionSha256 !== journal.record.rawTransactionSha256 || operation.journalSha256 !== journalSha256) fail('OPERATOR_FANOUT_RECOVERY_REJECTED', 'canonical fanout operation does not bind this journal snapshot');
  if (!['send-attempted', 'indeterminate', 'reconciled'].includes(operation.state)) fail('OPERATOR_FANOUT_RECOVERY_REJECTED', 'recovery is only permitted after the durable send boundary');
  try { await verifyExactFanoutOutputs(journal.record, capability); } catch (error) { return Object.freeze({ runId: id, transactionId: journal.record.transactionId, status: 'not-observed-zero-conf', inspected: true, errorCode: error?.code ?? 'OPERATOR_FANOUT_READBACK_REJECTED' }); }
  registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId: journal.record.transactionId, sources: registrySources(journal.record) });
  for (const state of ['send-attempted', 'indeterminate']) { try { casV2BetaOperatorFanoutOperation({ operatorRoot, runId: id, transactionId: journal.record.transactionId, rawTransactionSha256: journal.record.rawTransactionSha256, journalSha256, fromState: state, toState: 'reconciled' }); break; } catch (error) { if (error?.code !== 'SOURCE_REGISTRY_CAS_CONFLICT') throw error; } }
  return Object.freeze({ runId: id, transactionId: journal.record.transactionId, recipientCount: journal.record.recipients.length, status: 'reconciled-zero-conf', inspected: true });
  } finally { if (ownsRpc) { try { await capability.close?.(); } catch {} } }
}
