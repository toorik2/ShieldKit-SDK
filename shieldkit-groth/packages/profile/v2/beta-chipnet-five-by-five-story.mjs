/**
 * Offline builder and separately acknowledged broadcaster for one explicitly
 * unqualified Chipnet beta story: five deposits followed by five withdrawals.
 * Every serial rolling-bundle transaction is built, proven, signed, VM-tested,
 * and journaled before this module can send any of them.
 */
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

import { secp256k1 } from '@bitauth/libauth';

import { buildDirectV2CircuitInput } from '../../action/v2/circuit-witness.mjs';
import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
} from '../../action/v2/notes.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import {
  assembleV2DirectSettlement,
  prepareV2DirectSettlement,
  signV2DirectSettlement,
} from '../../action/v2/settlement.mjs';
import { applyDirectV2Transition, createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { assertLayer1BchnChipnetRpc } from '../../kit/chipnet-rpc.mjs';
import { broadcastStagedOperation, commitStagedOperation, loadPendingOperation, stageOperation, transactionIdFromHex } from '../../kit/transaction-coordinator.mjs';
import { atomicWriteJson, PRIVATE_FILE_MODE, readJsonFile } from '../../kit/secure-files.mjs';
import { createV2LocalVmEvidence, V2_VM_PROFILE } from '../../kit/v2/vm-evidence.mjs';
import { deriveV2ChipnetFundingWallet } from '../../kit/v2/funding-wallet.mjs';
import { assertV2BetaChipnetDeploymentCapability } from './beta-chipnet-deployment.mjs';
import { assertV2BetaChipnetRuntimeResolution, deriveV2BetaChipnetSettlementPins } from './beta-chipnet-runtime.mjs';
import { canonicalizeJcs, deriveProfileId, validateProfileCore } from './profile-core.mjs';
import { proveV2DirectGroth16Default } from '../../prove/v2/groth16-proof-worker.mjs';
import { BABYJUB_SUBGROUP_ORDER } from '../../recover/portable-core.mjs';
import { buildDirectV2Pf10BetaActionWitness, DIRECT_V2_PF10_STATE_UNLOCK_BYTES, DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES } from '../../unlock-builder/v2/pf10-action-witness.mjs';

const require = createRequire(import.meta.url);
const LIBAUTH_VERSION = require('@bitauth/libauth/package.json').version;
const HASH = /^[0-9a-f]{64}$/u;
const HEX = /^(?:[0-9a-f]{2})+$/u;
export const V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA = 'shieldkit-v2-beta-chipnet-five-by-five-story-v1';
export const V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT = 'acknowledge-beta-unqualified-chipnet-five-deposit-five-withdrawal-story';

export class V2BetaFiveByFiveStoryError extends Error {
  constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaFiveByFiveStoryError'; this.code = code; }
}
const fail = (code, message, options = undefined) => { throw new V2BetaFiveByFiveStoryError(code, message, options); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('BETA_STORY_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('BETA_STORY_INVALID', `${label} has missing or unknown properties`);
  return value;
}
function hex(value, label) { if (typeof value !== 'string' || !HEX.test(value)) fail('BETA_STORY_INVALID', `${label} must be lowercase nonempty hex`); return value; }
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail('BETA_STORY_INVALID', `${label} must be lowercase 32-byte hex`); return value; }
function privateDirectory(directory) {
  if (typeof directory !== 'string' || directory.length === 0) fail('BETA_STORY_PATH_REJECTED', 'storyDirectory is required');
  const root = path.resolve(directory); let stat;
  try { stat = lstatSync(root); } catch (error) { fail('BETA_STORY_PATH_REJECTED', `storyDirectory is unavailable: ${error.message}`, { cause: error }); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || realpathSync(root) !== root) fail('BETA_STORY_PATH_REJECTED', 'storyDirectory must be a private canonical directory');
  return root;
}
function shieldkitDirectory(directory) {
  const root = privateDirectory(directory); const child = path.join(root, '.shieldkit');
  if (existsSync(child)) { const stat = lstatSync(child); if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || realpathSync(child) !== child) fail('BETA_STORY_PATH_REJECTED', '.shieldkit story ancestry must be private and canonical'); }
  return child;
}
function storyPath(directory) { return path.join(shieldkitDirectory(directory), 'v2-beta-chipnet-five-by-five-story.json'); }
function walletPath(directory) { return path.join(shieldkitDirectory(directory), 'v2-beta-chipnet-five-by-five-note-wallet.json'); }
function actionArtifactPath(directory, index) { return path.join(shieldkitDirectory(directory), `v2-beta-chipnet-five-by-five-action-${index + 1}.json`); }
function broadcastReadbackPath(directory, index) { return path.join(shieldkitDirectory(directory), `v2-beta-chipnet-five-by-five-broadcast-${index + 1}.json`); }
function assertAcknowledgement(value) { if (value !== V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT) fail('BETA_STORY_ACKNOWLEDGEMENT_REQUIRED', 'exact beta acknowledgement is required'); }
function assertBchnRpc(value) { try { return assertLayer1BchnChipnetRpc(value); } catch (error) { fail('BETA_STORY_RPC_REJECTED', error instanceof Error ? error.message : 'branded BCHN Chipnet RPC capability is required', { cause: error }); } }
function settlementPins(runtimeResolution) { return deriveV2BetaChipnetSettlementPins(runtimeResolution); }
function freshBabyJubSecret(label) {
  for (let attempts = 0; attempts < 4096; attempts += 1) {
    const candidate = randomBytes(32).toString('hex');
    const scalar = BigInt(`0x${candidate}`);
    if (scalar > 0n && scalar < BABYJUB_SUBGROUP_ORDER) return candidate;
  }
  fail('BETA_STORY_WALLET_FAILED', `could not sample a canonical ${label}`);
}
function freshChangeWallets(count, forbiddenLocks = new Set()) {
  const wallets = [];
  const locks = new Set();
  while (wallets.length < count) {
    let wallet;
    try { wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: randomBytes(32).toString('hex') }); }
    catch { continue; }
    if (locks.has(wallet.lockingBytecodeHex) || forbiddenLocks.has(wallet.lockingBytecodeHex)) continue;
    locks.add(wallet.lockingBytecodeHex);
    wallets.push(wallet);
  }
  return Object.freeze(wallets);
}
function freshNoteWallet(profileId, instanceId) {
  const spendSecret = freshBabyJubSecret('spend secret');
  const incomingViewSecret = freshBabyJubSecret('incoming-view secret');
  const address = deriveDirectV2Address({ networkId: 2, profileId, instanceId, spendSecret, incomingViewSecret });
  return Object.freeze({ address, incomingViewSecret, spendSecret });
}
function loadOrCreateWallet(directory, profileId, instanceId, fundingLockingBytecodeHex) {
  const filename = walletPath(directory);
  if (existsSync(filename)) {
    let value = readJsonFile(filename);
    const legacyKeys = ['address', 'incomingViewSecret', 'instanceId', 'profileId', 'schema', 'spendSecret'];
    if (Object.keys(value).sort().join('\u0000') === legacyKeys.sort().join('\u0000')) {
      value = { ...value, changeWallets: freshChangeWallets(10, new Set([fundingLockingBytecodeHex])) };
      atomicWriteJson(filename, value, { mode: PRIVATE_FILE_MODE });
    }
    exact(value, ['address', 'changeWallets', 'incomingViewSecret', 'instanceId', 'profileId', 'schema', 'spendSecret'], 'stored beta note wallet');
    if (value.schema !== `${V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA}-note-wallet` || value.profileId !== profileId || value.instanceId !== instanceId || canonicalizeJcs(value.address) !== canonicalizeJcs(deriveDirectV2Address({ networkId: 2, profileId, instanceId, spendSecret: value.spendSecret, incomingViewSecret: value.incomingViewSecret }))) fail('BETA_STORY_WALLET_REJECTED', 'stored beta note wallet does not bind this exact profile/instance/secrets');
    if (!Array.isArray(value.changeWallets) || value.changeWallets.length !== 10) fail('BETA_STORY_WALLET_REJECTED', 'stored beta note wallet must contain ten private change wallets');
    const changeWallets = value.changeWallets.map((stored, index) => {
      let derived; try { derived = deriveV2ChipnetFundingWallet({ privateKeyHex: stored?.privateKeyHex }); } catch (error) { fail('BETA_STORY_WALLET_REJECTED', `stored change wallet ${index + 1} is invalid`, { cause: error }); }
      if (canonicalizeJcs(stored) !== canonicalizeJcs(derived)) fail('BETA_STORY_WALLET_REJECTED', `stored change wallet ${index + 1} does not match its private scalar`);
      return derived;
    });
    if (new Set(changeWallets.map((entry) => entry.lockingBytecodeHex)).size !== 10) fail('BETA_STORY_WALLET_REJECTED', 'stored beta change wallets must use ten distinct locks');
    if (changeWallets.some((entry) => entry.lockingBytecodeHex === fundingLockingBytecodeHex)) fail('BETA_STORY_WALLET_REJECTED', 'stored beta change wallets must differ from the funding lock');
    return Object.freeze({ address: value.address, changeWallets: Object.freeze(changeWallets), incomingViewSecret: value.incomingViewSecret, spendSecret: value.spendSecret });
  }
  const wallet = freshNoteWallet(profileId, instanceId);
  const changeWallets = freshChangeWallets(10, new Set([fundingLockingBytecodeHex]));
  atomicWriteJson(filename, { schema: `${V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA}-note-wallet`, profileId, instanceId, spendSecret: wallet.spendSecret, incomingViewSecret: wallet.incomingViewSecret, address: wallet.address, changeWallets }, { mode: PRIVATE_FILE_MODE });
  return Object.freeze({ ...wallet, changeWallets });
}
function normalizeFunding(value, sourceHex) {
  exact(value, ['lockingBytecode', 'privateKeyHex'], 'story funding wallet');
  let wallet; try { wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: hash(value.privateKeyHex, 'funding.privateKeyHex') }); } catch (error) { fail('BETA_STORY_INVALID', error instanceof Error ? error.message : 'funding private scalar is invalid', { cause: error }); }
  const privateKey = Buffer.from(wallet.privateKeyHex, 'hex');
  if (transactionIdFromHex(sourceHex) === undefined) fail('BETA_STORY_INVALID', 'bootstrap source transaction is malformed');
  if (hex(value.lockingBytecode, 'funding.lockingBytecode') !== wallet.lockingBytecodeHex) fail('BETA_STORY_INVALID', 'funding locking bytecode must be the canonical P2PKH lock of the funding scalar');
  return Object.freeze({
    privateKey,
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    publicKey: Buffer.from(wallet.compressedPublicKeyHex, 'hex'),
    publicKeyHex: wallet.compressedPublicKeyHex,
  });
}
function transitionInput({ current, kind, profileId, instanceId, contextHash, output, spend, withdrawalLockingBytecodeHash, denominationSats }) {
  return Object.freeze({ kind, networkId: 2, profileId, instanceId, denominationSats, preState: current.state, noteTree: current.noteTree, nullifierTree: current.nullifierTree, transactionContextHash: contextHash, ...(output === undefined ? {} : { output }), ...(spend === undefined ? {} : { spend }), ...(withdrawalLockingBytecodeHash === undefined ? {} : { withdrawalLockingBytecodeHash }) });
}
function artifactCore({ denominationSats, index, kind, preState, transition, proofResult, prepared, signed }) {
  return Object.freeze({ index, kind, packetSha256: sha256(transition.packet), proofSha256: sha256(proofResult.proofBytes), transactionId: signed.txid, rawTransactionSha256: sha256(Buffer.from(signed.rawTransactionHex, 'hex')), contextHash: prepared.contextHash, preStateSha256: sha256(encodeStateNftCommitment(preState, { denominationSats })), postStateSha256: sha256(encodeStateNftCommitment(transition.state, { denominationSats })) });
}
function validateStoryRecord(value) {
  exact(value, ['actions', 'claims', 'eligibility', 'evidenceSha256', 'genesisTransactionId', 'instanceId', 'profileId', 'schema', 'status', 'terminalStateHex', 'terminalStateSha256'], 'beta five-by-five story record');
  const { evidenceSha256, ...core } = value;
  if (value.schema !== V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA || !['staged-beta-unqualified', 'accepted-zero-conf-beta-unqualified'].includes(value.status) || value.eligibility !== 'beta-single-contributor-unqualified' || !HASH.test(value.profileId) || !HASH.test(value.instanceId) || !HASH.test(value.genesisTransactionId) || !HASH.test(value.terminalStateSha256) || !/^[0-9a-f]{256}$/u.test(value.terminalStateHex) || sha256(Buffer.from(value.terminalStateHex, 'hex')) !== value.terminalStateSha256 || canonicalSha256(core) !== hash(evidenceSha256, 'story evidenceSha256') || !Array.isArray(value.actions) || value.actions.length !== 10) fail('BETA_STORY_EVIDENCE_REJECTED', 'durable beta story evidence is malformed or unqualified boundary changed');
  exact(value.claims, ['broadcasted', 'mined', 'productionQualified'], 'beta story claims');
  if (typeof value.claims.broadcasted !== 'boolean' || value.claims.mined !== false || value.claims.productionQualified !== false || (value.status === 'staged-beta-unqualified' ? value.claims.broadcasted !== false : value.claims.broadcasted !== true)) fail('BETA_STORY_EVIDENCE_REJECTED', 'beta story claims/status are inconsistent');
  value.actions.forEach((action, index) => {
    exact(action, ['contextHash', 'index', 'kind', 'packetSha256', 'postStateSha256', 'preStateSha256', 'proofSha256', 'rawTransactionSha256', 'transactionId'], `beta story action ${index}`);
    if (action.index !== index || action.kind !== (index < 5 ? 'deposit' : 'withdrawal') || !HASH.test(action.contextHash) || !HASH.test(action.packetSha256) || !HASH.test(action.postStateSha256) || !HASH.test(action.preStateSha256) || !HASH.test(action.proofSha256) || !HASH.test(action.rawTransactionSha256) || !HASH.test(action.transactionId)) fail('BETA_STORY_EVIDENCE_REJECTED', 'beta story action evidence has an invalid ordinal, kind, or exact hash');
  });
  return value;
}

/** Build all ten exact signed transactions offline and stage their bytes atomically. */
export async function buildV2BetaChipnetFiveByFiveStory(value) {
  exact(value, ['acknowledgement', 'bootstrapSourceTransactionHex', 'deploymentBinding', 'funding', 'genesisRawTransactionHex', 'maximumLiveNotes', 'profileCore', 'runtimeResolution', 'storyDirectory', 'withdrawalLockingBytecode'], 'beta five-by-five build input');
  assertAcknowledgement(value.acknowledgement); const deployment = assertV2BetaChipnetDeploymentCapability(value.deploymentBinding); const runtime = assertV2BetaChipnetRuntimeResolution(value.runtimeResolution);
  validateProfileCore(value.profileCore); const profileId = deriveProfileId(value.profileCore);
  if (value.profileCore.network.id !== 2 || value.profileCore.network.name !== 'chipnet' || value.profileCore.denominationSats !== '10000000' || value.maximumLiveNotes !== '100000' || deployment.profileId !== profileId || runtime.identity.profileId !== profileId || runtime.identity.instanceId !== deployment.instanceId || runtime.identity.maximumLiveNotes !== '100000' || runtime.identity.denominationSats !== '10000000' || runtime.runtimeMaterial.profileId !== profileId || runtime.runtimeMaterial.instanceId !== deployment.instanceId || runtime.descriptorSha256 !== deployment.zeroConfEvidenceSha256 || runtime.manifestSha256 !== runtime.runtimeManifestSha256) fail('BETA_STORY_BINDING_REJECTED', 'branded beta runtime/deployment/profile/capacity bindings differ');
  const directory = privateDirectory(value.storyDirectory); const sourceHex = hex(value.bootstrapSourceTransactionHex, 'bootstrapSourceTransactionHex'); const genesisHex = hex(value.genesisRawTransactionHex, 'genesisRawTransactionHex');
  if (transactionIdFromHex(sourceHex) !== deployment.sourceTransactionId || transactionIdFromHex(genesisHex) !== deployment.genesisOutpoint.txid) fail('BETA_STORY_BINDING_REJECTED', 'source or genesis raw transaction differs from deployment capability');
  const funding = normalizeFunding(value.funding, sourceHex); const denominationSats = value.profileCore.denominationSats; const pins = settlementPins(runtime); const wallet = loadOrCreateWallet(directory, profileId, deployment.instanceId, funding.lockingBytecodeHex); const withdrawalLockingBytecode = Buffer.from(hex(value.withdrawalLockingBytecode, 'withdrawalLockingBytecode'), 'hex');
  if (withdrawalLockingBytecode.toString('hex') === funding.lockingBytecodeHex) {
    fail(
      'BETA_STORY_WITHDRAWAL_TO_FUNDER_REJECTED',
      'withdrawalLockingBytecode must not equal the funding fee wallet lock; use a dedicated external payout lock',
    );
  }
  const noteAccount = Object.freeze({ address: wallet.address, incomingViewSecret: wallet.incomingViewSecret, spendSecret: wallet.spendSecret });
  let current = createDirectV2PoolModel({ profileId, maximumLiveNotes: value.maximumLiveNotes, denominationSats });
  if (sha256(encodeStateNftCommitment(current.state, { denominationSats })) !== deployment.initialStateSha256) fail('BETA_STORY_BINDING_REJECTED', 'maximumLiveNotes/profile initial model does not equal accepted deployment state');
  const notes = []; const actions = []; let previousBundleTransactionHex = genesisHex;
  for (let index = 0; index < 10; index += 1) {
    const kind = index < 5 ? 'deposit' : 'withdrawal'; const preState = current.state; const actionSequence = BigInt(current.state.actionSequence) + 1n;
    let output; let recovered; let spend; let circuitSpend; let withdrawalLockingBytecodeHash;
    if (kind === 'deposit') {
      output = constructDirectV2Output({ address: wallet.address, postActionSequence: actionSequence.toString(), rng: { bytes: (length) => randomBytes(length) } });
      recovered = recoverDirectV2Output({ account: noteAccount, outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord }); notes.push(Object.freeze({ output, recovered, noteIndex: String(current.state.noteCount) }));
    } else {
      const note = notes[index - 5]; if (note === undefined) fail('BETA_STORY_NOTE_REJECTED', 'withdrawal has no owned deposit note');
      spend = { inputNoteLeaf: note.output.public.outputNoteLeaf, noteIndex: note.noteIndex, publicNullifier: note.recovered.nullifier };
      circuitSpend = { spendSecret: wallet.spendSecret, incomingViewPublicKey: wallet.address.incomingViewPublicKey, rho: note.recovered.rho, r: note.recovered.r, encryptedRecord: note.recovered.encryptedRecord };
      withdrawalLockingBytecodeHash = sha256(withdrawalLockingBytecode);
    }
    const publicOutput = output === undefined ? undefined : { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord };
    const preview = applyDirectV2Transition(transitionInput({ current, kind, profileId, instanceId: deployment.instanceId, contextHash: '00'.repeat(32), output: publicOutput, spend, withdrawalLockingBytecodeHash, denominationSats }));
    const prepared = prepareV2DirectSettlement({ changeLockingBytecode: Buffer.from(wallet.changeWallets[index].lockingBytecodeHex, 'hex'), denominationSats, feeRateSatsPerByte: '1', funding: { outpointIndex: String(index + 1), publicKey: funding.publicKey, sourceTransactionHex: sourceHex }, instanceId: deployment.instanceId, kind, networkId: 2, payoutLockingBytecode: kind === 'withdrawal' ? withdrawalLockingBytecode : null, pins, postState: preview.state, preState: current.state, previousBundleTransactionHex, profileId, unlockingBytecodeLengths: { verifier: [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES], state: DIRECT_V2_PF10_STATE_UNLOCK_BYTES } });
    const transition = applyDirectV2Transition(transitionInput({ current, kind, profileId, instanceId: deployment.instanceId, contextHash: prepared.contextHash, output: publicOutput, spend, withdrawalLockingBytecodeHash, denominationSats }));
    const circuitInput = buildDirectV2CircuitInput({ transition, ...(kind === 'deposit' ? { output } : { spend: circuitSpend }), denominationSats });
    const proofResult = await proveV2DirectGroth16Default({ artifacts: runtime.proofArtifacts, circuitInput, expectedPublicInputs: transition.publicInputs, workspaceDirectory: directory });
    const witness = buildDirectV2Pf10BetaActionWitness({ actionPacket: transition.packet, denominationSats, proofResult, runtimeMaterial: runtime.runtimeMaterial });
    const assembled = assembleV2DirectSettlement(prepared, { actionPacket: transition.packet, verifierUnlockingBytecodes: witness.verifierUnlockingBytecodes, stateUnlockingBytecode: witness.stateUnlockingBytecode });
    let signedOnce = false;
    const signed = await signV2DirectSettlement(assembled, { signFunding: async (request) => { if (signedOnce || request.publicKeyHex !== funding.publicKeyHex || request.contextHash !== prepared.contextHash) fail('BETA_STORY_SIGNING_REJECTED', 'funding signing request differs from exact prepared action'); signedOnce = true; const signature = secp256k1.signMessageHashSchnorr(funding.privateKey, Buffer.from(request.digestHex, 'hex')); if (!(signature instanceof Uint8Array) || signature.length !== 64) fail('BETA_STORY_SIGNING_REJECTED', 'Schnorr signing failed'); return signature; }, createLocalVmEvidence: async (request) => createV2LocalVmEvidence({ ...request, tool: { name: '@bitauth/libauth', version: LIBAUTH_VERSION, vm: V2_VM_PROFILE, profileId, profileSha256: canonicalSha256(value.profileCore) } }) });
    if (!signedOnce) fail('BETA_STORY_SIGNING_REJECTED', 'funding signer was not invoked');
    const artifact = artifactCore({ denominationSats, index, kind, preState, transition, proofResult, prepared, signed });
    atomicWriteJson(actionArtifactPath(directory, index), {
      schema: `${V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA}-action-artifact`,
      eligibility: 'beta-single-contributor-unqualified',
      index,
      kind,
      artifact,
      packetHex: Buffer.from(transition.packet).toString('hex'),
      proofHex: Buffer.from(proofResult.proofBytes).toString('hex'),
      unsignedTransactionHex: assembled.unsignedTransactionHex,
      signedTransactionHex: signed.rawTransactionHex,
      localVmEvidenceHex: signed.localVmEvidenceHex,
    }, { mode: PRIVATE_FILE_MODE });
    const action = Object.freeze({ index, kind, transition, proofResult, prepared, signed, artifact }); actions.push(action); previousBundleTransactionHex = signed.rawTransactionHex; current = transition;
  }
  const terminalStateHex = Buffer.from(encodeStateNftCommitment(current.state, { denominationSats })).toString('hex');
  const core = Object.freeze({ schema: V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA, status: 'staged-beta-unqualified', eligibility: 'beta-single-contributor-unqualified', claims: Object.freeze({ broadcasted: false, mined: false, productionQualified: false }), profileId, instanceId: deployment.instanceId, genesisTransactionId: deployment.genesisOutpoint.txid, terminalStateHex, terminalStateSha256: sha256(Buffer.from(terminalStateHex, 'hex')), actions: Object.freeze(actions.map((action) => action.artifact)) });
  const record = Object.freeze({ ...core, evidenceSha256: canonicalSha256(core) });
  let staged; try { staged = stageOperation({ poolDirectory: directory, kind: 'v2-beta-chipnet-five-deposit-five-withdrawal', network: 'chipnet', setupMode: 'development-only', transactions: actions.map((action, index) => ({ role: index < 5 ? `deposit-${index + 1}` : `withdrawal-${index - 4}`, txid: action.signed.txid, hex: action.signed.rawTransactionHex })), nextState: { ...core, status: 'accepted-zero-conf-beta-unqualified', claims: { broadcasted: true, mined: false, productionQualified: false } }, ledgerRecord: { schema: V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA, status: 'accepted-zero-conf-beta-unqualified', eligibility: core.eligibility, claims: { broadcasted: true, mined: false, productionQualified: false }, profileId, instanceId: deployment.instanceId, actionCount: 10 }, publicResult: { profileId, instanceId: deployment.instanceId, actionCount: 10 } }); } catch (error) { fail('BETA_STORY_STAGE_REJECTED', error instanceof Error ? error.message : 'could not stage beta story', { cause: error }); }
  atomicWriteJson(storyPath(directory), record, { mode: PRIVATE_FILE_MODE });
  return Object.freeze({ path: storyPath(directory), journalPath: staged.journalPath, operationId: staged.journal.operationId, record });
}

/** Send only a fully built/staged story, then require exact BCHN raw-byte readback. */
export async function broadcastV2BetaChipnetFiveByFiveStory({ acknowledgement, rpc, storyDirectory } = {}) {
  assertAcknowledgement(acknowledgement); const checkedRpc = assertBchnRpc(rpc); const directory = privateDirectory(storyDirectory); const loaded = validateStoryRecord(readJsonFile(storyPath(directory)));
  if (!['staged-beta-unqualified', 'accepted-zero-conf-beta-unqualified'].includes(loaded.status)) fail('BETA_STORY_EVIDENCE_REJECTED', 'durable staged or accepted beta story is required');
  const pending = loadPendingOperation(directory); if (pending === null || pending.journal.kind !== 'v2-beta-chipnet-five-deposit-five-withdrawal' || pending.journal.transactions.length !== 10) fail('BETA_STORY_STAGE_REJECTED', 'exact ten-action coordinator journal is required');
  if (pending.journal.network !== 'chipnet' || pending.journal.setupMode !== 'development-only' || pending.journal.publicResult?.profileId !== loaded.profileId || pending.journal.publicResult?.instanceId !== loaded.instanceId || pending.journal.publicResult?.actionCount !== 10) fail('BETA_STORY_STAGE_REJECTED', 'coordinator identity or beta boundary differs from the exact story');
  pending.journal.transactions.forEach((transaction, index) => {
    if (transaction.role !== (index < 5 ? `deposit-${index + 1}` : `withdrawal-${index - 4}`) || transaction.txid !== loaded.actions[index].transactionId || sha256(Buffer.from(transaction.hex, 'hex')) !== loaded.actions[index].rawTransactionSha256) fail('BETA_STORY_EVIDENCE_REJECTED', 'story evidence does not bind the exact ordered coordinator transaction bytes');
  });
  let journal;
  try {
    journal = await broadcastStagedOperation({
      journalPath: pending.journalPath,
      rpc: checkedRpc,
      afterTransactionBroadcast: async ({ transaction, readback }) => {
        const index = pending.journal.transactions.findIndex((entry) => entry.txid === transaction.txid);
        if (index < 0 || readback?.transactionId !== transaction.txid
          || readback?.rawTransactionHex !== transaction.hex) {
          fail('BETA_STORY_READBACK_REJECTED', 'BCHN readback differs from an exact staged beta story transaction');
        }
        atomicWriteJson(broadcastReadbackPath(directory, index), {
          schema: `${V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA}-broadcast-readback`,
          status: 'accepted-zero-conf-beta-unqualified',
          claims: { broadcasted: true, mined: false, productionQualified: false },
          index,
          transactionId: transaction.txid,
          rawTransactionSha256: sha256(Buffer.from(transaction.hex, 'hex')),
        }, { mode: PRIVATE_FILE_MODE });
      },
    });
  } catch (error) {
    if (['EXACT_BROADCAST_READBACK_FAILED', 'EXACT_BROADCAST_READBACK_INVALID']
      .includes(error?.code)) {
      fail('BETA_STORY_READBACK_REJECTED', error.message, { cause: error });
    }
    throw error instanceof V2BetaFiveByFiveStoryError
      ? error
      : new V2BetaFiveByFiveStoryError(
        'BETA_STORY_BROADCAST_REJECTED',
        error instanceof Error ? error.message : 'BCHN broadcast failed',
        { cause: error },
      );
  }
  for (const [index, transaction] of journal.transactions.entries()) {
    if (transaction.readback?.rawTransactionSha256 !== sha256(Buffer.from(transaction.hex, 'hex'))
      || typeof transaction.readback?.observedAt !== 'string'
      || !Number.isFinite(Date.parse(transaction.readback.observedAt))) {
      fail('BETA_STORY_READBACK_REJECTED', 'coordinator lacks durable exact readback for a staged beta story transaction');
    }
    atomicWriteJson(broadcastReadbackPath(directory, index), { schema: `${V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA}-broadcast-readback`, status: 'accepted-zero-conf-beta-unqualified', claims: { broadcasted: true, mined: false, productionQualified: false }, index, transactionId: transaction.txid, rawTransactionSha256: sha256(Buffer.from(transaction.hex, 'hex')) }, { mode: PRIVATE_FILE_MODE });
  }
  const terminal = journal.transactions[9]; const observedState = await checkedRpc.gettxout(terminal.txid, 0); const token = observedState?.tokenData ?? observedState?.token; const category = token?.category; const expectedCategory = Buffer.from(loaded.instanceId, 'hex').reverse().toString('hex');
  if (category !== expectedCategory || Buffer.from(category ?? '', 'hex').reverse().toString('hex') !== loaded.instanceId || token?.amount !== '0' || token?.nft?.capability !== 'mutable' || token?.nft?.commitment !== loaded.terminalStateHex) fail('BETA_STORY_READBACK_REJECTED', 'BCHN terminal state NFT differs from the exact serial story terminal state');
  const { evidenceSha256: _prior, ...prior } = loaded; const core = { ...prior, status: 'accepted-zero-conf-beta-unqualified', claims: { broadcasted: true, mined: false, productionQualified: false } }; const record = Object.freeze({ ...core, evidenceSha256: canonicalSha256(core) }); atomicWriteJson(storyPath(directory), record, { mode: PRIVATE_FILE_MODE });
  let committed; try { committed = commitStagedOperation({ journalPath: pending.journalPath, statePath: path.join(shieldkitDirectory(directory), 'v2-beta-chipnet-five-by-five-state.json'), ledgerPath: path.join(shieldkitDirectory(directory), 'v2-beta-chipnet-five-by-five-ledger.jsonl') }); } catch (error) { fail('BETA_STORY_COMMIT_REJECTED', error instanceof Error ? error.message : 'could not commit accepted zero-conf story', { cause: error }); }
  return Object.freeze({ path: storyPath(directory), journalPath: pending.journalPath, operationId: committed.operationId, record, broadcast: true, rpcBackend: checkedRpc.backend });
}
