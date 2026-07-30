/* TEST-ONLY: this file never supplies evidence capable of producing Q-09. */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signMessage } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { decodeTransactionBch, encodeTransaction } from '@bitauth/libauth';

import { decodeActionPacket, encodeActionPacket } from '../packages/action/v2/packet.mjs';
import { encodeDirectV2BindingUnlock } from '../packages/action/v2/binding-unlock.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { encodeStateNftCommitment } from '../packages/action/v2/state.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  createRollingFixtureArtifacts,
  createFixtureEvidence,
  FIXTURE_BINDING_LOCK,
  FIXTURE_BINDING_REDEEM,
  FIXTURE_CARRIER_COUNT,
  FIXTURE_DENOMINATION_SATS,
  FIXTURE_INSTANCE_ID,
  FIXTURE_PROFILE_ID,
  FIXTURE_PROFILE_SHA256,
  FIXTURE_STATE_BASE_SATS,
  FIXTURE_STATE_CONTEXT,
  fixturePreState,
  resignFixtureFundingInput,
} from '../packages/kit/v2/v2-test-fixtures.mjs';
import {
  assertV2Q09Q08PairBinding,
  parseChainObservers,
  parseV2Q09Arguments,
  runV2Q09ChipnetSoak,
  validateV2Q09ChainEvidence,
  validateV2Q09SettlementJournal,
  validateV2Q09PlaygroundEvidence,
  validateV2Q09PlaygroundCandidate,
  V2Q09ChipnetSoakError,
  V2_Q09_RESULT_SCHEMA,
  V2_Q09_SOURCE_PIN_SCHEMA,
} from './v2-chipnet-soak.mjs';

const commit = 'aa'.repeat(20);
const tree = 'bb'.repeat(20);
const identity = Object.freeze({
  profileId: '11'.repeat(32), profileSha256: '12'.repeat(32), instanceId: '22'.repeat(32), descriptorSha256: '33'.repeat(32),
  manifestSha256: '44'.repeat(32), finalLocksSha256: '55'.repeat(32), sourceCommit: commit,
  runtimeMaterialSha256: '88'.repeat(32),
  sourceTree: tree, releaseRootId: 'final-chipnet', releaseBootstrapSha256: '77'.repeat(32), denominationSats: '10000000', maximumLiveNotes: '210000000',
  genesis: { transactionId: '66'.repeat(32), outpointIndex: 0 }, initialStateHex: '00'.repeat(128),
  carrierCount: 10, stateLockingBytecodeHex: '51', stateBaseSats: '546', topologyId: 'pf10-fused-q-genesis',
});

/*
 * TEST-ONLY structural subject. This reuses the maintained V2 rolling fixture
 * and production packet/state/transaction codecs. It deliberately has no
 * chain or VM qualification meaning: headers and observer attestations exist
 * only to drive the offline parser past its immutable-evidence guards.
 */
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const sha256Json = (value) => createHash('sha256').update(canonicalizeJcs(value)).digest('hex');
const fixtureIdentity = (genesis) => Object.freeze({
  profileId: FIXTURE_PROFILE_ID,
  profileSha256: FIXTURE_PROFILE_SHA256,
  instanceId: FIXTURE_INSTANCE_ID,
  descriptorSha256: '33'.repeat(32),
  manifestSha256: '44'.repeat(32),
  finalLocksSha256: '55'.repeat(32),
  sourceCommit: commit,
  sourceTree: tree,
  denominationSats: FIXTURE_DENOMINATION_SATS,
  maximumLiveNotes: '32',
  genesis: { transactionId: genesis, outpointIndex: 0 },
  initialStateHex: encodeStateNftCommitment(fixturePreState(), FIXTURE_STATE_CONTEXT).toString('hex'),
  carrierCount: FIXTURE_CARRIER_COUNT,
  stateLockingBytecodeHex: '51',
  stateBaseSats: FIXTURE_STATE_BASE_SATS.toString(),
  topologyId: 'test-only-fixture',
});

function decodedTransaction(rawTransactionHex) {
  const decoded = decodeTransactionBch(Uint8Array.from(Buffer.from(rawTransactionHex, 'hex')));
  if (typeof decoded === 'string') throw new Error(`fixture transaction decode failed: ${decoded}`);
  return decoded;
}

function transactionHex(transaction) {
  return Buffer.from(encodeTransaction(transaction)).toString('hex');
}

function transactionId(rawTransactionHex) {
  return parseV2RawTransaction(rawTransactionHex).txid;
}

function packetFor({ kind = 'deposit', preState, postState, instanceId = FIXTURE_INSTANCE_ID }) {
  return encodeActionPacket({
    kind,
    networkId: 2,
    instanceId,
    preState,
    postState,
    publicNullifier: '00'.repeat(32),
    outputNoteLeaf: kind === 'withdrawal' ? '00'.repeat(32) : fr(4),
    encryptedRecord: kind === 'withdrawal' ? Buffer.alloc(128) : Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: '00'.repeat(32),
    transactionContextHash: '99'.repeat(32),
  }, FIXTURE_STATE_CONTEXT);
}

function state({ noteCount, nullifierCount, actionSequence, noteRoot }) {
  const live = BigInt(noteCount) - BigInt(nullifierCount);
  return {
    profileId: FIXTURE_PROFILE_ID,
    noteRoot: fr(noteRoot),
    nullifierRoot: fr(2),
    noteCount: String(noteCount),
    nullifierCount: String(nullifierCount),
    maximumLiveNotes: '32',
    reserveSats: (live * BigInt(FIXTURE_DENOMINATION_SATS)).toString(),
    actionSequence: String(actionSequence),
  };
}

function rewriteFixtureTransaction(baseRaw, {
  packet,
  previousOutpoint,
  postState,
  sourceTransactionHexes = undefined,
}) {
  const transaction = decodedTransaction(baseRaw);
  transaction.inputs[FIXTURE_CARRIER_COUNT].unlockingBytecode = Uint8Array.from(encodeDirectV2BindingUnlock({
    packet,
    redeemScript: FIXTURE_BINDING_REDEEM,
    sourceLockingBytecode: FIXTURE_BINDING_LOCK,
  }));
  if (previousOutpoint !== undefined) {
    transaction.inputs[FIXTURE_CARRIER_COUNT + 1].outpointTransactionHash = Uint8Array.from(Buffer.from(previousOutpoint.txid, 'hex'));
    transaction.inputs[FIXTURE_CARRIER_COUNT + 1].outpointIndex = previousOutpoint.vout;
  }
  if (postState !== undefined) {
    transaction.outputs[0].token.nft.commitment = Uint8Array.from(encodeStateNftCommitment(postState, FIXTURE_STATE_CONTEXT));
    transaction.outputs[0].valueSatoshis = FIXTURE_STATE_BASE_SATS + BigInt(postState.reserveSats);
  }
  const rawTransactionHex = transactionHex(transaction);
  return sourceTransactionHexes === undefined
    ? rawTransactionHex
    : resignFixtureFundingInput({
      rawTransactionHex,
      carrierCount: FIXTURE_CARRIER_COUNT,
      sourceTransactionHexes,
    });
}

function candidate(rawTransactionHex, packet, included = undefined, localVmEvidenceHex = undefined) {
  const base = {
    transactionId: transactionId(rawTransactionHex),
    rawTransactionHex,
    packetHex: Buffer.from(packet).toString('hex'),
    stateOutputIndex: 0,
  };
  return included === undefined
    ? { ...base, ...(localVmEvidenceHex === undefined ? {} : { localVmEvidenceHex }) }
    : { ...included, ...base };
}

function contentionVmEvidenceHex(artifacts, rawTransactionHex, stateSourceTransactionHex, { swapFirstTwoCarrierSources = false } = {}) {
  const sourceTransactionHexes = [...artifacts.sourceTransactionHexes];
  sourceTransactionHexes[FIXTURE_CARRIER_COUNT + 1] = stateSourceTransactionHex;
  if (swapFirstTwoCarrierSources) [sourceTransactionHexes[0], sourceTransactionHexes[1]] = [sourceTransactionHexes[1], sourceTransactionHexes[0]];
  return Buffer.from(createFixtureEvidence({ rawTransactionHex, sourceTransactionHexes })).toString('hex');
}

function signed(statement, observers) {
  const bytes = Buffer.from(canonicalizeJcs(statement), 'utf8');
  return observers.map(({ id, privateKey }) => ({ algorithm: 'ed25519', observerId: id, signatureBase64: signMessage(null, bytes, privateKey).toString('base64') }));
}

function deliveryJournal(candidateTransactionId, stateOutpoint, status, observers) {
  const payload = { candidateTransactionId, event: 'delivery', previousSha256: null, sequence: 0, stateOutpoint, status };
  const entry = { ...payload, entrySha256: sha256Json(payload) };
  const statement = { entries: [entry], schema: 'shieldkit-v2-direct-q09-delivery-journal/v1' };
  return { ...statement, attestations: signed(statement, observers) };
}

function signRecoveryJournal(recoveryJournal, observers) {
  const { attestations: _attestations, ...statement } = recoveryJournal;
  recoveryJournal.attestations = signed(statement, observers);
  return recoveryJournal;
}

function signPlaygroundRecord(record, observers) {
  const { attestations: _attestations, ...statement } = record;
  record.attestations = signed(statement, observers);
  return record;
}

function observerSet(subject) {
  return { observers: new Map(subject.fixture.observers.map(({ id, publicKey }) => [id, publicKey])) };
}

function validateSubjectRecord(subject, record) {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-playground-evidence-'));
  try {
    const path = join(root, 'playground.json');
    writeFileSync(path, canonicalizeJcs(record));
    return validateV2Q09PlaygroundEvidence(path, identity, subject.fixture.identity, subject.chain, { txids: [] }, observerSet(subject));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function subjectFixture() {
  const artifacts = createRollingFixtureArtifacts();
  const initial = fixturePreState();
  const genesisRaw = rewriteFixtureTransaction(artifacts.rawTransactionHex, {
    packet: artifacts.packet,
    postState: initial,
    sourceTransactionHexes: artifacts.sourceTransactionHexes,
  });
  const fixture = { raw: artifacts.rawTransactionHex, initial, identity: fixtureIdentity(transactionId(genesisRaw)), observers: ['observer-a', 'observer-b'].map((id) => ({ id, ...generateKeyPairSync('ed25519') })) };
  const chain = { sha256: 'cc'.repeat(32), headers: new Map(), tip: { height: 10_000 } };
  let height = 1;
  const include = (rawTransactionHex, packet) => {
    const txid = transactionId(rawTransactionHex); const blockHash = height.toString(16).padStart(64, '0');
    chain.headers.set(height, { hash: blockHash, transactionCount: 1, merkleRoot: txid, seconds: height });
    const evidence = candidate(rawTransactionHex, packet, { blockHash, blockHeight: height, merkleBranch: [], transactionIndex: 0 }); height += 1;
    return evidence;
  };
  const includedGenesis = include(genesisRaw, artifacts.packet);
  const { packetHex: _genesisPacket, stateOutputIndex: _genesisStateOutput, ...genesis } = includedGenesis;
  const transition = (kind, preState, postState, previousOutpoint, stateSourceTransactionHex) => {
    const packet = packetFor({ kind, preState, postState });
    const sourceTransactionHexes = [...artifacts.sourceTransactionHexes];
    sourceTransactionHexes[FIXTURE_CARRIER_COUNT + 1] = stateSourceTransactionHex;
    const rawTransactionHex = rewriteFixtureTransaction(artifacts.rawTransactionHex, {
      packet,
      previousOutpoint,
      postState,
      sourceTransactionHexes,
    });
    return { packet, rawTransactionHex, localVmEvidenceHex: contentionVmEvidenceHex(artifacts, rawTransactionHex, stateSourceTransactionHex), evidence: include(rawTransactionHex, packet), outpoint: { txid: transactionId(rawTransactionHex), vout: 0 }, state: postState };
  };
  let tip = { outpoint: { txid: transactionId(genesisRaw), vout: 0 }, state: initial, rawTransactionHex: genesisRaw };
  const fill = [];
  for (let ordinal = 1; ordinal <= 32; ordinal += 1) {
    const next = transition('deposit', tip.state, state({ noteCount: ordinal, nullifierCount: 0, actionSequence: ordinal, noteRoot: ordinal + 2 }), tip.outpoint, tip.rawTransactionHex);
    fill.push(next.evidence); tip = next;
  }
  const withdrawal = transition('withdrawal', tip.state, state({ noteCount: 32, nullifierCount: 1, actionSequence: 33, noteRoot: 35 }), tip.outpoint, tip.rawTransactionHex); tip = withdrawal;
  const refill = transition('deposit', tip.state, state({ noteCount: 33, nullifierCount: 1, actionSequence: 34, noteRoot: 36 }), tip.outpoint, tip.rawTransactionHex); tip = refill;
  const recoveredSpend = transition('withdrawal', tip.state, state({ noteCount: 33, nullifierCount: 2, actionSequence: 35, noteRoot: 36 }), tip.outpoint, tip.rawTransactionHex);
  const winner = transition('deposit', recoveredSpend.state, state({ noteCount: 34, nullifierCount: 2, actionSequence: 36, noteRoot: 37 }), recoveredSpend.outpoint, recoveredSpend.rawTransactionHex);
  const loser = transition('deposit', recoveredSpend.state, state({ noteCount: 34, nullifierCount: 2, actionSequence: 36, noteRoot: 38 }), recoveredSpend.outpoint, recoveredSpend.rawTransactionHex);
  const recoveryEntries = [...fill, withdrawal.evidence, refill.evidence];
  const recoveryStatement = { entries: recoveryEntries, recoveredNoteId: 'ab'.repeat(32), schema: 'shieldkit-v2-direct-q09-recovery-journal/v1' };
  const recoveryJournal = { ...recoveryStatement, attestations: signed(recoveryStatement, fixture.observers) };
  const record = {
    schema: 'shieldkit-v2-direct-q09-playground-evidence/v1', profileId: FIXTURE_PROFILE_ID, instanceId: FIXTURE_INSTANCE_ID,
    finalLocksSha256: fixture.identity.finalLocksSha256, playgroundDescriptorSha256: fixture.identity.descriptorSha256,
    sourceCommit: commit, sourceTree: tree, chainEvidenceSha256: chain.sha256, genesis,
    runs: [{ fill, withdraw: [withdrawal.evidence], refill: [refill.evidence], admission33: { action: 'deposit', result: 'rejected-capacity-before-proving', liveNoteCount: 32, proofInvocationCountBefore: 0, proofInvocationCountAfter: 0, admissionJournal: 'aa'.repeat(32) } }],
    eraseRecover: { deleteStateJournal: 'bb'.repeat(32), recoveryJournal, recoveredSpend: { ...recoveredSpend.evidence, recoveredNoteId: recoveryStatement.recoveredNoteId } },
    contention: { winnerTransactionId: winner.evidence.transactionId, attempts: [
      { candidate: candidate(winner.rawTransactionHex, winner.packet, undefined, winner.localVmEvidenceHex), canonical: winner.evidence, result: 'confirmed-winner', deliveryJournal: deliveryJournal(winner.evidence.transactionId, recoveredSpend.outpoint, 'broadcast', fixture.observers) },
      { candidate: candidate(loser.rawTransactionHex, loser.packet, undefined, loser.localVmEvidenceHex), result: 'conflicted-not-broadcast', deliveryJournal: deliveryJournal(loser.evidence.transactionId, recoveredSpend.outpoint, 'not-broadcast', fixture.observers) },
    ] },
  };
  const statement = { ...record }; record.attestations = signed(statement, fixture.observers);
  return { artifacts, chain, fixture, genesis, record, recoveredSpend, loser, winner };
}

function argumentsFor(root) {
  const write = (name, value) => { const path = join(root, name); writeFileSync(path, canonicalizeJcs(value)); return path; };
  const descriptor = write('descriptor.json', { test: 'placeholder-not-parsed-in-test-only-mode' });
  const playgroundDescriptor = write('playground-descriptor.json', { test: 'placeholder-not-parsed-in-test-only-mode' });
  const profile = write('profile.json', { test: 'placeholder-not-parsed-in-test-only-mode' });
  const observer = (id) => ({ id, publicKeyPem: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }) });
  const observers = write('observers.json', { schema: 'shieldkit-v2-direct-q09-chain-observers/v1', minimumTipChainWork: '1', anchors: [{ height: 0, hash: '00'.repeat(32), chainWork: '1', maximumTarget: 'ff'.repeat(32) }], observers: [observer('observer-a'), observer('observer-b')] });
  const chainObserverSetSha256 = createHash('sha256').update(readFileSync(observers)).digest('hex');
  const source = write('source.json', { schema: V2_Q09_SOURCE_PIN_SCHEMA, commit, tree, profileId: identity.profileId, instanceId: identity.instanceId, descriptorSha256: identity.descriptorSha256, playgroundDescriptorSha256: '99'.repeat(32), finalLocksSha256: identity.finalLocksSha256, chainObserverSetSha256 });
  const q02 = write('q02.json', { test: 'must-not-be-consumed-by-test-only-seam' });
  const chain = write('chain.json', { test: 'must-not-be-consumed-by-test-only-seam' });
  const settlements = write('settlements.json', { test: 'must-not-be-consumed-by-test-only-seam' });
  const playground = write('playground.json', { test: 'must-not-be-consumed-by-test-only-seam' });
  return {
    testOnly: true, outputDirectory: join(root, 'out'), descriptorPath: descriptor, playgroundDescriptorPath: playgroundDescriptor, profileCorePath: profile,
    releaseRootId: identity.releaseRootId, sourcePinPath: source, chainObserversPath: observers, q02CorpusPath: q02,
    q08HostAPath: join(root, 'must-not-be-read-q08-a.json'), q08HostBPath: join(root, 'must-not-be-read-q08-b.json'), q08PairPath: join(root, 'must-not-be-read-q08-pair.json'),
    chainEvidencePath: chain, settlementsPath: settlements, playgroundPath: playground,
    expectedCommit: commit, expectedTree: tree,
  };
}

function gitRunner(executable, arguments_) {
  assert.equal(executable, 'git');
  if (arguments_[0] === 'status') return Promise.resolve({ exitCode: 0, signal: null, stdout: '', stderr: '' });
  return Promise.resolve({ exitCode: 0, signal: null, stdout: `${arguments_[1] === 'HEAD^{commit}' ? commit : tree}\n`, stderr: '' });
}

test('Q-09 requires one exact absolute argument for every immutable input', () => {
  assert.throws(() => parseV2Q09Arguments([]), V2Q09ChipnetSoakError);
  assert.throws(() => parseV2Q09Arguments([
    '--output-dir', 'relative', '--descriptor', '/a', '--playground-descriptor', '/b', '--profile-core', '/c', '--release-root', identity.releaseRootId, '--source-pin', '/e', '--chain-observers', '/f', '--q02-corpus', '/g', '--q08-host-a', '/h', '--q08-host-b', '/i', '--q08-pair', '/pair', '--chain-evidence', '/j', '--settlements', '/k', '--playground', '/l', '--expected-commit', commit, '--expected-tree', tree,
  ]), /absolute normalized/u);
  assert.throws(() => parseV2Q09Arguments([
    '--output-dir', '/o', '--descriptor', '/a', '--playground-descriptor', '/b', '--profile-core', '/c', '--trusted-signers', '/d', '--source-pin', '/e', '--chain-observers', '/f', '--q02-corpus', '/g', '--q08-host-a', '/h', '--q08-host-b', '/i', '--q08-pair', '/pair', '--chain-evidence', '/j', '--settlements', '/k', '--playground', '/l', '--expected-commit', commit, '--expected-tree', tree,
  ]), /malformed|usage/u);
  assert.throws(() => parseV2Q09Arguments([
    '--output-dir', '/o', '--descriptor', '/a', '--playground-descriptor', '/b', '--profile-core', '/c', '--release-root', '../caller-root', '--source-pin', '/e', '--chain-observers', '/f', '--q02-corpus', '/g', '--q08-host-a', '/h', '--q08-host-b', '/i', '--q08-pair', '/pair', '--chain-evidence', '/j', '--settlements', '/k', '--playground', '/l', '--expected-commit', commit, '--expected-tree', tree,
  ]), /release root id is malformed/u);
  assert.throws(() => parseV2Q09Arguments([
    '--output-dir', '/o', '--descriptor', '/a', '--playground-descriptor', '/b', '--profile-core', '/c', '--release-root', identity.releaseRootId, '--source-pin', '/e', '--chain-observers', '/f', '--q02-corpus', '/g', '--q08-host-a', '/h', '--q08-host-b', '/i', '--chain-evidence', '/j', '--settlements', '/k', '--playground', '/l', '--expected-commit', commit, '--expected-tree', tree,
  ]), /usage/u);
  assert.throws(() => parseV2Q09Arguments([
    '--output-dir', '/o', '--descriptor', '/a', '--playground-descriptor', '/b', '--profile-core', '/c', '--release-root', identity.releaseRootId, '--source-pin', '/e', '--chain-observers', '/f', '--q02-corpus', '/g', '--q08-host-a', '/h', '--q08-host-b', '/i', '--q08-transcript', '/legacy', '--chain-evidence', '/j', '--settlements', '/k', '--playground', '/l', '--expected-commit', commit, '--expected-tree', tree,
  ]), /malformed/u);
});

test('Q-09 rejects observer identity aliasing by canonical Ed25519 SPKI DER key', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-observer-alias-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const sharedKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const path = join(root, 'observers.json');
  writeFileSync(path, canonicalizeJcs({
    schema: 'shieldkit-v2-direct-q09-chain-observers/v1',
    minimumTipChainWork: '1',
    anchors: [{ height: 0, hash: '00'.repeat(32), chainWork: '1', maximumTarget: 'ff'.repeat(32) }],
    observers: [
      { id: 'observer-a', publicKeyPem: sharedKey },
      { id: 'observer-b', publicKeyPem: sharedKey },
    ],
  }));
  assert.throws(() => parseChainObservers(path), /shared by multiple observer IDs/u);
});

test('Q-09 independently rejects Q-08 pair identity and runtime drift', () => {
  const d02Closure = {
    expectedFinalHashes: {
      commit: identity.sourceCommit,
      tree: identity.sourceTree,
      profileId: identity.profileId,
      descriptorSha256: identity.descriptorSha256,
      manifestSha256: identity.manifestSha256,
      runtimeMaterialSha256: identity.runtimeMaterialSha256,
    },
  };
  const pair = {
    schema: 'shieldkit-v2-direct-q08-pair-qualification-v2',
    q08Qualified: true,
    production: false,
    releaseQualified: false,
    profileId: identity.profileId,
    profileSha256: identity.profileSha256,
    instanceId: identity.instanceId,
    carrierCount: identity.carrierCount,
    descriptorSha256: identity.descriptorSha256,
    manifestSha256: identity.manifestSha256,
    runtimeMaterialSha256: identity.runtimeMaterialSha256,
    releaseRootId: identity.releaseRootId,
    releaseBootstrapSha256: identity.releaseBootstrapSha256,
    topology: { id: identity.topologyId },
    git: { commit: identity.sourceCommit, tree: identity.sourceTree },
    artifactSha256: '90'.repeat(32),
    d02: {
      closure: d02Closure,
      closureSha256: sha256Json(d02Closure),
    },
    hosts: {
      a: { envelopeSha256: '91'.repeat(32), statementSha256: '92'.repeat(32) },
      b: { envelopeSha256: '93'.repeat(32), statementSha256: '94'.repeat(32) },
    },
  };
  assert.equal(assertV2Q09Q08PairBinding(pair, identity), pair);
  assert.throws(
    () => assertV2Q09Q08PairBinding(
      { ...pair, runtimeMaterialSha256: 'ff'.repeat(32) },
      identity,
    ),
    /final root, runtime, topology, and source/u,
  );
  assert.throws(
    () => assertV2Q09Q08PairBinding(
      { ...pair, q08Qualified: false },
      identity,
    ),
    /final root, runtime, topology, and source/u,
  );
});

test('Q-09 rejects mainnet and cannot treat a caller timestamp as chain time', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-chain-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'chain.json');
  writeFileSync(path, canonicalizeJcs({
    schema: 'shieldkit-v2-direct-q09-chipnet-chain-evidence/v1', profileId: identity.profileId,
    instanceId: identity.instanceId, network: { id: 0, name: 'mainnet' }, tipHeight: 0,
    anchor: { height: 0, hash: '00'.repeat(32), chainWork: '1' }, attestations: [], headers: [], genesis: { blockHash: '00'.repeat(32), blockHeight: 0, transactionId: identity.genesis.transactionId, rawTransactionHex: '00' },
  }));
  assert.throws(() => validateV2Q09ChainEvidence(path, identity), /final Chipnet|canonical Chipnet/u);
});

test('Q-09 rejects legacy withdraw spelling but permits the canonical withdrawal action kind', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-withdrawal-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const entries = Array.from({ length: 1_000 }, (_, sequence) => ({
    blockHash: '00'.repeat(32), blockHeight: 0, entrySha256: '00'.repeat(32),
    kind: sequence === 0 ? 'withdraw' : 'deposit', merkleBranch: [], packetHex: '00'.repeat(552),
    previousEntrySha256: null, rawTransactionHex: '00', stateOutputIndex: 0,
    transactionId: '00'.repeat(32), transactionIndex: 0,
  }));
  const path = join(root, 'settlements.json');
  writeFileSync(path, canonicalizeJcs({
    schema: 'shieldkit-v2-direct-q09-settlement-journal/v1', profileId: identity.profileId,
    instanceId: identity.instanceId, finalLocksSha256: identity.finalLocksSha256,
    sourceCommit: commit, sourceTree: tree, chainEvidenceSha256: 'cc'.repeat(32),
    fundingProvenance: { classification: 'observer-attested-non-faucet-non-sponsor-declaration', scope: 'declaration-not-independent-source-of-funds-proof', depositTransactionIds: [], attestations: [] },
    entries,
  }));
  assert.throws(() => validateV2Q09SettlementJournal(path, identity, { sha256: 'cc'.repeat(32), headers: new Map(), tip: { height: 0 } }, { observers: new Map() }), /unsupported or legacy action kind/u);
  entries[0].kind = 'withdrawal';
  writeFileSync(path, canonicalizeJcs({
    schema: 'shieldkit-v2-direct-q09-settlement-journal/v1', profileId: identity.profileId,
    instanceId: identity.instanceId, finalLocksSha256: identity.finalLocksSha256,
    sourceCommit: commit, sourceTree: tree, chainEvidenceSha256: 'cc'.repeat(32),
    fundingProvenance: { classification: 'observer-attested-non-faucet-non-sponsor-declaration', scope: 'declaration-not-independent-source-of-funds-proof', depositTransactionIds: [], attestations: [] },
    entries,
  }));
  assert.throws(
    () => validateV2Q09SettlementJournal(path, identity, { sha256: 'cc'.repeat(32), headers: new Map(), tip: { height: 0 } }, { observers: new Map() }),
    (error) => !/unsupported or legacy action kind/u.test(error.message),
  );
});

test('Q-09 rejects a wrong playground instance and a non-32 aggregate fill before accepting any tx labels', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-playground-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const playground = { profileId: identity.profileId, profileSha256: identity.profileSha256, instanceId: '88'.repeat(32), descriptorSha256: '99'.repeat(32), finalLocksSha256: 'aa'.repeat(32), denominationSats: identity.denominationSats, maximumLiveNotes: '32', genesis: { transactionId: '77'.repeat(32), outpointIndex: 0 }, initialStateHex: '00'.repeat(128), carrierCount: 10, stateLockingBytecodeHex: '51', stateBaseSats: '546' };
  const skeleton = (overrides = {}) => ({ schema: 'shieldkit-v2-direct-q09-playground-evidence/v1', profileId: identity.profileId, instanceId: playground.instanceId, finalLocksSha256: playground.finalLocksSha256, playgroundDescriptorSha256: playground.descriptorSha256, sourceCommit: commit, sourceTree: tree, chainEvidenceSha256: 'cc'.repeat(32), genesis: {}, attestations: [], runs: [{ fill: Array.from({ length: 32 }, () => ({})), withdraw: [], refill: [], admission33: {} }], eraseRecover: {}, contention: {}, ...overrides });
  const chain = { sha256: 'cc'.repeat(32) }; const settlements = { txids: [] }; const observers = { observers: new Map() };
  const wrong = join(root, 'wrong.json'); writeFileSync(wrong, canonicalizeJcs(skeleton({ instanceId: identity.instanceId })));
  assert.throws(() => validateV2Q09PlaygroundEvidence(wrong, identity, playground, chain, settlements, observers), /separate final-qualified 32-note instance/u);
  const short = join(root, 'short.json'); writeFileSync(short, canonicalizeJcs(skeleton({ runs: [{ fill: [{}], withdraw: [], refill: [], admission33: {} }] })));
  assert.throws(() => validateV2Q09PlaygroundEvidence(short, identity, playground, chain, settlements, observers), /exactly 32 raw fill transactions/u);
});

test('Q-09 rejects an arbitrary raw transaction even when presented as a playground candidate', () => {
  const raw = `0200000001${'11'.repeat(32)}0000000000ffffffff01e8030000000000000000000000`;
  const playground = { profileId: identity.profileId, profileSha256: identity.profileSha256, instanceId: '88'.repeat(32), descriptorSha256: '99'.repeat(32), finalLocksSha256: 'aa'.repeat(32), denominationSats: identity.denominationSats, maximumLiveNotes: '32', genesis: { transactionId: '77'.repeat(32), outpointIndex: 0 }, initialStateHex: '00'.repeat(128), carrierCount: 10, stateLockingBytecodeHex: '51', stateBaseSats: '546' };
  assert.throws(() => validateV2Q09PlaygroundCandidate({ transactionId: '00'.repeat(32), rawTransactionHex: raw, packetHex: '00'.repeat(552), stateOutputIndex: 0 }, playground, {}, { outpoint: { txid: '77'.repeat(32), vout: 0 }, state: Buffer.alloc(128) }, { requireInclusion: false }), /transaction ID does not bind|exact playground topology/u);
});

test('Q-09 test-only structural subject reaches direct state, recovery, and contention branches', () => {
  const subject = subjectFixture();
  const { artifacts, chain, fixture, record } = subject;
  const previous = { outpoint: { txid: fixture.identity.genesis.transactionId, vout: fixture.identity.genesis.outpointIndex }, state: Buffer.from(fixture.identity.initialStateHex, 'hex') };
  const baselineRaw = rewriteFixtureTransaction(artifacts.rawTransactionHex, { packet: artifacts.packet, previousOutpoint: previous.outpoint, postState: decodeActionPacket(artifacts.packet, FIXTURE_STATE_CONTEXT).postState });
  const baseline = candidate(baselineRaw, artifacts.packet);
  assert.equal(validateV2Q09PlaygroundCandidate(baseline, fixture.identity, chain, previous, { requireInclusion: false }).kind, 'deposit');

  const wrongPrevout = decodedTransaction(baselineRaw);
  wrongPrevout.inputs[FIXTURE_CARRIER_COUNT + 1].outpointIndex = 1;
  const wrongPrevoutRaw = transactionHex(wrongPrevout);
  assert.throws(
    () => validateV2Q09PlaygroundCandidate(candidate(wrongPrevoutRaw, artifacts.packet), fixture.identity, chain, previous, { requireInclusion: false }),
    /exact prior playground state outpoint/u,
  );

  const decoded = decodeActionPacket(artifacts.packet, FIXTURE_STATE_CONTEXT);
  const wrongRootPacket = packetFor({
    preState: { ...decoded.preState, noteRoot: fr(91) },
    postState: decoded.postState,
  });
  const wrongRootRaw = rewriteFixtureTransaction(baselineRaw, { packet: wrongRootPacket, previousOutpoint: previous.outpoint, postState: decoded.postState });
  assert.throws(
    () => validateV2Q09PlaygroundCandidate(candidate(wrongRootRaw, wrongRootPacket), fixture.identity, chain, previous, { requireInclusion: false }),
    /exact prior playground state\/profile\/instance/u,
  );

  const wrongLivePost = { ...decoded.postState, noteCount: '2', reserveSats: '20000000', actionSequence: '2' };
  const wrongLivePacket = packetFor({ preState: decoded.preState, postState: wrongLivePost });
  const wrongLiveRaw = rewriteFixtureTransaction(baselineRaw, { packet: wrongLivePacket, previousOutpoint: previous.outpoint, postState: decoded.postState });
  assert.throws(
    () => validateV2Q09PlaygroundCandidate(candidate(wrongLiveRaw, wrongLivePacket), fixture.identity, chain, previous, { requireInclusion: false }),
    /successor state output does not bind playground descriptor state/u,
  );

  assert.doesNotThrow(() => validateSubjectRecord(subject, record));
});

test('Q-09 rejects a mined loser rather than treating its inclusion tuple as a no-send candidate', () => {
  const subject = subjectFixture();
  const record = structuredClone(subject.record);
  // A loser must be an unmined prepared candidate. Giving it a canonical
  // inclusion tuple is neither no-send evidence nor a valid candidate schema.
  record.contention.attempts[1].candidate = structuredClone(subject.loser.evidence);
  signPlaygroundRecord(record, subject.fixture.observers);
  assert.throws(() => validateSubjectRecord(subject, record), /contention candidate 1 has missing or unknown properties/u);
});

test('Q-09 rejects winner/loser transaction identity reuse', () => {
  const subject = subjectFixture();
  const record = structuredClone(subject.record);
  const winnerCandidate = candidate(
    subject.winner.rawTransactionHex,
    subject.winner.packet,
    undefined,
    subject.winner.localVmEvidenceHex,
  );
  record.contention.attempts[1].candidate = winnerCandidate;
  record.contention.attempts[1].deliveryJournal = deliveryJournal(winnerCandidate.transactionId, subject.recoveredSpend.outpoint, 'not-broadcast', subject.fixture.observers);
  signPlaygroundRecord(record, subject.fixture.observers);
  assert.throws(() => validateSubjectRecord(subject, record), /reuses a high-capacity or earlier canonical transaction|loser journal contradicts/u);
});

test('Q-09 rejects an invalid recovery-journal signature and a broken recovered lineage', () => {
  const badSignature = subjectFixture();
  const signatureRecord = structuredClone(badSignature.record);
  signatureRecord.eraseRecover.recoveryJournal.attestations[0].signatureBase64 = 'A'.repeat(88);
  signPlaygroundRecord(signatureRecord, badSignature.fixture.observers);
  assert.throws(() => validateSubjectRecord(badSignature, signatureRecord), /recovery journal attestation signature is invalid/u);

  const badLineage = subjectFixture();
  const lineageRecord = structuredClone(badLineage.record);
  [lineageRecord.eraseRecover.recoveryJournal.entries[0], lineageRecord.eraseRecover.recoveryJournal.entries[1]] = [
    lineageRecord.eraseRecover.recoveryJournal.entries[1], lineageRecord.eraseRecover.recoveryJournal.entries[0],
  ];
  signRecoveryJournal(lineageRecord.eraseRecover.recoveryJournal, badLineage.fixture.observers);
  signPlaygroundRecord(lineageRecord, badLineage.fixture.observers);
  assert.throws(() => validateSubjectRecord(badLineage, lineageRecord), /recovery journal entry 0 does not spend the exact prior playground state outpoint|exact prior playground state/u);
});

test('Q-09 rejects an arbitrary recovered candidate and a recovered note-id mismatch', () => {
  const arbitrary = subjectFixture();
  const arbitraryRecord = structuredClone(arbitrary.record);
  arbitraryRecord.eraseRecover.recoveredSpend = {
    ...arbitrary.winner.evidence,
    recoveredNoteId: arbitraryRecord.eraseRecover.recoveryJournal.recoveredNoteId,
  };
  signPlaygroundRecord(arbitraryRecord, arbitrary.fixture.observers);
  assert.throws(() => validateSubjectRecord(arbitrary, arbitraryRecord), /recovered-note spend does not spend the exact prior playground state outpoint/u);

  const wrongNote = subjectFixture();
  const wrongNoteRecord = structuredClone(wrongNote.record);
  wrongNoteRecord.eraseRecover.recoveredSpend.recoveredNoteId = 'cd'.repeat(32);
  signPlaygroundRecord(wrongNoteRecord, wrongNote.fixture.observers);
  assert.throws(() => validateSubjectRecord(wrongNote, wrongNoteRecord), /recovered spend does not bind the recovered note journal/u);
});

test('Q-09 rejects invalid contention-delivery signatures and hash chains', () => {
  const badSignature = subjectFixture();
  const signatureRecord = structuredClone(badSignature.record);
  signatureRecord.contention.attempts[1].deliveryJournal.attestations[0].signatureBase64 = 'A'.repeat(88);
  signPlaygroundRecord(signatureRecord, badSignature.fixture.observers);
  assert.throws(() => validateSubjectRecord(badSignature, signatureRecord), /contention delivery journal 1 attestation signature is invalid/u);

  const badHash = subjectFixture();
  const hashRecord = structuredClone(badHash.record);
  hashRecord.contention.attempts[1].deliveryJournal.entries[0].entrySha256 = '00'.repeat(32);
  // Re-signing the journal proves the rejection comes from the entry hash,
  // rather than from the outer observer signature.
  const { attestations: _attestations, ...statement } = hashRecord.contention.attempts[1].deliveryJournal;
  hashRecord.contention.attempts[1].deliveryJournal.attestations = signed(statement, badHash.fixture.observers);
  signPlaygroundRecord(hashRecord, badHash.fixture.observers);
  assert.throws(() => validateSubjectRecord(badHash, hashRecord), /contention delivery journal is not hash-chained to the same prior state/u);
});

test('Q-09 test doubles can exercise only ordering and never emit a qualifying rollout artifact', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-test-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const options = argumentsFor(root); const calls = [];
  const result = await runV2Q09ChipnetSoak(options, {
    runner: gitRunner,
    verifyFinalInputs: async () => { calls.push('identity'); return identity; },
    verifyPlaygroundInputs: async () => { calls.push('playground-identity'); return { profileId: identity.profileId, profileSha256: identity.profileSha256, instanceId: '88'.repeat(32), descriptorSha256: '99'.repeat(32), finalLocksSha256: 'aa'.repeat(32), releaseRootId: identity.releaseRootId, releaseBootstrapSha256: identity.releaseBootstrapSha256, denominationSats: identity.denominationSats, maximumLiveNotes: '32', genesis: { transactionId: '77'.repeat(32), outpointIndex: 0 }, initialStateHex: '00'.repeat(128), carrierCount: 10, stateLockingBytecodeHex: '51', stateBaseSats: '546' }; },
    testOnlyEvidence: async () => { calls.push('test-order'); },
  });
  assert.deepEqual(calls, ['identity', 'playground-identity', 'test-order']);
  assert.deepEqual(result, { schema: V2_Q09_RESULT_SCHEMA, status: 'test-only-nonqualifying', q09Qualified: false });
  const marker = readFileSync(join(root, 'out', 'test-only.json'), 'utf8');
  assert.match(marker, /test-only-nonqualifying/u);
  assert.match(marker, /"q09Qualified":\s*false/u);
  assert.throws(() => readFileSync(join(root, 'out', 'q09-chipnet-rollout-validation.json')), /ENOENT/u);
});

test('Q-09 production mode refuses injected doubles before it can emit a qualified artifact', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q09-reject-')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const options = argumentsFor(root); options.testOnly = false;
  await assert.rejects(runV2Q09ChipnetSoak(options, { runner: gitRunner, verifyFinalInputs: async () => identity }), /refuses injected test doubles/u);
  assert.throws(() => readFileSync(join(root, 'out', 'q09-chipnet-rollout-validation.json')), /ENOENT/u);
  assert.throws(() => readFileSync(join(root, 'out', 'failure.json')), /ENOENT/u);
});
