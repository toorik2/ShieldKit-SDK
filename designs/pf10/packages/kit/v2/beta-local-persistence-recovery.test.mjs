import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { constructDirectV2Output, deriveDirectV2Address, recoverDirectV2Output } from '../../action/v2/notes.mjs';
import { actionPacketPublicLimbs } from '../../action/v2/packet.mjs';
import { applyDirectV2Transition, createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { canonicalizeJcs, deriveProfileId, V2_PROFILE_DOMAINS } from '../../profile/v2/profile-core.mjs';
import { createV2BetaLocalProfilePackage, deriveV2BetaLocalProfileCore, V2_BETA_LOCAL_ELIGIBILITY, V2_BETA_LOCAL_FALSE_CLAIMS } from '../../profile/v2/beta-local-profile.mjs';
import { runV2BetaLocalPersistenceRecovery, verifyV2BetaLocalPersistenceRecovery, V2_BETA_LOCAL_PERSISTENCE_RECOVERY_SCHEMA, V2BetaLocalPersistenceRecoveryError } from './beta-local-persistence-recovery.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const canonicalHash = (value) => hash(Buffer.from(canonicalizeJcs(value), 'utf8'));
const hex = (value) => BigInt(value).toString(16).padStart(64, '0');
const TEST_BUILD_ROOT = path.resolve(import.meta.dirname, '../../../.codex-beta-persistence-tests');

function core(vk = '9'.repeat(64)) {
  return {
    schema: 'shieldkit-profile-core-v2-direct', network: { id: 2, name: 'chipnet' }, denominationSats: '10000000',
    proof: { system: 'groth16', curve: 'bn254', relationId: 'shieldkit-pool-action-v2-direct', relationSha256: '1'.repeat(64), r1csSha256: '2'.repeat(64), verificationKeySha256: vk, witnessWasmSha256: '4'.repeat(64) },
    trees: { note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' }, nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' } },
    crypto: { babyJubCurveId: 'circomlib-babyjub-base8', poseidonId: 'circomlib-poseidon-bn254', domains: { ...V2_PROFILE_DOMAINS } },
    encodings: { state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552', address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128', unlock: 'shieldkit-rolling-bundle-unlock-v2-direct' },
    publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' }, baseVerifierArtifacts: [{ id: 'carrier-base', sha256: '5'.repeat(64) }], toolchain: [{ name: 'snarkjs', version: '0.7.6', sha256: '6'.repeat(64) }],
  };
}

function profileFixture() {
  const base = core('3'.repeat(64)); const beta = deriveV2BetaLocalProfileCore({ baseProfileCore: base, verificationKeySha256: '9'.repeat(64) });
  const artifact = (pathName, sha256) => ({ bytes: 1, path: pathName, sha256 });
  const artifacts = { r1cs: artifact('r1cs', '2'.repeat(64)), witnessWasm: artifact('wasm', '4'.repeat(64)), circuitSymbols: artifact('sym', '7'.repeat(64)), initialZkey: artifact('initial', '0'.repeat(64)), powersOfTau: artifact('ptau', 'f'.repeat(64)), betaProvingKey: artifact('beta', '8'.repeat(64)), verificationKey: artifact('vk', '9'.repeat(64)) };
  const b01Manifest = { schema: 'shieldkit-v2-direct-b01-pre-freeze-v1', status: 'b01-pre-freeze-candidate-awaiting-independent-review', b01PreFreezeCandidate: true, reviewed: false, ceremonyAuthorized: false, production: false, releaseQualified: false, localOnly: true, preCeremony: true, claims: { developmentKey: true, finalKey: false, bchVm: false, production: false, releaseQualified: false }, source: { gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40), repositoryRoot: '/fixture' }, profile: { profileId: deriveProfileId(base), profileCoreSha256: canonicalHash(base), relationSha256: base.proof.relationSha256, r1csSha256: base.proof.r1csSha256, witnessWasmSha256: base.proof.witnessWasmSha256, verificationKeySha256: base.proof.verificationKeySha256 }, runtime: { proofArtifacts: { circuitSymbols: artifacts.circuitSymbols.sha256, initialProvingKey: artifacts.initialZkey.sha256, powersOfTau: artifacts.powersOfTau.sha256, r1cs: artifacts.r1cs.sha256, verificationKey: base.proof.verificationKeySha256, witnessWasm: artifacts.witnessWasm.sha256 } }, packetAbi: {}, q01Pre: {}, topology: {}, boundaries: [] };
  const ceremony = { ceremonyId: 'shieldkit-v2-beta-r3', b01ManifestSha256: `sha256:${canonicalHash(b01Manifest)}`, preparationSha256: `sha256:${'b'.repeat(64)}`, resultSha256: `sha256:${'c'.repeat(64)}`, transcriptSha256: `sha256:${'d'.repeat(64)}`, circuitSymbolsSha256: `sha256:${'7'.repeat(64)}`, initialZkeySha256: `sha256:${'0'.repeat(64)}`, powersOfTauSha256: `sha256:${'f'.repeat(64)}`, betaProvingKeySha256: `sha256:${'8'.repeat(64)}`, verificationKeySha256: `sha256:${'9'.repeat(64)}`, source: { gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40) } };
  const betaProfilePackage = createV2BetaLocalProfilePackage({ baseProfileCore: base, b01Manifest, profileCore: beta.profileCore, profileCoreSha256: beta.profileCoreSha256, ceremony, artifacts });
  return { betaProfilePackage, profileCore: beta.profileCore, profileId: beta.profileId };
}

function rng(seed) { let next = BigInt(seed); return { bytes(length) { assert.equal(length, 32); const result = Buffer.from(hex(next), 'hex'); next += 1n; return result; } }; }

function packetsAndRecords(profileId, instanceId, maximumLiveNotes = '32') {
  const account = { spendSecret: hex(3), incomingViewSecret: hex(4) };
  account.address = deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
  const depositOutput = constructDirectV2Output({ address: account.address, postActionSequence: '1', rng: rng(5) });
  const first = recoverDirectV2Output({ account, outputNoteLeaf: depositOutput.public.outputNoteLeaf, encryptedRecord: depositOutput.public.encryptedRecord });
  const transferOutput = constructDirectV2Output({ address: account.address, postActionSequence: '2', rng: rng(8) });
  const second = recoverDirectV2Output({ account, outputNoteLeaf: transferOutput.public.outputNoteLeaf, encryptedRecord: transferOutput.public.encryptedRecord });
  let current = createDirectV2PoolModel({ profileId, maximumLiveNotes, denominationSats: '10000000' });
  const contexts = ['a', 'b', 'c'].map((value) => hash(`context-${value}`));
  const apply = (kind, extra, expectedPostState = undefined) => applyDirectV2Transition({ kind, networkId: 2, profileId, instanceId, denominationSats: '10000000', preState: current.state, noteTree: current.noteTree, nullifierTree: current.nullifierTree, transactionContextHash: contexts[['deposit', 'transfer', 'withdrawal'].indexOf(kind)], ...extra, ...(expectedPostState === undefined ? {} : { expectedPostState }) });
  const deposit = apply('deposit', { output: { outputNoteLeaf: depositOutput.public.outputNoteLeaf, encryptedRecord: depositOutput.public.encryptedRecord } }); current = deposit;
  const transfer = apply('transfer', { output: { outputNoteLeaf: transferOutput.public.outputNoteLeaf, encryptedRecord: transferOutput.public.encryptedRecord }, spend: { inputNoteLeaf: depositOutput.public.outputNoteLeaf, noteIndex: '0', publicNullifier: first.nullifier } }); current = transfer;
  const withdrawal = apply('withdrawal', { spend: { inputNoteLeaf: transferOutput.public.outputNoteLeaf, noteIndex: '1', publicNullifier: second.nullifier }, withdrawalLockingBytecodeHash: hash('withdrawal lock') });
  const transitions = [deposit, transfer, withdrawal];
  const packets = transitions.map((transition) => Buffer.from(transition.packet));
  const op = (value) => `v2op:${hex(value)}`;
  return { packets, records: [ { expectedActionSequence: 0, kind: 'deposit', operationId: op(1), output: depositOutput, publicNullifier: null }, { expectedActionSequence: 1, kind: 'transfer', operationId: op(2), output: transferOutput, publicNullifier: first.nullifier }, { expectedActionSequence: 2, kind: 'withdrawal', operationId: op(3), output: null, publicNullifier: second.nullifier } ] };
}

function betaClaims() {
  const claims = { ...V2_BETA_LOCAL_FALSE_CLAIMS };
  delete claims.bchVm;
  return { ...claims, authenticatedSerializedParentOutputs: true, bchnMempool: false, bchnMined: false, leanBch: false, libauthBch2026: true, liveChainParentProvenance: false, productionSettlementBuilderPath: true, unmodifiedMaintainerBenchmark: false };
}

async function fixture(t, maximumLiveNotes = '32') {
  await mkdir(TEST_BUILD_ROOT, { recursive: true, mode: 0o700 }); await chmod(TEST_BUILD_ROOT, 0o700);
  const root = await mkdtemp(path.join(TEST_BUILD_ROOT, 'case-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const profile = profileFixture(); const instanceId = hash(`beta persistence instance ${maximumLiveNotes}`); const action = packetsAndRecords(profile.profileId, instanceId, maximumLiveNotes);
  const runtimeMaterialSha256 = 'a'.repeat(64);
  const runtimeManifest = { schema: 'shieldkit-v2-direct-pf10-beta-local-runtime-bundle-v2', status: 'beta-local-runtime-built-unqualified', eligibility: V2_BETA_LOCAL_ELIGIBILITY, assuranceClass: 'beta-single-contributor', claims: V2_BETA_LOCAL_FALSE_CLAIMS, profile: { profileId: profile.profileId }, identity: { instanceId, maximumLiveNotes, denominationSats: '10000000' }, runtime: { materialSha256: runtimeMaterialSha256 }, artifacts: [], proofArtifacts: {}, proofQualification: {} };
  const manifestSha256 = canonicalHash(runtimeManifest);
  const proofEvidence = { schema: 'shieldkit-v2-direct-beta-groth16-qualification-v1', evidenceClass: 'deterministic-beta-single-contributor-groth16-integration-evidence', eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: V2_BETA_LOCAL_FALSE_CLAIMS, fixture: 'fixture', identity: { profileId: profile.profileId, instanceId, maximumLiveNotes, denominationSats: '10000000' }, measurements: {}, prover: {}, versions: {}, betaProvenance: {}, sourceArtifacts: { profileCore: { sha256: profile.betaProfilePackage.profileCoreSha256 }, r1cs: { sha256: profile.betaProfilePackage.artifacts.r1cs.sha256 }, wasm: { sha256: profile.betaProfilePackage.artifacts.witnessWasm.sha256 }, betaProvingKey: { sha256: profile.betaProfilePackage.artifacts.betaProvingKey.sha256 }, verificationKey: { sha256: profile.betaProfilePackage.artifacts.verificationKey.sha256 } }, actions: Object.fromEntries(['deposit', 'transfer', 'withdrawal'].map((kind, index) => [kind, { witnessValid: true, proofVerified: true, packetDigest: hash(action.packets[index]), files: { packet: { bytes: 552, path: `/${kind}.packet`, sha256: hash(action.packets[index]) }, v2DirectGroth16Adapter: { bytes: 1, path: `/${kind}.adapter`, sha256: hash(`${kind}-adapter`) } } }])) };
  const proofEvidenceSha256 = canonicalHash(proofEvidence);
  const transactionIds = ['deposit', 'transfer', 'withdrawal'].map((kind) => hash(`${kind}-signed-libauth-transaction`));
  const libauthEvidence = { schema: 'shieldkit-v2-direct-pf10-beta-local-libauth-evidence-v1', eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: betaClaims(), identity: { profileId: profile.profileId, instanceId, runtimeMaterialSha256 }, betaProofQualification: { sha256: proofEvidenceSha256, profileId: profile.profileId, instanceId }, pf10FusedQGenesisActions: { actions: ['deposit', 'transfer', 'withdrawal'].map((kind, index) => { const packetSha256 = hash(action.packets[index]); const publicInputs = actionPacketPublicLimbs(action.packets[index], { denominationSats: '10000000' }); const proof = { pi_a: [`${index + 1}`, '2', '1'], pi_b: [['1', '2'], ['3', '4'], ['1', '0']], pi_c: ['5', '6', '1'], protocol: 'groth16' }; return { kind, transactionId: transactionIds[index], packetHex: action.packets[index].toString('hex'), packetSha256, publicInputs, proof, proofBindingSha256: canonicalHash({ packetSha256, proof, publicInputs }), contextHash: hash(`${kind}-context`), proofVerified: true, inputCount: 13 }; }) } };
  const libauthActions = libauthEvidence.pf10FusedQGenesisActions.actions;
  const libauthEvidenceSha256 = canonicalHash(libauthEvidence);
  await mkdir(path.join(root, 'actions'), { mode: 0o700 });
  return { betaProfilePackage: profile.betaProfilePackage, profileCore: profile.profileCore, instanceId, carrierCount: 10, maximumLiveNotes, genesis: { blockHash: hash('genesis block'), height: 100, outpoint: { txid: hash('genesis outpoint'), vout: 0 } }, preparedActions: action.records, privateActionDirectory: path.join(root, 'actions'), stateStorePath: path.join(root, 'state.sqlite'), betaRuntime: { manifest: runtimeManifest, manifestSha256, verification: { schema: 'shieldkit-v2-direct-pf10-beta-local-runtime-verification-v1', status: 'beta-runtime-reverified-unqualified', eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: V2_BETA_LOCAL_FALSE_CLAIMS, manifestSha256, runtimeMaterialSha256 } }, betaProofQualification: { evidence: proofEvidence, evidenceSha256: proofEvidenceSha256, verification: { schema: 'shieldkit-v2-direct-beta-groth16-qualification-verification-v1', evidenceSha256: proofEvidenceSha256, eligibility: V2_BETA_LOCAL_ELIGIBILITY, profileId: profile.profileId, instanceId, maximumLiveNotes, status: 'beta-proof-qualification-reverified-unqualified', claims: V2_BETA_LOCAL_FALSE_CLAIMS } }, betaLibauthQualification: { evidence: libauthEvidence, evidenceSha256: libauthEvidenceSha256, verification: { schema: 'shieldkit-v2-direct-pf10-beta-local-libauth-verification-v1', eligibility: V2_BETA_LOCAL_ELIGIBILITY, evidenceSha256: libauthEvidenceSha256, proofEvidenceReverified: true, status: 'beta-local-libauth-reverified-unqualified', transactionSpecificProofs: libauthActions.map((entry) => ({ kind: entry.kind, packetSha256: entry.packetSha256, proofBindingSha256: entry.proofBindingSha256, proofVerified: true, transactionId: entry.transactionId })), transactions: ['deposit', 'transfer', 'withdrawal'].map((kind, index) => ({ kind, transactionId: transactionIds[index], inputs: 13 })) } } };
}

const rejects = (code) => (error) => error instanceof V2BetaLocalPersistenceRecoveryError && error.code === code;
const verifyInput = (value, evidence) => ({
  betaLibauthQualification: value.betaLibauthQualification,
  betaProfilePackage: value.betaProfilePackage,
  betaProofQualification: value.betaProofQualification,
  betaRuntime: value.betaRuntime,
  evidence,
  preparedActions: value.preparedActions,
  privateActionDirectory: value.privateActionDirectory,
  profileCore: value.profileCore,
  stateStorePath: value.stateStorePath,
});

test('beta lane persists three evidence-bound checkpoints and cold-reopens the terminal state', async (t) => {
  const value = await fixture(t); const result = await runV2BetaLocalPersistenceRecovery(value);
  assert.equal(Object.hasOwn(value.betaLibauthQualification.evidence.claims, 'bchVm'), false);
  assert.equal(result.schema, V2_BETA_LOCAL_PERSISTENCE_RECOVERY_SCHEMA); assert.equal(result.replay.coldReopenCount, 3); assert.equal(result.actions.length, 3);
  for (const [index, action] of result.actions.entries()) {
    const source = value.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[index];
    assert.equal(action.packetSha256, source.packetSha256); assert.equal(action.proofBindingSha256, source.proofBindingSha256); assert.equal(action.transactionId, source.transactionId);
  }
  assert.deepEqual(await verifyV2BetaLocalPersistenceRecovery(verifyInput(value, result)), { evidenceSha256: result.evidenceSha256, status: result.status, eligibility: V2_BETA_LOCAL_ELIGIBILITY });
  assert.equal((await lstat(value.privateActionDirectory)).mode & 0o777, 0o700); assert.equal((await lstat(value.stateStorePath)).mode & 0o777, 0o600);
  for (const action of result.actions) assert.equal((await lstat(path.join(value.privateActionDirectory, `${action.operationId.slice(5)}.json`))).mode & 0o777, 0o600);
});

test('beta lane binds and reopens a 100000-note admission capacity', async (t) => {
  const value = await fixture(t, '100000');
  const result = await runV2BetaLocalPersistenceRecovery(value);
  assert.equal(result.maximumLiveNotes, '100000');
  assert.deepEqual(
    await verifyV2BetaLocalPersistenceRecovery(verifyInput(value, result)),
    {
      evidenceSha256: result.evidenceSha256,
      status: result.status,
      eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    },
  );
});

test('beta proof qualification remains independently pinned while Libauth packets are authoritative', async (t) => {
  const value = await fixture(t);
  const independent = value.betaProofQualification.evidence.actions.deposit;
  independent.packetDigest = 'e'.repeat(64); independent.files.packet.sha256 = independent.packetDigest;
  const proofEvidenceSha256 = canonicalHash(value.betaProofQualification.evidence);
  value.betaProofQualification.evidenceSha256 = proofEvidenceSha256;
  value.betaProofQualification.verification.evidenceSha256 = proofEvidenceSha256;
  value.betaLibauthQualification.evidence.betaProofQualification.sha256 = proofEvidenceSha256;
  const libauthEvidenceSha256 = canonicalHash(value.betaLibauthQualification.evidence);
  value.betaLibauthQualification.evidenceSha256 = libauthEvidenceSha256;
  value.betaLibauthQualification.verification.evidenceSha256 = libauthEvidenceSha256;
  const result = await runV2BetaLocalPersistenceRecovery(value);
  assert.notEqual(result.actions[0].packetSha256, independent.packetDigest);
});

test('beta lane rejects standalone packet injection, Libauth packet/proof/input/transaction substitutions, and durable-record substitutions', async (t) => {
  const value = await fixture(t);
  const swappedRuntime = structuredClone(value); swappedRuntime.betaRuntime.manifest.runtime.materialSha256 = 'e'.repeat(64);
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedRuntime), rejects('BETA_PERSISTENCE_EVIDENCE_REJECTED'));
  const swappedPacket = structuredClone(value); swappedPacket.betaProofQualification.packets = [];
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedPacket), rejects('BETA_PERSISTENCE_INVALID'));
  const swappedLibauthPacket = structuredClone(value); swappedLibauthPacket.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[1].packetHex = `00${swappedLibauthPacket.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[1].packetHex.slice(2)}`;
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedLibauthPacket), rejects('BETA_PERSISTENCE_EVIDENCE_REJECTED'));
  const swappedPublicInputs = structuredClone(value); swappedPublicInputs.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[0].publicInputs[0] = '0';
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedPublicInputs), rejects('BETA_PERSISTENCE_EVIDENCE_REJECTED'));
  const swappedProofBinding = structuredClone(value); swappedProofBinding.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[0].proofBindingSha256 = 'e'.repeat(64);
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedProofBinding), rejects('BETA_PERSISTENCE_EVIDENCE_REJECTED'));
  const swappedTransaction = structuredClone(value); swappedTransaction.betaLibauthQualification.evidence.pf10FusedQGenesisActions.actions[2].transactionId = 'e'.repeat(64);
  await assert.rejects(runV2BetaLocalPersistenceRecovery(swappedTransaction), rejects('BETA_PERSISTENCE_EVIDENCE_REJECTED'));
  const evidence = await runV2BetaLocalPersistenceRecovery(value); const filename = path.join(value.privateActionDirectory, `${evidence.actions[1].operationId.slice(5)}.json`); await writeFile(filename, '{"corrupt":true}', { mode: 0o600 });
  await assert.rejects(verifyV2BetaLocalPersistenceRecovery(verifyInput(value, evidence)), rejects('BETA_PERSISTENCE_VERIFICATION_REJECTED'));
});
