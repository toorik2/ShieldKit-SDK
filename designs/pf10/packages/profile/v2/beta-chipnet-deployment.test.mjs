import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';

import { encodeTransaction, hash160, secp256k1 } from '@bitauth/libauth';

import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpcForTest } from '../../kit/chipnet-rpc.mjs';
import { loadPendingOperation, transactionIdFromHex } from '../../kit/transaction-coordinator.mjs';
import { readJsonFile } from '../../kit/secure-files.mjs';
import {
  V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
  V2BetaChipnetDeploymentError,
  acceptV2BetaChipnetZeroConfDeployment,
  assertV2BetaChipnetCommittedGenesisCapability,
  assertV2BetaChipnetDeploymentCapability,
  broadcastV2BetaChipnetDeployment,
  commitV2BetaChipnetDeployment,
  deriveV2BetaChipnetDeploymentBinding,
  loadV2BetaChipnetCommittedGenesis,
  loadV2BetaChipnetDeployment,
  loadV2BetaChipnetDeploymentRecovery,
  stageV2BetaChipnetDeployment,
} from './beta-chipnet-deployment.mjs';
import {
  V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
  V2_GENESIS_INTENT_SCHEMA,
  createV2BetaChipnetGenesisRuntime,
  deriveV2FinalizedGenesisPackagePins,
  finalizeV2Genesis,
  prepareV2Genesis,
} from './genesis.mjs';
import { V2_PROFILE_DOMAINS, canonicalizeJcs } from './profile-core.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../../');
const TEST_ROOT = path.join(ROOT, '.codex-beta-chipnet-deployment-tests');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value) => Buffer.from(value).toString('hex');
const repeat = (value) => value.repeat(64);
const privateKey = Buffer.from(`${'00'.repeat(31)}01`, 'hex');
const publicKey = Buffer.from(secp256k1.derivePublicKeyCompressed(privateKey));
const rejects = (code) => (error) => error instanceof V2BetaChipnetDeploymentError && error.code === code;
let base;
let baseRoot;

function p2pkhLock(key = publicKey) {
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), Buffer.from(hash160(key)), Buffer.from([0x88, 0xac])]);
}

function sourceTransaction() {
  return hex(encodeTransaction({ version: 2, locktime: 0, inputs: [{ outpointTransactionHash: new Uint8Array(32).fill(0x42), outpointIndex: 1, sequenceNumber: 0, unlockingBytecode: new Uint8Array() }], outputs: [{ valueSatoshis: 80_000n, lockingBytecode: p2pkhLock() }] }));
}

function profileCore(pins) {
  return { schema: 'shieldkit-profile-core-v2-direct', network: { id: 2, name: 'chipnet' }, denominationSats: '10000000', proof: { system: 'groth16', curve: 'bn254', relationId: 'shieldkit-pool-action-v2-direct', relationSha256: repeat('1'), r1csSha256: pins.r1cs.sha256, verificationKeySha256: pins.verificationKey.sha256, witnessWasmSha256: pins.wasm.sha256 }, trees: { note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' }, nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' } }, crypto: { babyJubCurveId: 'circomlib-babyjub-base8', poseidonId: 'circomlib-poseidon-bn254', domains: { ...V2_PROFILE_DOMAINS } }, encodings: { state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552', address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128', unlock: 'shieldkit-rolling-bundle-unlock-v2-direct' }, publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' }, baseVerifierArtifacts: [{ id: 'carrier-base', sha256: repeat('5') }, { id: 'state-base', sha256: repeat('6') }], toolchain: [{ name: 'circom', version: '2.2.3', sha256: repeat('7') }, { name: 'snarkjs', version: '0.7.6', sha256: repeat('8') }] };
}

function settlementPins(pins) {
  return { topologyId: pins.finalLocks.topology.id, verifierRoles: pins.finalLocks.verifiers.map((entry) => entry.role), verifierCarriers: pins.finalLocks.verifiers.map((entry) => ({ baseValueSats: entry.baseSats.toString(), lockingBytecode: Buffer.from(entry.lockingBytecode) })), bindingBaseSats: pins.finalLocks.binding.baseSats.toString(), bindingLockingBytecode: Buffer.from(pins.finalLocks.binding.lockingBytecode), bindingRedeemBytecode: Buffer.from(pins.finalLocks.binding.redeemBytecode), stateBaseSats: pins.finalLocks.state.baseSats.toString(), stateLockingBytecode: Buffer.from(pins.finalLocks.state.lockingBytecode) };
}

async function fixture() {
  await mkdir(TEST_ROOT, { recursive: true, mode: 0o700 }); await chmod(TEST_ROOT, 0o700);
  const root = await mkdtemp(path.join(TEST_ROOT, 'runtime-')); await chmod(root, 0o700);
  const temporaryRoot = path.join(root, 'runtime-tmp'); await mkdir(temporaryRoot, { mode: 0o700 });
  const verificationKeyFixture = path.join(ROOT, 'designs/pf10/packages/prove/test-fixtures/two-public/verification_key.json');
  const artifacts = { provingKey: path.join(root, 'beta.zkey'), r1cs: path.join(root, 'main.r1cs'), wasm: path.join(root, 'main.wasm'), verificationKey: path.join(root, 'verification_key.json') };
  await Promise.all([writeFile(artifacts.provingKey, 'beta-key-fixture', { mode: 0o600 }), writeFile(artifacts.r1cs, 'r1cs-fixture', { mode: 0o600 }), writeFile(artifacts.wasm, 'wasm-fixture', { mode: 0o600 }), writeFile(artifacts.verificationKey, await readFile(verificationKeyFixture), { mode: 0o600 })]);
  const proofArtifacts = Object.freeze(Object.fromEntries(await Promise.all(Object.entries(artifacts).map(async ([name, filename]) => [name, Object.freeze({ path: filename, sha256: hash(await readFile(filename)) })]))));
  const sourceHex = sourceTransaction(); const sourceTxid = transactionIdFromHex(sourceHex); const instanceId = Buffer.from(sourceTxid, 'hex').reverse().toString('hex'); const core = profileCore(proofArtifacts);
  const runtime = await createV2BetaChipnetGenesisRuntime({ repositoryRoot: ROOT, artifactRoot: root, temporaryRoot, profileCore: core, proofArtifacts, instanceId });
  const intent = { schema: V2_GENESIS_INTENT_SCHEMA, profileCore: core, maximumLiveNotes: '32', fundingPublicKeyHex: hex(publicKey), changeLockingBytecodeHex: hex(p2pkhLock()), feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE, sourceTransactionHex: sourceHex };
  const prepared = prepareV2Genesis(intent, runtime); const signature = secp256k1.signMessageHashSchnorr(privateKey, Buffer.from(prepared.signingRequest.digestHex, 'hex')); assert.notEqual(typeof signature, 'string'); const finalized = finalizeV2Genesis(prepared, Buffer.from(signature), runtime); const packagePins = deriveV2FinalizedGenesisPackagePins(finalized, runtime);
  const packagedGenesis = { descriptor: { profileId: packagePins.profileId, instanceId: packagePins.instanceId, genesis: { transactionId: packagePins.genesis.transactionId, outpointIndex: packagePins.genesis.outputIndex }, initialState: Buffer.from(packagePins.initialStateHex, 'hex') }, rawGenesisTransaction: Buffer.from(finalized.genesis.rawTransactionHex, 'hex'), rawSourceTransaction: Buffer.from(sourceHex, 'hex'), settlementPins: settlementPins(packagePins) };
  return { root, sourceHex, packagedGenesis, instanceId, profileId: packagePins.profileId, genesisHex: finalized.genesis.rawTransactionHex, genesisTxid: finalized.genesis.transactionId, commitment: packagePins.initialStateHex, sourceTxid };
}

before(async () => { base = await fixture(); baseRoot = base.root; });
after(async () => { if (baseRoot !== undefined) await rm(baseRoot, { recursive: true, force: true }); });

async function deployment(t) {
  const root = await mkdtemp(path.join(TEST_ROOT, 'deployment-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  return { ...base, root, packagedGenesis: { descriptor: { ...base.packagedGenesis.descriptor, genesis: { ...base.packagedGenesis.descriptor.genesis }, initialState: Buffer.from(base.packagedGenesis.descriptor.initialState) }, rawGenesisTransaction: Buffer.from(base.packagedGenesis.rawGenesisTransaction), rawSourceTransaction: Buffer.from(base.packagedGenesis.rawSourceTransaction), settlementPins: { ...base.packagedGenesis.settlementPins, verifierRoles: [...base.packagedGenesis.settlementPins.verifierRoles], verifierCarriers: base.packagedGenesis.settlementPins.verifierCarriers.map((entry) => ({ ...entry, lockingBytecode: Buffer.from(entry.lockingBytecode) })), bindingLockingBytecode: Buffer.from(base.packagedGenesis.settlementPins.bindingLockingBytecode), bindingRedeemBytecode: Buffer.from(base.packagedGenesis.settlementPins.bindingRedeemBytecode), stateLockingBytecode: Buffer.from(base.packagedGenesis.settlementPins.stateLockingBytecode) } } };
}

async function rpcFor(subject, options = {}) {
  const calls = [];
  const rpc = await createLayer1BchnChipnetRpcForTest({ executeLayer1Cli: async (method, args) => {
    if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
    if (method === 'getblockcount') return '123';
    if (method === 'testmempoolaccept') { const txid = transactionIdFromHex(args[0]); calls.push(`test:${txid}`); return JSON.stringify([{ allowed: options.reject === txid ? false : true, txid }]); }
    if (method === 'sendrawtransaction') { const txid = transactionIdFromHex(args[0]); calls.push(`send:${txid}`); return options.mismatch === txid ? 'e'.repeat(64) : txid; }
    if (method === 'getrawtransaction') { const txid = args[0]; if (options.missingTransaction === txid) return 'null'; const hexValue = options.byteMismatch === txid ? '00' : txid === subject.sourceTxid ? subject.sourceHex : subject.genesisHex; return args[1] ? JSON.stringify({ txid, hex: hexValue }) : hexValue; }
    if (method === 'gettxout') { if (options.missingState) return 'null'; return JSON.stringify({ tokenData: { category: options.tokenMismatch ? '0'.repeat(64) : options.wrongEndianCategory ? subject.instanceId : subject.sourceTxid, amount: '0', nft: { capability: 'mutable', commitment: subject.commitment } } }); }
    throw new Error(`unexpected ${method}`);
  } });
  return { rpc, calls };
}

function input(subject, rpc) { return { acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, packagedGenesis: subject.packagedGenesis, rpc, sourceFundingRawTxHex: subject.sourceHex }; }

test('refuses unbranded RPC and requires the exact beta acknowledgement', async (t) => {
  const subject = await deployment(t);
  await assert.throws(() => stageV2BetaChipnetDeployment({ ...input(subject, {}), acknowledgement: 'no' }), rejects('BETA_DEPLOYMENT_RPC_REJECTED'));
  const { rpc } = await rpcFor(subject);
  assert.throws(() => stageV2BetaChipnetDeployment({ ...input(subject, rpc), acknowledgement: 'no' }), rejects('BETA_DEPLOYMENT_ACKNOWLEDGEMENT_REQUIRED'));
});

test('journals exact source then genesis before BCHN preflight/send and supports pending resume', async (t) => {
  const subject = await deployment(t); const { rpc, calls } = await rpcFor(subject);
  const staged = stageV2BetaChipnetDeployment(input(subject, rpc)); assert.equal(calls.length, 0); assert.equal(loadPendingOperation(subject.root).journal.transactions[0].role, 'source-funding'); assert.equal(loadPendingOperation(subject.root).journal.transactions[1].role, 'beta-genesis');
  assert.equal(stageV2BetaChipnetDeployment(input(subject, rpc)).resumed, true);
  const sent = await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc });
  assert.equal(sent.broadcast, true); assert.deepEqual(calls, [`test:${subject.sourceTxid}`, `send:${subject.sourceTxid}`, `test:${subject.genesisTxid}`, `send:${subject.genesisTxid}`]);
  assert.throws(() => commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED'));
  assert.equal(staged.record.claims.productionQualified, false);
});

test('loads exact retained deployment recovery without invoking BCHN', async (t) => {
  const subject = await deployment(t); const { rpc, calls } = await rpcFor(subject);
  const staged = stageV2BetaChipnetDeployment(input(subject, rpc));
  const recovery = loadV2BetaChipnetDeploymentRecovery({ deploymentDirectory: subject.root });
  assert.equal(recovery.operationId, staged.operationId);
  assert.equal(recovery.journalPath, staged.journalPath);
  assert.equal(recovery.sourceFundingRawTxHex, subject.sourceHex);
  assert.equal(recovery.genesisRawTxHex, subject.genesisHex);
  assert.equal(recovery.record.source.transactionId, subject.sourceTxid);
  assert.equal(recovery.record.genesis.transactionId, subject.genesisTxid);
  assert.equal(recovery.ambiguousSend, false);
  assert.deepEqual(calls, []);
  const resumed = stageV2BetaChipnetDeployment(input(subject, rpc));
  assert.equal(resumed.operationId, staged.operationId);
  assert.equal(resumed.journalPath, staged.journalPath);
  assert.deepEqual(calls, []);
  const pending = loadPendingOperation(subject.root);
  pending.journal.transactions[1].hex = '00';
  await writeFile(pending.journalPath, JSON.stringify(pending.journal), { mode: 0o600 });
  assert.throws(
    () => loadV2BetaChipnetDeploymentRecovery({ deploymentDirectory: subject.root }),
    rejects('BETA_DEPLOYMENT_RECOVERY_REJECTED'),
  );
});

test('recovers only the exact coordinator-before-record crash boundary without re-staging', async (t) => {
  const subject = await deployment(t); const { rpc, calls } = await rpcFor(subject);
  const staged = stageV2BetaChipnetDeployment(input(subject, rpc));
  await rm(staged.path);
  assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: subject.root }), null);
  const recovered = stageV2BetaChipnetDeployment(input(subject, rpc));
  assert.equal(recovered.resumed, true);
  assert.equal(recovered.operationId, staged.operationId);
  assert.deepEqual(calls, []);
  assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: subject.root }).record.status, 'prepared');
});

test('rejects a coordinator-before-record journal whose public result is not exact', async (t) => {
  const subject = await deployment(t); const { rpc } = await rpcFor(subject);
  const staged = stageV2BetaChipnetDeployment(input(subject, rpc));
  await rm(staged.path);
  const pending = loadPendingOperation(subject.root);
  pending.journal.publicResult.profileId = '0'.repeat(64);
  await writeFile(pending.journalPath, JSON.stringify(pending.journal), { mode: 0o600 });
  assert.throws(() => stageV2BetaChipnetDeployment(input(subject, rpc)), rejects('BETA_DEPLOYMENT_RESUME_REJECTED'));
  assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: subject.root }), null);
});

test('does not commit on BCHN mempool rejection or returned txid mismatch', async (t) => {
  const rejected = await deployment(t); const rejecting = await rpcFor(rejected, { reject: rejected.genesisTxid }); stageV2BetaChipnetDeployment(input(rejected, rejecting.rpc));
  assert.throws(() => commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: rejected.root }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED'));
  await assert.rejects(broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: rejected.root, rpc: rejecting.rpc }), rejects('BETA_DEPLOYMENT_BROADCAST_REJECTED'));
  assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: rejected.root }).record.status, 'prepared');
  const mismatchRoot = await mkdtemp(path.join(TEST_ROOT, 'deployment-')); await chmod(mismatchRoot, 0o700); t.after(() => rm(mismatchRoot, { recursive: true, force: true })); const mismatched = { ...rejected, root: mismatchRoot }; const mismatch = await rpcFor(mismatched, { mismatch: mismatched.sourceTxid }); stageV2BetaChipnetDeployment(input(mismatched, mismatch.rpc));
  await assert.rejects(broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: mismatched.root, rpc: mismatch.rpc }), rejects('BETA_DEPLOYMENT_BROADCAST_REJECTED'));
});

test('accepts zero-conf BCHN readback and commits only truthful unqualified state', async (t) => {
  const subject = await deployment(t); const connection = await rpcFor(subject); stageV2BetaChipnetDeployment(input(subject, connection.rpc));
  assert.notEqual(subject.sourceTxid, subject.instanceId);
  await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc });
  const accepted = await acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc });
  assert.equal(accepted.accepted, true); assert.equal(accepted.evidence.status, 'accepted-zero-conf-beta-unqualified'); assert.deepEqual(accepted.evidence.claims, { broadcasted: true, confirmed: false, mined: false, productionQualified: false });
  const capability = deriveV2BetaChipnetDeploymentBinding({ deploymentDirectory: subject.root }); assert.equal(assertV2BetaChipnetDeploymentCapability(capability), capability); assert.throws(() => assertV2BetaChipnetDeploymentCapability({ ...capability }), rejects('BETA_DEPLOYMENT_CAPABILITY_REJECTED'));
  const committed = commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root }); assert.equal(committed.committed, true); assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: subject.root }).record.status, 'committed');
  const state = readJsonFile(path.join(subject.root, '.shieldkit', 'v2-beta-chipnet-state.json')); assert.equal(state.status, 'accepted-zero-conf-beta-unqualified'); assert.deepEqual(state.claims, { broadcasted: true, confirmed: false, mined: false, productionQualified: false });
});

test('loads a branded exact committed genesis only from pinned deployment artifacts', async (t) => {
  const subject = await deployment(t); const connection = await rpcFor(subject);
  stageV2BetaChipnetDeployment(input(subject, connection.rpc));
  await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc });
  await acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc });
  commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root });
  // This coordinator convenience file is intentionally not an input to the loader.
  await writeFile(path.join(subject.root, '.shieldkit', 'v2-beta-chipnet-state.json'), JSON.stringify({ initialState: 'untrusted-side-file' }), { mode: 0o600 });
  const genesis = loadV2BetaChipnetCommittedGenesis({ deploymentDirectory: subject.root });
  assert.equal(genesis.profileId, subject.profileId);
  assert.equal(genesis.instanceId, subject.instanceId);
  assert.equal(genesis.initialState.toString('hex'), subject.commitment);
  assert.deepEqual(genesis.genesisOutpoint, { txid: subject.genesisTxid, vout: 0 });
  assert.equal(genesis.zeroConfEvidenceSha256.length, 64);
  assert.equal(assertV2BetaChipnetCommittedGenesisCapability(genesis), genesis);
  assert.throws(() => assertV2BetaChipnetCommittedGenesisCapability({ ...genesis }), rejects('BETA_DEPLOYMENT_COMMITTED_GENESIS_CAPABILITY_REJECTED'));
  genesis.initialState[0] ^= 1;
  assert.throws(() => assertV2BetaChipnetCommittedGenesisCapability(genesis), rejects('BETA_DEPLOYMENT_COMMITTED_GENESIS_CAPABILITY_REJECTED'));
  const pending = loadPendingOperation(subject.root);
  pending.journal.transactions[1].hex = '00';
  await writeFile(pending.journalPath, JSON.stringify(pending.journal), { mode: 0o600 });
  assert.throws(() => loadV2BetaChipnetCommittedGenesis({ deploymentDirectory: subject.root }), rejects('BETA_DEPLOYMENT_COMMITTED_GENESIS_REJECTED'));
});

test('migrates only the exact legacy broadcast journal to truthful zero-conf state before commit', async (t) => {
  const subject = await deployment(t); const connection = await rpcFor(subject); const staged = stageV2BetaChipnetDeployment(input(subject, connection.rpc));
  await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc });
  const legacyRecord = readJsonFile(staged.path); const { evidenceSha256: _evidenceSha256, ...legacyCore } = legacyRecord; legacyCore.claims = { productionQualified: false }; await writeFile(staged.path, JSON.stringify({ ...legacyCore, evidenceSha256: hash(canonicalizeJcs(legacyCore)) }), { mode: 0o600 });
  const pending = loadPendingOperation(subject.root); pending.journal.nextState = { schema: pending.journal.nextState.schema, status: 'confirmed-beta-unqualified', eligibility: legacyRecord.eligibility, claims: { productionQualified: false }, profileId: legacyRecord.profileId, instanceId: legacyRecord.instanceId, genesis: { transactionId: legacyRecord.genesis.transactionId, outputIndex: 0 } }; pending.journal.ledgerRecord = { schema: pending.journal.ledgerRecord.schema, status: 'confirmed-beta-unqualified', eligibility: legacyRecord.eligibility, profileId: legacyRecord.profileId, instanceId: legacyRecord.instanceId, sourceTransactionId: legacyRecord.source.transactionId, genesisTransactionId: legacyRecord.genesis.transactionId, operationId: pending.journal.operationId }; await writeFile(pending.journalPath, JSON.stringify(pending.journal), { mode: 0o600 });
  const accepted = await acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: subject.root, rpc: connection.rpc }); assert.equal(accepted.accepted, true);
  const migrated = loadPendingOperation(subject.root).journal; assert.equal(migrated.nextState.status, 'accepted-zero-conf-beta-unqualified'); assert.equal(migrated.ledgerRecord.status, 'accepted-zero-conf-beta-unqualified'); assert.deepEqual(migrated.ledgerRecord.claims, { broadcasted: true, confirmed: false, mined: false, productionQualified: false });
});

test('does not accept or commit when BCHN has not exposed a mempool transaction or state NFT', async (t) => {
  const missingTransaction = await deployment(t); const absentTransaction = await rpcFor(missingTransaction, { missingTransaction: missingTransaction.sourceTxid }); stageV2BetaChipnetDeployment(input(missingTransaction, absentTransaction.rpc));
  await assert.rejects(
    broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: missingTransaction.root, rpc: absentTransaction.rpc }),
    rejects('BETA_DEPLOYMENT_BROADCAST_REJECTED'),
  );
  assert.equal(loadV2BetaChipnetDeployment({ deploymentDirectory: missingTransaction.root }).record.status, 'prepared');
  assert.throws(() => commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: missingTransaction.root }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED'));
  const missingState = await deployment(t); const sentState = await rpcFor(missingState); stageV2BetaChipnetDeployment(input(missingState, sentState.rpc)); await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: missingState.root, rpc: sentState.rpc });
  const absentState = await rpcFor(missingState, { missingState: true }); const stateResult = await acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: missingState.root, rpc: absentState.rpc }); assert.equal(stateResult.accepted, false); assert.throws(() => commitV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: missingState.root }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REQUIRED'));
});

test('rejects BCHN zero-conf byte, wrong-endian category, or state-NFT mismatches', async (t) => {
  const byteSubject = await deployment(t); const wrongBytes = await rpcFor(byteSubject, { byteMismatch: byteSubject.genesisTxid }); stageV2BetaChipnetDeployment(input(byteSubject, wrongBytes.rpc));
  await assert.rejects(
    broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: byteSubject.root, rpc: wrongBytes.rpc }),
    rejects('BETA_DEPLOYMENT_BROADCAST_REJECTED'),
  );
  const tokenSubject = await deployment(t); const tokenSent = await rpcFor(tokenSubject); stageV2BetaChipnetDeployment(input(tokenSubject, tokenSent.rpc)); await broadcastV2BetaChipnetDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: tokenSubject.root, rpc: tokenSent.rpc });
  const wrongToken = await rpcFor(tokenSubject, { tokenMismatch: true }); await assert.rejects(acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: tokenSubject.root, rpc: wrongToken.rpc }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REJECTED'));
  const wrongEndian = await rpcFor(tokenSubject, { wrongEndianCategory: true }); await assert.rejects(acceptV2BetaChipnetZeroConfDeployment({ acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT, deploymentDirectory: tokenSubject.root, rpc: wrongEndian.rpc }), rejects('BETA_DEPLOYMENT_ZERO_CONF_REJECTED'));
});
