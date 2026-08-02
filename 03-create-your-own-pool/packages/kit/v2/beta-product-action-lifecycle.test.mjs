import assert from 'node:assert/strict';
import { availableParallelism } from 'node:os';
import { createHash } from 'node:crypto';
import {
  chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';

import {
  encodeTransaction,
  hash160,
  secp256k1,
} from '@bitauth/libauth';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  CHIPNET_GENESIS_HASH,
  createLayer1BchnChipnetRpcForTest,
} from '../chipnet-rpc.mjs';
import { openV2BetaIncrementalStore } from '../../profile/v2/beta-incremental-store.mjs';
import {
  V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA,
} from '../../profile/v2/beta-chipnet-runtime.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../../profile/v2/beta-local-profile.mjs';
import {
  createV2BetaChipnetGenesisRuntime,
  deriveV2FinalizedGenesisPackagePins,
  finalizeV2Genesis,
  prepareV2Genesis,
  V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
  V2_GENESIS_INTENT_SCHEMA,
} from '../../profile/v2/genesis.mjs';
import {
  V2_PROFILE_DOMAINS,
  canonicalizeJcs,
  deriveProfileId,
} from '../../profile/v2/profile-core.mjs';
import { openV2DeliveryJournal } from './delivery-journal.mjs';
import { openV2BetaProductWallet } from './beta-product-wallet.mjs';
import {
  createV2BetaProductActionLifecycle,
  createV2BetaProductActionLifecycleForTest,
  deriveV2BetaOneShotAdmissionRpcObservationForTest,
  validateV2BetaPersistedProofContainment,
  V2BetaProductActionLifecycleError,
} from './beta-product-action-lifecycle.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';

const ROOT = path.resolve(import.meta.dirname, '../../../..');
const TEST_ROOT = path.join(ROOT, '.codex-beta-product-lifecycle-tests');
const HASH = value => createHash('sha256').update(value).digest('hex');
const PRIVATE_KEY = Buffer.from(`${'00'.repeat(31)}07`, 'hex');
const PUBLIC_KEY = Buffer.from(secp256k1.derivePublicKeyCompressed(PRIVATE_KEY));
const LOCK = Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),
  Buffer.from(hash160(PUBLIC_KEY)),
  Buffer.from([0x88, 0xac]),
]);

let base;

function rawSource(valueSatoshis, lockingBytecode = LOCK) {
  return Buffer.from(encodeTransaction({
    version: 2,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x42),
      outpointIndex: 1,
      sequenceNumber: 0,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{ valueSatoshis, lockingBytecode }],
    locktime: 0,
  })).toString('hex');
}

function profileCore(proofArtifacts) {
  return {
    schema: 'shieldkit-profile-core-v2-direct',
    network: { id: 2, name: 'chipnet' },
    denominationSats: '10000000',
    proof: {
      system: 'groth16',
      curve: 'bn254',
      relationId: 'shieldkit-pool-action-v2-direct',
      relationSha256: '11'.repeat(32),
      r1csSha256: proofArtifacts.r1cs.sha256,
      verificationKeySha256: proofArtifacts.verificationKey.sha256,
      witnessWasmSha256: proofArtifacts.wasm.sha256,
    },
    trees: {
      note: {
        id: 'shieldkit-note-tree-v2-depth32',
        depth: 32,
        leafSchemaId: 'shieldkit-note-leaf-v2',
      },
      nullifier: {
        id: 'shieldkit-indexed-nullifier-tree-v2-depth32',
        depth: 32,
        leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2',
      },
    },
    crypto: {
      babyJubCurveId: 'circomlib-babyjub-base8',
      poseidonId: 'circomlib-poseidon-bn254',
      domains: { ...V2_PROFILE_DOMAINS },
    },
    encodings: {
      state: 'shieldkit-pool-state-sks2-native128',
      packet: 'shieldkit-direct-action-sda2-552',
      address: 'shieldkit-address-v2-direct',
      record: 'shieldkit-note-record-v2-direct-128',
      unlock: 'shieldkit-rolling-bundle-unlock-v2-direct',
    },
    publicInputAbi: {
      id: 'shieldkit-sda2-sha256-be-u128x2',
      count: 2,
      limbBits: 128,
      digest: 'sha256',
    },
    baseVerifierArtifacts: [
      { id: 'carrier-base', sha256: '55'.repeat(32) },
      { id: 'state-base', sha256: '66'.repeat(32) },
    ],
    toolchain: [
      { name: 'circom', version: '2.2.3', sha256: '77'.repeat(32) },
      { name: 'snarkjs', version: '0.7.6', sha256: '88'.repeat(32) },
    ],
  };
}

function settlementPins(pins) {
  return Object.freeze({
    topologyId: pins.finalLocks.topology.id,
    verifierRoles: Object.freeze(
      pins.finalLocks.verifiers.map(entry => entry.role),
    ),
    verifierCarriers: Object.freeze(pins.finalLocks.verifiers.map(entry =>
      Object.freeze({
        baseValueSats: entry.baseSats.toString(),
        lockingBytecode: Buffer.from(entry.lockingBytecode),
      }))),
    bindingBaseSats: pins.finalLocks.binding.baseSats.toString(),
    bindingLockingBytecode: Buffer.from(
      pins.finalLocks.binding.lockingBytecode,
    ),
    bindingRedeemBytecode: Buffer.from(pins.finalLocks.binding.redeemBytecode),
    stateBaseSats: pins.finalLocks.state.baseSats.toString(),
    stateLockingBytecode: Buffer.from(pins.finalLocks.state.lockingBytecode),
  });
}

before(async () => {
  mkdirSync(TEST_ROOT, { recursive: true, mode: 0o700 });
  chmodSync(TEST_ROOT, 0o700);
  const root = mkdtempSync(path.join(TEST_ROOT, 'runtime-'));
  chmodSync(root, 0o700);
  const temporaryRoot = path.join(root, 'runtime-tmp');
  mkdirSync(temporaryRoot, { mode: 0o700 });
  const artifacts = {
    provingKey: path.join(root, 'beta.zkey'),
    r1cs: path.join(root, 'main.r1cs'),
    wasm: path.join(root, 'main.wasm'),
    verificationKey: path.join(root, 'verification_key.json'),
  };
  for (const [name, filename] of Object.entries(artifacts)) {
    writeFileSync(
      filename,
      name === 'verificationKey'
        ? readFileSync(path.join(
          ROOT,
          '03-create-your-own-pool/packages/prove/test-fixtures/two-public/verification_key.json',
        ))
        : `${name}-fixture`,
      { mode: 0o600 },
    );
  }
  const proofArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(artifacts).map(([name, filename]) => [name, Object.freeze({
      path: filename,
      sha256: HASH(Buffer.from(
        name === 'verificationKey'
          ? readFileSync(filename)
          : `${name}-fixture`,
      )),
    })]),
  ));
  const core = profileCore(proofArtifacts);
  const sourceHex = rawSource(120_000n);
  const sourceTxid = parseV2RawTransaction(sourceHex).txid;
  const instanceId = Buffer.from(sourceTxid, 'hex').reverse().toString('hex');
  const genesisRuntime = await createV2BetaChipnetGenesisRuntime({
    repositoryRoot: ROOT,
    artifactRoot: root,
    temporaryRoot,
    profileCore: core,
    proofArtifacts,
    instanceId,
  });
  const prepared = prepareV2Genesis({
    schema: V2_GENESIS_INTENT_SCHEMA,
    profileCore: core,
    maximumLiveNotes: '100000',
    fundingPublicKeyHex: PUBLIC_KEY.toString('hex'),
    changeLockingBytecodeHex: LOCK.toString('hex'),
    feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
    sourceTransactionHex: sourceHex,
  }, genesisRuntime);
  const signature = secp256k1.signMessageHashSchnorr(
    PRIVATE_KEY,
    Buffer.from(prepared.signingRequest.digestHex, 'hex'),
  );
  assert.ok(signature instanceof Uint8Array);
  const finalized = finalizeV2Genesis(
    prepared,
    Buffer.from(signature),
    genesisRuntime,
  );
  const pins = deriveV2FinalizedGenesisPackagePins(finalized, genesisRuntime);
  const fundingHex = rawSource(20_000_000n);
  base = Object.freeze({
    root,
    core,
    profileId: deriveProfileId(core),
    instanceId,
    proofArtifacts,
    genesisHex: finalized.genesis.rawTransactionHex,
    genesisTxid: finalized.genesis.transactionId,
    initialState: Buffer.from(pins.initialStateHex, 'hex'),
    settlementPins: settlementPins(pins),
    fundingHex,
    fundingTxid: parseV2RawTransaction(fundingHex).txid,
  });
});

after(() => {
  if (base !== undefined) rmSync(base.root, { recursive: true, force: true });
  rmSync(TEST_ROOT, { recursive: true, force: true });
});

function fakeRuntime(maximumLiveNotes = '100000') {
  const materialSha256 = 'aa'.repeat(32);
  return Object.freeze({
    schema: V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    identity: Object.freeze({
      profileId: base.profileId,
      instanceId: base.instanceId,
      maximumLiveNotes,
      denominationSats: '10000000',
    }),
    proofArtifacts: base.proofArtifacts,
    runtimeManifestSha256: 'bb'.repeat(32),
    descriptorSha256: 'dd'.repeat(32),
    manifestSha256: 'bb'.repeat(32),
    runtimeMaterial: Object.freeze({
      profileId: base.profileId,
      instanceId: base.instanceId,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      materialSha256,
    }),
    runtimeMaterialSha256: materialSha256,
    settlementPins: base.settlementPins,
  });
}

function canonicalNativeProofResultForTest({
  inputSha256 = 'ee'.repeat(32),
  nativeProver = {},
  resultSha256 = undefined,
  timingsMs = {},
} = {}) {
  const cores = availableParallelism();
  const value = {
    schema: 'shieldkit-v2-direct-native-groth16-proof-result-v1',
    claims: {
      proofVerified: true,
      witnessCalculated: true,
      witnessR1csChecked: false,
    },
    inputSha256,
    proof: {},
    publicInputs: ['0', '0'],
    sourceHashes: Object.fromEntries(
      Object.entries(base.proofArtifacts).map(([name, artifact]) => [name, artifact.sha256]),
    ),
    timingsMs: {
      witnessCalculation: 0,
      proofGeneration: 1,
      proofVerification: 0,
      total: 0,
      ...timingsMs,
    },
    nativeProver: {
      activeCpuThreads: cores,
      backend: 'rapidsnark',
      sha256: 'cc'.repeat(32),
      ompThreads: cores,
      threads: cores,
      peakRssKiB: 1,
      userTicks: 1,
      systemTicks: 0,
      ...nativeProver,
    },
  };
  return Object.freeze({
    ...value,
    resultSha256: resultSha256 ?? HASH(Buffer.from(canonicalizeJcs(value), 'utf8')),
  });
}

async function context(t, options = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'shieldkit-beta-lifecycle-'));
  chmodSync(directory, 0o700);
  const store = openV2BetaIncrementalStore({
    databasePath: path.join(directory, 'store', 'pool.sqlite'),
  });
  store.initialize({
    profileId: Buffer.from(base.profileId, 'hex'),
    instanceId: Buffer.from(base.instanceId, 'hex'),
    networkId: 2,
    denominationSats: '10000000',
    state: base.initialState,
    outpoint: { txid: Buffer.from(base.genesisTxid, 'hex'), vout: 0 },
    acceptanceId: Buffer.alloc(32, 0x91),
    runtimeMaterialSha256: Buffer.alloc(32, 0xaa),
    runtimeManifestSha256: Buffer.alloc(32, 0xbb),
    deploymentZeroConfEvidenceSha256: Buffer.alloc(32, 0xcc),
  });
  for (let vout = 0; vout < (options.bootstrapFundingOutputs ?? 1); vout += 1) {
    store.putFundingUtxo({
      txid: Buffer.from(base.fundingTxid, 'hex'),
      vout,
      valueSats: '20000000',
    });
  }
  for (const name of ['wallet', 'journal']) {
    mkdirSync(path.join(directory, name), { mode: 0o700 });
  }
  const wallet = openV2BetaProductWallet({
    databasePath: path.join(directory, 'wallet', 'wallet.sqlite'),
    profileId: base.profileId,
    instanceId: base.instanceId,
    fundingPrivateKeyHex: PRIVATE_KEY.toString('hex'),
  });
  const journal = openV2DeliveryJournal(
    path.join(directory, 'journal', 'delivery.sqlite'),
  );
  const proofWorkspace = path.join(directory, 'proof-workspace');
  mkdirSync(proofWorkspace, { mode: 0o700 });
  const genesis = parseV2RawTransaction(base.genesisHex);
  const genesisOutput = parseSerializedSourceOutput(
    genesis.outputs[0].serializedHex,
  );
  const funding = parseV2RawTransaction(base.fundingHex);
  const fundingOutput = parseSerializedSourceOutput(
    funding.outputs[0].serializedHex,
  );
  const calls = [];
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: async (method, args) => {
      calls.push(method);
      if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
      if (method === 'getrawtransaction') {
        const txid = args[0];
        const hex = txid === base.genesisTxid ? base.genesisHex : base.fundingHex;
        return JSON.stringify({ txid, hex });
      }
      if (method === 'gettxout') {
        if (args[0] === base.fundingTxid && options.spentFunding === true) {
          return 'null';
        }
        if (args[0] === base.genesisTxid) {
          const valueSatoshis = options.tipValueSats
            ?? genesisOutput.valueSatoshis.toString();
          return JSON.stringify({
            valueSatoshis,
            scriptPubKey: { hex: genesisOutput.lockingBytecodeHex },
            tokenData: {
              category: Buffer.from(base.instanceId, 'hex').reverse().toString('hex'),
              amount: '0',
              nft: {
                capability: 'mutable',
                commitment: base.initialState.toString('hex'),
              },
            },
          });
        }
        return JSON.stringify({
          valueSatoshis: fundingOutput.valueSatoshis.toString(),
          scriptPubKey: { hex: fundingOutput.lockingBytecodeHex },
        });
      }
      throw new Error(`unexpected test-only RPC method ${method}`);
    },
  });
  t.after(() => {
    journal.close();
    wallet.close();
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { directory, store, wallet, journal, rpc, proofWorkspace, calls };
}

function injected(prove, afterSafePreSendWalletAbort = undefined) {
  return Object.freeze({
    assertRuntimeCacheCapability: value => value,
    assertNativeProofArtifacts: value => value,
    afterSafePreSendWalletAbort,
    prove,
    deriveNativeProofArtifacts: runtime => Object.freeze({ artifacts: runtime.proofArtifacts }),
    createVmEvidence: async () => {
      throw new Error('VM must not run after a prover failure');
    },
    submitAdmission: async () => {
      throw new Error('admission must not run after a prover failure');
    },
    rebroadcastAdmission: async () => {
      throw new Error('exact rebroadcast must not run after a prover failure');
    },
    reconcileAdmission: async () => {
      throw new Error('reconciliation must not run after a prover failure');
    },
  });
}

function lifecycle(subject, runtime = fakeRuntime(), dependencies = injected(
  async () => { throw Object.assign(new Error('test-only proof failure'), { code: 'TEST_PROOF_FAILED' }); },
)) {
  return createV2BetaProductActionLifecycleForTest({
    profileCore: base.core,
    runtimeCache: runtime,
    nativeProverInstallation: { binary: { sha256: 'cc'.repeat(32) } },
    store: subject.store,
    wallet: subject.wallet,
    journal: subject.journal,
    rpc: subject.rpc,
    proofWorkspaceDirectory: subject.proofWorkspace,
  }, dependencies);
}

function reserveDepositForRecovery(subject, operationId) {
  subject.wallet.stageChangeWallet({ operationId });
  const note = subject.wallet.stageDepositNote({ operationId, postActionSequence: '1' });
  subject.store.putEncryptedRecord({
    recordId: note.privateStoreMaterial.recordId,
    record: note.privateStoreMaterial.encryptedRecord,
  });
  subject.store.reserveOperation({
    operationId,
    kind: 'deposit',
    selectedNoteId: null,
    funding: { txid: Buffer.from(base.fundingTxid, 'hex'), vout: 0 },
  });
}

function stageDepositForRecovery(subject, operationId) {
  reserveDepositForRecovery(subject, operationId);
  const transition = subject.store.deriveProvingTransition({
    operationId,
    outputNoteLeaf: Buffer.from([...new Uint8Array(31), 0x51]),
    encryptedRecord: Buffer.alloc(128, 0x52),
    publicNullifier: null,
    withdrawalLockingBytecodeHash: null,
    transactionContextHash: Buffer.alloc(32, 0x53),
  });
  subject.store.stageOperationArtifacts({
    operationId,
    packet: transition.packet,
    proofArtifact: Buffer.from('recovery-proof'),
    transactionArtifact: Buffer.from('recovery-transaction'),
  });
}

function reopenForRecovery(subject) {
  subject.journal.close();
  subject.wallet.close();
  subject.store.close();
  return {
    ...subject,
    store: openV2BetaIncrementalStore({ databasePath: path.join(subject.directory, 'store', 'pool.sqlite') }),
    wallet: openV2BetaProductWallet({
      databasePath: path.join(subject.directory, 'wallet', 'wallet.sqlite'),
      profileId: base.profileId,
      instanceId: base.instanceId,
      fundingPrivateKeyHex: PRIVATE_KEY.toString('hex'),
    }),
    journal: openV2DeliveryJournal(path.join(subject.directory, 'journal', 'delivery.sqlite')),
  };
}

test('action RPC evidence projects only the exact admission delta', () => {
  const before = Object.freeze({
    backend: 'layer1-bchn-chipnet',
    genesis: CHIPNET_GENESIS_HASH,
    methodCounts: Object.freeze({
      getblockhash: 1,
      getrawtransaction: 4,
      gettxout: 3,
      scantxoutset: 0,
      sendrawtransaction: 0,
      testmempoolaccept: 0,
    }),
  });
  const after = Object.freeze({
    backend: before.backend,
    genesis: before.genesis,
    methodCounts: Object.freeze({
      getblockhash: 1,
      getrawtransaction: 5,
      gettxout: 4,
      scantxoutset: 0,
      sendrawtransaction: 1,
      testmempoolaccept: 1,
    }),
  });
  assert.deepEqual(
    deriveV2BetaOneShotAdmissionRpcObservationForTest(before, after),
    {
      backend: before.backend,
      genesis: before.genesis,
      methodCounts: {
        getblockhash: 0,
        getrawtransaction: 1,
        gettxout: 1,
        scantxoutset: 0,
        sendrawtransaction: 1,
        testmempoolaccept: 1,
      },
    },
  );
  assert.throws(
    () => deriveV2BetaOneShotAdmissionRpcObservationForTest(before, {
      ...after,
      methodCounts: { ...after.methodCounts, sendrawtransaction: 2 },
    }),
    { code: 'BETA_RPC_OBSERVATION_REJECTED' },
  );
});

test('production construction rejects an unbranded native prover installation outside the explicit unit-test seam', async (t) => {
  const subject = await context(t);
  await assert.rejects(
    createV2BetaProductActionLifecycle({
      profileCore: base.core,
      runtimeCache: fakeRuntime(),
      nativeProverInstallation: { binary: { sha256: 'cc'.repeat(32) } },
      store: subject.store,
      wallet: subject.wallet,
      journal: subject.journal,
      rpc: subject.rpc,
      proofWorkspaceDirectory: subject.proofWorkspace,
    }),
    error => error?.code === 'NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED',
  );
});

test('production construction rejects arbitrary dependency injection', async (t) => {
  const subject = await context(t);
  await assert.rejects(
    createV2BetaProductActionLifecycle({
      profileCore: base.core,
      runtimeCache: fakeRuntime(),
      nativeProverInstallation: { binary: { sha256: 'cc'.repeat(32) } },
      store: subject.store,
      wallet: subject.wallet,
      journal: subject.journal,
      rpc: subject.rpc,
      proofWorkspaceDirectory: subject.proofWorkspace,
    }, injected(async () => { throw new Error('must not run'); })),
    error => error instanceof V2BetaProductActionLifecycleError
      && error.code === 'BETA_ACTION_INJECTION_REJECTED',
  );
});

test('lifecycle rejects a structural native-proof-artifact lookalike before proving', async (t) => {
  const subject = await context(t);
  const dependencies = {
    ...injected(async () => { throw new Error('proof worker must not execute'); }),
    deriveNativeProofArtifacts: runtime => ({ artifacts: runtime.proofArtifacts }),
    assertNativeProofArtifacts: () => {
      throw Object.assign(new Error('unbranded proof artifact lookalike'), {
        code: 'BETA_LINKED_RUNTIME_PROOF_ARTIFACTS_UNBRANDED',
      });
    },
  };
  assert.throws(
    () => lifecycle(subject, fakeRuntime(), dependencies),
    error => error?.code === 'BETA_PROOF_ARTIFACT_REJECTED',
  );
});

test('native proof provenance rejects a missing input hash and a mismatched canonical result hash before witness assembly', async (t) => {
  for (const [operationId, prove] of [
    ['deposit.proof-input-missing', async () => canonicalNativeProofResultForTest({ inputSha256: null })],
    ['deposit.proof-result-mismatch', async () => canonicalNativeProofResultForTest({ resultSha256: 'ff'.repeat(32) })],
  ]) {
    const subject = await context(t);
    await assert.rejects(
      lifecycle(subject, fakeRuntime(), injected(prove)).executeDeposit({ operationId }),
      error => error instanceof V2BetaProductActionLifecycleError
        && error.code === 'BETA_PROOF_ARTIFACT_REJECTED',
    );
    assert.equal(subject.wallet.publicSummary().rejectedDepositNoteCount, 1);
  }
});

test('persisted native proof provenance rejects partial-core and zero-work results', async (t) => {
  const cores = availableParallelism();
  const cases = [
    { nativeProver: { activeCpuThreads: Math.max(0, cores - 1) } },
    { nativeProver: { threads: Math.max(0, cores - 1) } },
    { nativeProver: { peakRssKiB: 0 } },
    { nativeProver: { userTicks: 0, systemTicks: 0 } },
    { timingsMs: { proofGeneration: 0 } },
  ];
  for (const [index, overrides] of cases.entries()) {
    const subject = await context(t);
    await assert.rejects(
      lifecycle(subject, fakeRuntime(), injected(
        async () => canonicalNativeProofResultForTest(overrides),
      )).executeDeposit({ operationId: `deposit.proof-all-core-${index}` }),
      error => error instanceof V2BetaProductActionLifecycleError
        && error.code === 'BETA_PROOF_ARTIFACT_REJECTED',
    );
  }
});

test('persisted proof containment rejects every tampered enforcement field before admission', () => {
  const containment = () => ({
    backend: 'linux-systemd-cgroup-v2',
    memoryMaxBytes: '4294967296',
    memorySwapMaxBytes: '0',
    memoryPeakBytes: '1',
    oomDelta: 0,
    oomKillDelta: 0,
    terminatedSuccessfully: true,
  });
  const cases = [
    value => { value.backend = 'uncontained'; },
    value => { value.memoryMaxBytes = '4294967295'; },
    value => { value.memorySwapMaxBytes = '1'; },
    value => { value.memoryPeakBytes = '0'; },
    value => { value.memoryPeakBytes = '4294967297'; },
    value => { value.oomDelta = 1; },
    value => { value.oomKillDelta = 1; },
    value => { value.terminatedSuccessfully = false; },
  ];
  for (const tamper of cases) {
    const value = containment();
    tamper(value);
    assert.throws(
      () => validateV2BetaPersistedProofContainment(value),
      error => error instanceof V2BetaProductActionLifecycleError
        && error.code === 'BETA_PROOF_TELEMETRY_UNAVAILABLE',
    );
  }
});

test('canonical native proof provenance passes the lifecycle gate before the test runtime rejects witness construction', async (t) => {
  const subject = await context(t);
  await assert.rejects(
    lifecycle(subject, fakeRuntime(), injected(
      async () => canonicalNativeProofResultForTest(),
    )).executeDeposit({ operationId: 'deposit.proof-provenance-valid' }),
    error => error?.code !== 'BETA_PROOF_ARTIFACT_REJECTED',
  );
});

test('a prover failure atomically rejects only the pre-send operation and releases funding', async (t) => {
  const subject = await context(t);
  await assert.rejects(
    lifecycle(subject).executeDeposit({ operationId: 'deposit.proof-failure' }),
    error => error?.code === 'TEST_PROOF_FAILED',
  );
  assert.equal(subject.store.activeOperation(), null);
  assert.equal(subject.store.availableFundingUtxos().length, 1);
  assert.equal(subject.wallet.publicSummary().orphanRecoverableChangeCount, 1);
  assert.equal(subject.wallet.publicSummary().rejectedDepositNoteCount, 1);
  assert.equal(subject.journal.record('deposit.proof-failure'), null);
});

test('the first deposit can reserve one of the ten pool-create action funding UTXOs', async (t) => {
  const subject = await context(t, { bootstrapFundingOutputs: 10 });
  assert.equal(subject.store.availableFundingUtxos().length, 10);
  await assert.rejects(
    lifecycle(subject).executeDeposit({ operationId: 'deposit.bootstrap-first' }),
    error => error?.code === 'TEST_PROOF_FAILED',
  );
  assert.equal(subject.store.activeOperation(), null);
  assert.equal(subject.store.availableFundingUtxos().length, 10);
});

test('reopen and resume finish only the exact journal-marked safe pre-send abort after a crash between wallet and store finalization', async (t) => {
  const subject = await context(t);
  const crash = Object.assign(new Error('test crash after durable wallet abort'), {
    code: 'TEST_AFTER_WALLET_ABORT_CRASH',
  });
  await assert.rejects(
    lifecycle(subject, fakeRuntime(), injected(
      async () => { throw Object.assign(new Error('test-only proof failure'), { code: 'TEST_PROOF_FAILED' }); },
      () => { throw crash; },
    )).executeDeposit({ operationId: 'deposit.abort-reopen' }),
    error => error?.code === 'BETA_PRE_SEND_ABORT_FAILED',
  );
  assert.equal(subject.store.activeOperation()?.operationId, 'deposit.abort-reopen');
  assert.equal(subject.wallet.publicSummary().rejectedDepositNoteCount, 1);
  assert.deepEqual(
    subject.journal.safePreSendAbortMarker('deposit.abort-reopen'),
    { operationId: 'deposit.abort-reopen', kind: 'deposit', reason: 'action-failed-before-network-send' },
  );
  assert.equal(subject.journal.record('deposit.abort-reopen'), null);

  subject.journal.close();
  subject.wallet.close();
  subject.store.close();
  const reopened = {
    ...subject,
    store: openV2BetaIncrementalStore({ databasePath: path.join(subject.directory, 'store', 'pool.sqlite') }),
    wallet: openV2BetaProductWallet({
      databasePath: path.join(subject.directory, 'wallet', 'wallet.sqlite'),
      profileId: base.profileId,
      instanceId: base.instanceId,
      fundingPrivateKeyHex: PRIVATE_KEY.toString('hex'),
    }),
    journal: openV2DeliveryJournal(path.join(subject.directory, 'journal', 'delivery.sqlite')),
  };
  await assert.rejects(
    lifecycle(reopened).resume({ operationId: 'deposit.abort-reopen' }),
    error => error instanceof V2BetaProductActionLifecycleError
      && error.code === 'BETA_ACTION_ABORTED_PRE_SEND',
  );
  assert.equal(reopened.store.activeOperation(), null);
  assert.equal(reopened.store.availableFundingUtxos().length, 1);
  assert.equal(reopened.wallet.publicSummary().orphanRecoverableChangeCount, 1);
  assert.equal(reopened.wallet.publicSummary().rejectedDepositNoteCount, 1);
  reopened.journal.close();
  reopened.wallet.close();
  reopened.store.close();
});

test('command-start recovery returns null without an active operation', async (t) => {
  const subject = await context(t);
  assert.equal(await lifecycle(subject).recoverOrResumeActive({ expectedKind: 'deposit' }), null);
});

test('SIGKILL-style reopen safely aborts only a reserved operation with no delivery record', async (t) => {
  const subject = await context(t);
  const operationId = 'deposit.command-start-reserved';
  reserveDepositForRecovery(subject, operationId);
  const reopened = reopenForRecovery(subject);
  assert.equal(await lifecycle(reopened).recoverOrResumeActive({ expectedKind: 'deposit' }), null);
  assert.equal(reopened.store.activeOperation(), null);
  assert.deepEqual(reopened.journal.safePreSendAbortMarker(operationId), {
    operationId, kind: 'deposit', reason: 'command-start-recovery-before-network-send',
  });
  assert.equal(reopened.calls.includes('testmempoolaccept'), false);
  assert.equal(reopened.calls.includes('sendrawtransaction'), false);
  reopened.journal.close();
  reopened.wallet.close();
  reopened.store.close();
});

test('command-start recovery reports the exact active operation on expected-kind mismatch', async (t) => {
  const subject = await context(t);
  const operationId = 'deposit.command-start-kind-mismatch';
  reserveDepositForRecovery(subject, operationId);
  await assert.rejects(
    lifecycle(subject).recoverOrResumeActive({ expectedKind: 'withdrawal' }),
    error => error?.code === 'BETA_ACTION_RECOVERY_KIND_MISMATCH'
      && error.recoverable === true && error.message.includes(operationId),
  );
  assert.equal(subject.store.activeOperation()?.operationId, operationId);
  assert.equal(subject.calls.includes('sendrawtransaction'), false);
});

test('command-start recovery never substitutes another active idempotency key', async (t) => {
  const subject = await context(t);
  const operationId = 'deposit.command-start-id-mismatch';
  reserveDepositForRecovery(subject, operationId);
  await assert.rejects(
    lifecycle(subject).recoverOrResumeActive({
      expectedKind: 'deposit',
      expectedOperationId: 'deposit.requested-id',
    }),
    error => error?.code === 'BETA_ACTION_RECOVERY_ID_MISMATCH'
      && error.recoverable === true
      && error.message.includes(operationId)
      && error.message.includes('deposit.requested-id'),
  );
  assert.equal(subject.store.activeOperation()?.operationId, operationId);
  assert.equal(subject.calls.includes('testmempoolaccept'), false);
  assert.equal(subject.calls.includes('sendrawtransaction'), false);
});

test('SIGKILL-style staged and accepted local-commit recovery stays on immutable-artifact handling without a duplicate send', async (t) => {
  for (const accepted of [false, true]) {
    const subject = await context(t);
    const operationId = accepted
      ? 'deposit.command-start-accepted'
      : 'deposit.command-start-staged';
    stageDepositForRecovery(subject, operationId);
    if (accepted) {
      subject.store.applyAcceptedZeroConfSuccessor({
        operationId,
        successor: { txid: Buffer.alloc(32, 0x61), vout: 0, acceptanceId: Buffer.alloc(32, 0x62) },
        change: { txid: Buffer.alloc(32, 0x63), vout: 0, valueSats: '10000000' },
        ownedOutputNoteId: null,
        ownedOutputRecordId: null,
        ownedOutputNullifier: null,
      });
      assert.equal(subject.store.activeOperation()?.localWalletCommitPending, true);
    }
    const reopened = reopenForRecovery(subject);
    await assert.rejects(
      lifecycle(reopened).recoverOrResumeActive({ expectedKind: 'deposit' }),
      error => error?.code === 'BETA_ACTION_ARTIFACT_REJECTED',
    );
    assert.equal(reopened.store.activeOperation()?.operationId, operationId);
    assert.equal(reopened.calls.includes('testmempoolaccept'), false);
    assert.equal(reopened.calls.includes('sendrawtransaction'), false);
    reopened.journal.close();
    reopened.wallet.close();
    reopened.store.close();
  }
});

test('exact tip value and live funding checks fail before staging private action material', async (t) => {
  const wrongTip = await context(t, { tipValueSats: '999' });
  await assert.rejects(
    lifecycle(wrongTip).executeDeposit({ operationId: 'deposit.wrong-tip' }),
    error => error?.code === 'BETA_TIP_READBACK_REJECTED',
  );
  assert.equal(wrongTip.wallet.publicSummary().changeWalletCount, 0);

  const spent = await context(t, { spentFunding: true });
  await assert.rejects(
    lifecycle(spent).executeDeposit({ operationId: 'deposit.spent-funding' }),
    error => error?.code === 'BETA_FUNDING_SOURCE_REJECTED',
  );
  assert.equal(spent.wallet.publicSummary().changeWalletCount, 0);
});

test('runtime capacity must equal the immutable capacity in the accepted state', async (t) => {
  const subject = await context(t);
  await assert.rejects(
    lifecycle(subject, fakeRuntime('99999')).executeDeposit({
      operationId: 'deposit.capacity-mismatch',
    }),
    error => error?.code === 'BETA_TIP_READBACK_REJECTED',
  );
  assert.equal(subject.wallet.publicSummary().changeWalletCount, 0);
});
