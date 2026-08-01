// Real local regression coverage for the offline V2 Direct genesis builder.
// The PF10 locks are compiled by production code from a hash-pinned two-public
// Groth16 VK; no test-supplied verifier or covenant bytecode is accepted.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import {
  after,
  before,
  test,
} from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeTransaction,
  hash160,
  secp256k1,
} from '@bitauth/libauth';

import {
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  assertV2VmResourceMetrics,
} from '../../kit/v2/vm-evidence.mjs';
import {
  V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
  V2_GENESIS_FINALIZED_SCHEMA,
  V2_GENESIS_INPUT_SEQUENCE,
  V2_GENESIS_INTENT_SCHEMA,
  V2_GENESIS_LOCKTIME,
  V2_GENESIS_PREPARED_SCHEMA,
  V2_GENESIS_RUNTIME_SCHEMA,
  V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
  V2_GENESIS_TRANSACTION_VERSION,
  V2GenesisError,
  createV2BetaChipnetGenesisRuntime,
  createV2GenesisRuntime,
  deriveV2FinalizedGenesisPackagePins,
  finalizeV2Genesis,
  prepareV2Genesis,
} from './genesis.mjs';
import {
  deriveProfileId,
  V2_PROFILE_DOMAINS,
} from './profile-core.mjs';

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../',
);
const hex = (value) => Buffer.from(value).toString('hex');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const repeat = (byte) => byte.repeat(64);
const privateKey = Buffer.from(`${'00'.repeat(31)}01`, 'hex');
const publicKey = Buffer.from(secp256k1.derivePublicKeyCompressed(privateKey));

let testDirectory;
let temporaryRoot;
let proofArtifacts;
let core;
let defaultSourceTransactionHex;
let defaultInstanceId;
let runtime;
let betaRuntime;
let tinySourceTransactionHex;
let tinyRuntime;

function p2pkhLock(key = publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(key)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function profileCore(pins) {
  return {
    schema: 'shieldkit-profile-core-v2-direct',
    network: { id: 2, name: 'chipnet' },
    denominationSats: '10000000',
    proof: {
      system: 'groth16',
      curve: 'bn254',
      relationId: 'shieldkit-pool-action-v2-direct',
      relationSha256: repeat('1'),
      r1csSha256: pins.r1cs.sha256,
      verificationKeySha256: pins.verificationKey.sha256,
      witnessWasmSha256: pins.wasm.sha256,
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
      { id: 'carrier-base', sha256: repeat('5') },
      { id: 'state-base', sha256: repeat('6') },
    ],
    toolchain: [
      { name: 'circom', version: '2.2.3', sha256: repeat('7') },
      { name: 'snarkjs', version: '0.7.6', sha256: repeat('8') },
    ],
  };
}

function sourceTransaction({
  valueSatoshis = 80_000n,
  outputZero = undefined,
  outputs = undefined,
} = {}) {
  return hex(encodeTransaction({
    version: 2,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x42),
      outpointIndex: 1,
      sequenceNumber: 0,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: outputs ?? [outputZero ?? {
      valueSatoshis,
      lockingBytecode: p2pkhLock(),
    }],
    locktime: 0,
  }));
}

function instanceIdOf(sourceTransactionHex) {
  return Buffer.from(
    parseV2RawTransaction(sourceTransactionHex).txid,
    'hex',
  ).reverse().toString('hex');
}

function fixture({
  sourceTransactionHex = defaultSourceTransactionHex,
  profile = core,
} = {}) {
  return {
    schema: V2_GENESIS_INTENT_SCHEMA,
    profileCore: profile,
    maximumLiveNotes: '32',
    fundingPublicKeyHex: hex(publicKey),
    changeLockingBytecodeHex: hex(p2pkhLock()),
    feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
    sourceTransactionHex,
  };
}

function signature(prepared) {
  const value = secp256k1.signMessageHashSchnorr(
    privateKey,
    Buffer.from(prepared.signingRequest.digestHex, 'hex'),
  );
  assert.notEqual(typeof value, 'string');
  return Buffer.from(value);
}

function rejectsCode(action, code) {
  return assert.throws(
    action,
    (error) => error instanceof V2GenesisError && error.code === code,
  );
}

async function rejectsCodeAsync(action, code) {
  return assert.rejects(
    action,
    (error) => error instanceof V2GenesisError && error.code === code,
  );
}

async function createRuntime(instanceId) {
  return createV2GenesisRuntime({
    repositoryRoot,
    temporaryRoot,
    profileCore: core,
    proofArtifacts,
    instanceId,
  });
}

async function packagedGenesisInspector() {
  const subject = await import('./genesis.mjs');
  assert.equal(
    typeof subject.inspectV2PackagedGenesisBinding,
    'function',
    'genesis module must export inspectV2PackagedGenesisBinding',
  );
  return subject.inspectV2PackagedGenesisBinding;
}

function packagedSettlementPins(packagePins) {
  return {
    topologyId: packagePins.finalLocks.topology.id,
    verifierRoles: packagePins.finalLocks.verifiers.map((entry) => entry.role),
    verifierCarriers: packagePins.finalLocks.verifiers.map((entry) => ({
      baseValueSats: entry.baseSats.toString(),
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    })),
    bindingBaseSats: packagePins.finalLocks.binding.baseSats.toString(),
    bindingLockingBytecode: Buffer.from(
      packagePins.finalLocks.binding.lockingBytecode,
    ),
    bindingRedeemBytecode: Buffer.from(
      packagePins.finalLocks.binding.redeemBytecode,
    ),
    stateBaseSats: packagePins.finalLocks.state.baseSats.toString(),
    stateLockingBytecode: Buffer.from(
      packagePins.finalLocks.state.lockingBytecode,
    ),
  };
}

function cloneSettlementPins(value) {
  return {
    ...value,
    verifierRoles: [...value.verifierRoles],
    verifierCarriers: value.verifierCarriers.map((entry) => ({
      ...entry,
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    })),
    bindingLockingBytecode: Buffer.from(value.bindingLockingBytecode),
    bindingRedeemBytecode: Buffer.from(value.bindingRedeemBytecode),
    stateLockingBytecode: Buffer.from(value.stateLockingBytecode),
  };
}

function packagedDescriptor(packagePins) {
  return {
    profileId: packagePins.profileId,
    instanceId: packagePins.instanceId,
    genesis: {
      transactionId: packagePins.genesis.transactionId,
      outpointIndex: packagePins.genesis.outputIndex,
    },
    initialState: Buffer.from(packagePins.initialStateHex, 'hex'),
  };
}

function mutateTransactionBytes(raw, mutate) {
  const decoded = decodeTransaction(Uint8Array.from(raw));
  assert.notEqual(typeof decoded, 'string');
  mutate(decoded);
  return Buffer.from(encodeTransaction(decoded));
}

function refreshPackagedGenesisTransactionId(value) {
  value.descriptor.genesis.transactionId = parseV2RawTransaction(
    value.rawGenesisTransaction.toString('hex'),
  ).txid;
}

function packagedGenesisFixture() {
  const prepared = prepareV2Genesis(fixture(), runtime);
  const finalized = finalizeV2Genesis(prepared, signature(prepared), runtime);
  const packagePins = deriveV2FinalizedGenesisPackagePins(finalized, runtime);
  return {
    descriptor: packagedDescriptor(packagePins),
    rawGenesisTransaction: Buffer.from(
      finalized.genesis.rawTransactionHex,
      'hex',
    ),
    rawSourceTransaction: Buffer.from(defaultSourceTransactionHex, 'hex'),
    settlementPins: packagedSettlementPins(packagePins),
    finalized,
    packagePins,
  };
}

before(async () => {
  const privateParent = path.join(
    repositoryRoot,
    '.codex-build',
    'test-tmp',
  );
  await mkdir(privateParent, { recursive: true, mode: 0o700 });
  await chmod(privateParent, 0o700);
  testDirectory = await mkdtemp(path.join(privateParent, 'v2-genesis-'));
  temporaryRoot = path.join(testDirectory, 'runtime-tmp');
  await mkdir(temporaryRoot, { mode: 0o700 });

  const artifactPaths = {
    provingKey: path.join(testDirectory, 'development.zkey'),
    r1cs: path.join(testDirectory, 'main.r1cs'),
    wasm: path.join(testDirectory, 'main.wasm'),
    verificationKey: path.join(testDirectory, 'verification_key.json'),
  };
  await writeFile(artifactPaths.provingKey, 'development-key-fixture', {
    mode: 0o600,
  });
  await writeFile(artifactPaths.r1cs, 'r1cs-fixture', { mode: 0o600 });
  await writeFile(artifactPaths.wasm, 'wasm-fixture', { mode: 0o600 });
  await writeFile(
    artifactPaths.verificationKey,
    await readFile(path.join(
      repositoryRoot,
      '03-create-your-own-pool/packages/prove/test-fixtures/two-public/verification_key.json',
    )),
    { mode: 0o600 },
  );
  proofArtifacts = Object.freeze(Object.fromEntries(
    await Promise.all(Object.entries(artifactPaths).map(
      async ([name, artifactPath]) => [
        name,
        Object.freeze({
          path: artifactPath,
          sha256: hash(await readFile(artifactPath)),
        }),
      ],
    )),
  ));
  core = profileCore(proofArtifacts);

  defaultSourceTransactionHex = sourceTransaction();
  defaultInstanceId = instanceIdOf(defaultSourceTransactionHex);
  runtime = await createRuntime(defaultInstanceId);
  betaRuntime = await createV2BetaChipnetGenesisRuntime({
    repositoryRoot,
    artifactRoot: testDirectory,
    temporaryRoot,
    profileCore: core,
    proofArtifacts,
    instanceId: defaultInstanceId,
  });

  tinySourceTransactionHex = sourceTransaction({ valueSatoshis: 16_000n });
  tinyRuntime = await createRuntime(instanceIdOf(tinySourceTransactionHex));
});

after(async () => {
  if (testDirectory !== undefined) {
    await rm(testDirectory, { recursive: true, force: true });
  }
});

test('V2 genesis derives exact PF10 locks internally and passes BCH_2026_STANDARD', () => {
  const intent = fixture();
  assert.equal(runtime.schema, V2_GENESIS_RUNTIME_SCHEMA);
  assert.equal(runtime.profileId, deriveProfileId(core));
  assert.equal(runtime.instanceId, defaultInstanceId);
  assert.deepEqual(runtime.baseValues.verifierSats, Array(10).fill('1200'));
  assert.equal(runtime.baseValues.bindingSats, '1200');
  assert.equal(runtime.baseValues.stateSats, '2500');

  const prepared = prepareV2Genesis(intent, runtime);
  assert.equal(prepared.schema, V2_GENESIS_PREPARED_SCHEMA);
  assert.equal(prepared.profileId, deriveProfileId(core));
  assert.equal(prepared.instanceId, defaultInstanceId);
  assert.equal(
    prepared.runtime.runtimeMaterialSha256,
    runtime.runtimeMaterialSha256,
  );
  assert.equal(prepared.runtime.finalLocksSha256, runtime.finalLocksSha256);
  assert.deepEqual(
    prepared.runtime.baseValues.verifierSats,
    Array(10).fill('1200'),
  );
  assert.equal(prepared.runtime.baseValues.bindingSats, '1200');
  assert.equal(prepared.runtime.baseValues.stateSats, '2500');
  assert.equal(prepared.signingRequest.sighashType, 0x61);

  const finalized = finalizeV2Genesis(
    prepared,
    signature(prepared),
    runtime,
  );
  assert.equal(finalized.schema, V2_GENESIS_FINALIZED_SCHEMA);
  assert.equal(finalized.instanceId, defaultInstanceId);
  assert.equal(finalized.stateNftCategoryWire, defaultInstanceId);
  assert.equal(finalized.measurements.inputCount, 1);
  assert.equal(finalized.measurements.outputCount, 13);
  assert.equal(finalized.measurements.maximumTransactionBytes, 100_000);
  assert.equal(finalized.measurements.maximumUnlockingBytecodeBytes, 10_000);
  assert.equal(finalized.measurements.bch2026StandardVmAccepted, true);
  assert.equal(finalized.claims.productionQualified, false);
  const packagePins = deriveV2FinalizedGenesisPackagePins(finalized, runtime);
  assert.equal(packagePins.instanceId, defaultInstanceId);
  assert.equal(packagePins.profileId, finalized.profileId);
  assert.equal(packagePins.genesis.transactionId, finalized.genesis.transactionId);
  assert.equal(
    packagePins.genesis.rawTransactionHex,
    finalized.genesis.rawTransactionHex,
  );
  assert.equal(packagePins.initialStateHex, finalized.initialStateHex);
  assert.equal(packagePins.finalLocks.verifiers.length, 10);
  assert.throws(
    () => deriveV2FinalizedGenesisPackagePins({ ...finalized }, runtime),
    (error) =>
      error instanceof V2GenesisError
      && error.code === 'GENESIS_FINALIZED_INVALID',
  );
  assert.throws(
    () => deriveV2FinalizedGenesisPackagePins(finalized, { ...runtime }),
    (error) =>
      error instanceof V2GenesisError
      && error.code === 'GENESIS_RUNTIME_INVALID',
  );

  const parsed = assertV2StandardTransactionEnvelope(
    parseV2RawTransaction(finalized.genesis.rawTransactionHex),
  );
  assert.equal(parsed.version, V2_GENESIS_TRANSACTION_VERSION);
  assert.equal(parsed.locktime, V2_GENESIS_LOCKTIME);
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.outputs.length, 13);
  assert.equal(
    parsed.inputs[0].outpoint.txid,
    parseV2RawTransaction(defaultSourceTransactionHex).txid,
  );
  assert.equal(parsed.inputs[0].outpoint.vout, 0);
  assert.equal(parsed.inputs[0].sequence, V2_GENESIS_INPUT_SEQUENCE);
  assert.equal(parsed.inputs[0].unlockingBytecodeBytes, 100);

  const outputs = parsed.outputs.map((output) =>
    parseSerializedSourceOutput(output.serializedHex));
  assert.equal(outputs[0].valueSatoshis, 2_500n);
  assert.equal(outputs[0].token.categoryWire, defaultInstanceId);
  assert.equal(outputs[0].token.amount, '0');
  assert.equal(outputs[0].token.nft.capability, 'mutable');
  assert.equal(outputs[0].token.nft.commitmentHex.length, 256);
  assert.equal(
    outputs.filter(
      (output) => output.token?.nft?.capability === 'mutable',
    ).length,
    1,
  );
  for (const output of outputs.slice(1, 11)) {
    assert.equal(output.token, null);
    assert.equal(output.valueSatoshis, 1_200n);
    assert.equal(output.lockingBytecode.length, 35);
  }
  assert.equal(outputs[11].valueSatoshis, 1_200n);
  assert.equal(outputs[11].lockingBytecode.length, 35);
  assert.equal(
    outputs[12].lockingBytecode.toString('hex'),
    intent.changeLockingBytecodeHex,
  );
  assert.equal(outputs[12].token, null);

  const source = parseV2RawTransaction(defaultSourceTransactionHex);
  const sourceValue = parseSerializedSourceOutput(
    source.outputs[0].serializedHex,
  ).valueSatoshis;
  const fee = sourceValue
    - outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
  assert.equal(fee, BigInt(parsed.sizeBytes));
  assert.equal(finalized.measurements.feeSats, parsed.sizeBytes.toString());

  const transaction = decodeTransaction(
    Uint8Array.from(Buffer.from(finalized.genesis.rawTransactionHex, 'hex')),
  );
  assert.notEqual(typeof transaction, 'string');
  const sourceOutput = parseSerializedSourceOutput(
    source.outputs[0].serializedHex,
  );
  const sourceOutputs = [{
    valueSatoshis: sourceOutput.valueSatoshis,
    lockingBytecode: Uint8Array.from(sourceOutput.lockingBytecode),
  }];
  const vm = createVirtualMachineBch2026(true);
  assert.equal(vm.verify({ sourceOutputs, transaction }), true);
  const state = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction });
  assert.equal(vm.stateSuccess(state), true);
  assertV2VmResourceMetrics(finalized.measurements.inputMetrics, {
    inputIndex: 0,
    unlockingBytecodeBytes: 100,
  });
});

test('single-contributor beta genesis uses a non-interchangeable runtime capability', () => {
  assert.equal(
    betaRuntime.schema,
    V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
  );
  assert.equal(
    betaRuntime.eligibility,
    'beta-single-contributor-unqualified',
  );
  assert.equal(betaRuntime.instanceId, runtime.instanceId);
  assert.equal(betaRuntime.profileId, runtime.profileId);
  assert.equal(betaRuntime.finalLocksSha256, runtime.finalLocksSha256);

  const prepared = prepareV2Genesis(fixture(), betaRuntime);
  assert.equal(
    prepared.runtime.schema,
    V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
  );
  const finalized = finalizeV2Genesis(
    prepared,
    signature(prepared),
    betaRuntime,
  );
  assert.equal(finalized.claims.productionQualified, false);
  assert.equal(finalized.measurements.bch2026StandardVmAccepted, true);
  assert.throws(
    () => deriveV2FinalizedGenesisPackagePins(finalized, runtime),
    (error) =>
      error instanceof V2GenesisError
      && error.code === 'GENESIS_RUNTIME_MISMATCH',
  );
  assert.throws(
    () => prepareV2Genesis(fixture(), { ...betaRuntime }),
    (error) =>
      error instanceof V2GenesisError
      && error.code === 'GENESIS_RUNTIME_INVALID',
  );
});

test('packaged genesis binding independently replays the exact VM-accepted genesis and rejects every binding drift', async (t) => {
  const inspect = await packagedGenesisInspector();
  const subject = packagedGenesisFixture();
  const input = () => ({
    descriptor: structuredClone(subject.descriptor),
    rawGenesisTransaction: Buffer.from(subject.rawGenesisTransaction),
    rawSourceTransaction: Buffer.from(subject.rawSourceTransaction),
    settlementPins: cloneSettlementPins(subject.settlementPins),
  });
  const inspected = inspect(input());
  assert.equal(inspected.profileId, subject.packagePins.profileId);
  assert.equal(inspected.instanceId, subject.packagePins.instanceId);
  assert.equal(inspected.genesisTransactionId, subject.finalized.genesis.transactionId);
  assert.equal(inspected.stateOutputIndex, 0);
  assert.equal(inspected.feeSats, subject.finalized.measurements.feeSats);
  assert.equal(inspected.bch2026StandardVmAccepted, true);

  const cases = [
    ['source transaction bytes', (value) => {
      value.rawSourceTransaction[value.rawSourceTransaction.length - 1] ^= 1;
    }],
    ['source outpoint', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.inputs[0].outpointIndex = 1; },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['missing descriptor genesis output index', (value) => {
      value.descriptor.genesis.outpointIndex = 13;
    }],
    ['state NFT category wire bytes', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.outputs[0].token.category = new Uint8Array(32); },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['exact 128-byte initial state commitment', (value) => {
      value.descriptor.initialState = `00${value.descriptor.initialState.slice(2)}`;
    }],
    ['verifier lock', (value) => {
      value.settlementPins.verifierCarriers[4].lockingBytecode[0] ^= 1;
    }],
    ['verifier base', (value) => {
      value.settlementPins.verifierCarriers[7].baseValueSats = '1201';
    }],
    ['binding lock', (value) => {
      value.settlementPins.bindingLockingBytecode[0] ^= 1;
    }],
    ['binding base', (value) => {
      value.settlementPins.bindingBaseSats = '1201';
    }],
    ['state lock', (value) => {
      value.settlementPins.stateLockingBytecode[0] ^= 1;
    }],
    ['state base', (value) => {
      value.settlementPins.stateBaseSats = '2501';
    }],
    ['topology', (value) => {
      value.settlementPins.topologyId = 'pf11-exact-msm-oracle-v1';
    }],
    ['missing state output', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.outputs.splice(0, 1); },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['extra token', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => {
          transaction.outputs[12].token = structuredClone(transaction.outputs[0].token);
        },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['minted token amount', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.outputs[0].token.amount = 1n; },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['funding/change P2PKH lock', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.outputs[12].lockingBytecode[0] ^= 1; },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['exact one-sat-per-byte fee and change', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.outputs[12].valueSatoshis -= 1n; },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
    ['canonical 100-byte funding unlock', (value) => {
      value.rawGenesisTransaction = mutateTransactionBytes(
        value.rawGenesisTransaction,
        (transaction) => { transaction.inputs[0].unlockingBytecode = Buffer.alloc(99); },
      );
      refreshPackagedGenesisTransactionId(value);
    }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, () => {
      const value = input();
      mutate(value);
      assert.throws(() => inspect(value));
    });
  }
});

test('caller-supplied or forged runtime locks cannot reach a signing request', () => {
  const intent = fixture();
  rejectsCode(
    () => prepareV2Genesis(intent),
    'GENESIS_RUNTIME_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis(intent, { ...runtime }),
    'GENESIS_RUNTIME_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis(intent, {
      ...runtime,
      finalLocks: {
        verifiers: Array(10).fill({ lockingBytecodeHex: '51' }),
      },
    }),
    'GENESIS_RUNTIME_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis({ ...intent, finalLocks: {} }, runtime),
    'GENESIS_INPUT_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis(intent, tinyRuntime),
    'GENESIS_RUNTIME_MISMATCH',
  );
});

test('V2 genesis rejects mutated signatures, envelopes, sources, and value', () => {
  const intent = fixture();
  const prepared = prepareV2Genesis(intent, runtime);
  const badSignature = signature(prepared);
  badSignature[0] ^= 1;
  rejectsCode(
    () => finalizeV2Genesis(prepared, badSignature, runtime),
    'GENESIS_SIGNATURE_INVALID',
  );
  rejectsCode(
    () => finalizeV2Genesis(
      { ...prepared, payload: '{}' },
      signature(prepared),
      runtime,
    ),
    'GENESIS_PREPARED_MUTATED',
  );
  rejectsCode(
    () => finalizeV2Genesis(
      { ...prepared, unsignedTransactionHex: '00' },
      signature(prepared),
      runtime,
    ),
    'GENESIS_PREPARED_MUTATED',
  );
  rejectsCode(
    () => finalizeV2Genesis({
      ...prepared,
      signingRequest: {
        ...prepared.signingRequest,
        digestHex: '00'.repeat(32),
      },
    }, signature(prepared), runtime),
    'GENESIS_PREPARED_MUTATED',
  );
  rejectsCode(
    () => finalizeV2Genesis(prepared, signature(prepared), { ...runtime }),
    'GENESIS_RUNTIME_INVALID',
  );

  const tokenedSource = sourceTransaction({
    outputZero: {
      valueSatoshis: 80_000n,
      lockingBytecode: p2pkhLock(),
      token: {
        category: new Uint8Array(32).fill(1),
        amount: 1n,
      },
    },
  });
  rejectsCode(
    () => prepareV2Genesis(
      fixture({ sourceTransactionHex: tokenedSource }),
      runtime,
    ),
    'GENESIS_SOURCE_INVALID',
  );
  const otherKey = Buffer.from(secp256k1.derivePublicKeyCompressed(
    Buffer.from(`${'00'.repeat(31)}02`, 'hex'),
  ));
  const wrongKeySource = sourceTransaction({
    outputZero: {
      valueSatoshis: 80_000n,
      lockingBytecode: p2pkhLock(otherKey),
    },
  });
  rejectsCode(
    () => prepareV2Genesis(
      fixture({ sourceTransactionHex: wrongKeySource }),
      runtime,
    ),
    'GENESIS_SOURCE_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis(
      fixture({ sourceTransactionHex: tinySourceTransactionHex }),
      tinyRuntime,
    ),
    'GENESIS_INSUFFICIENT_FUNDING',
  );
});

test('runtime pins, profile, capacity, and unknown fields fail closed', async () => {
  const intent = fixture();
  const wrongCore = {
    ...core,
    proof: {
      ...core.proof,
      r1csSha256: '00'.repeat(32),
    },
  };
  await rejectsCodeAsync(
    () => createV2GenesisRuntime({
      repositoryRoot,
      temporaryRoot,
      profileCore: wrongCore,
      proofArtifacts,
      instanceId: defaultInstanceId,
    }),
    'GENESIS_RUNTIME_INVALID',
  );
  await rejectsCodeAsync(
    () => createV2GenesisRuntime({
      repositoryRoot,
      temporaryRoot,
      profileCore: core,
      proofArtifacts,
      instanceId: defaultInstanceId,
      unexpected: true,
    }),
    'GENESIS_INPUT_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis({
      ...intent,
      profileCore: {
        ...intent.profileCore,
        network: { id: 1, name: 'mainnet' },
      },
    }, runtime),
    'GENESIS_INPUT_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis({ ...intent, maximumLiveNotes: '0' }, runtime),
    'GENESIS_INPUT_INVALID',
  );
  rejectsCode(
    () => prepareV2Genesis({ ...intent, unexpected: true }, runtime),
    'GENESIS_INPUT_INVALID',
  );
});
