import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodeCashAddress } from '@bitauth/libauth';

import {
  deriveV2ChipnetFundingWallet,
} from './funding-wallet.mjs';
import { decodeDirectV2Address } from '../../action/v2/address.mjs';
import {
  deriveDirectV2BindingP2sh32Lock,
} from '../../action/v2/binding-unlock.mjs';
import { constructDirectV2Output } from '../../action/v2/notes.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  directV2VerifierTopologyById,
} from '../../action/v2/topology.mjs';
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  V2_PROFILE_DOMAINS,
} from '../../profile/v2/profile-core.mjs';
import {
  descriptorAttestationBytes,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../../unlock-builder/v2/structural-covenants.mjs';
import {
  executeV2Cli,
  formatV2ShieldAddress,
  parseV2CliArguments,
  V2_DIRECT_CARRIER_COUNT,
  V2CliError,
  v2CliErrorResult,
} from './cli.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const repeatedHash = (nibble) => nibble.repeat(64);
const RUNTIME_MATERIALS_SHA256 = Buffer.from('a5'.repeat(32), 'hex');
const RUNTIME_MATERIALS_SHA256_HEX = RUNTIME_MATERIALS_SHA256.toString('hex');
const TEST_TMP_ROOT = path.resolve(process.cwd(), '.tmp');

async function createTestRoot(prefix) {
  await mkdir(TEST_TMP_ROOT, { recursive: true, mode: 0o700 });
  return mkdtemp(path.join(TEST_TMP_ROOT, prefix));
}

// This is deliberately a complete, canonical Chipnet-only configuration. The
// CLI must never accept an unpinned URL, a TLS downgrade, or redirects merely
// because a test fixture happens not to make a network request.
function pinnedChipnetChainConfig() {
  return {
    schema: 'shieldkit-v2-cli-chain-v1',
    protocol: 'v2-direct',
    network: 'chipnet',
    endpoint: {
      url: 'https://node.example.com/rpc',
      network: 'chipnet',
      tls: {
        certificateSha256: 'ab'.repeat(32),
        minVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        serverName: 'node.example.com',
      },
      allowRedirects: false,
    },
    confirmationDepth: 6,
    requestTimeoutMs: 15_000,
  };
}

const u32le = (value) => {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32LE(value);
  return encoded;
};
const u64le = (value) => {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64LE(BigInt(value));
  return encoded;
};
function compactSize(value) {
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = 0xfd;
    encoded.writeUInt16LE(value, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(5);
  encoded[0] = 0xfe;
  encoded.writeUInt32LE(value, 1);
  return encoded;
}
function serializedOutput(valueSats, contents) {
  return Buffer.concat([
    u64le(valueSats),
    compactSize(contents.length),
    contents,
  ]);
}
function buildRawGenesis({
  bases,
  instanceId,
  initialState,
  stateLock,
  verifierLocks,
  bindingLock,
}) {
  const instance = Buffer.from(instanceId, 'hex');
  const stateTokenPrefix = Buffer.concat([
    Buffer.from([0xef]),
    instance,
    Buffer.from([0x61, 0x80]),
    Buffer.from(initialState, 'hex'),
  ]);
  const inputUnlock = Buffer.from([0x51]);
  const input = Buffer.concat([
    instance,
    u32le(7),
    compactSize(inputUnlock.length),
    inputUnlock,
    u32le(0xffff_ffff),
  ]);
  const p2pkh = Buffer.from([
    0x76, 0xa9, 0x14, ...Array(20).fill(0x20), 0x88, 0xac,
  ]);
  const outputs = [
    serializedOutput(bases.state, Buffer.concat([stateTokenPrefix, stateLock])),
    ...verifierLocks.map((lock, index) =>
      serializedOutput(bases.verifiers[index], lock)),
    serializedOutput(bases.binding, bindingLock),
    serializedOutput(7_000, p2pkh),
  ];
  const raw = Buffer.concat([
    u32le(2),
    compactSize(1),
    input,
    compactSize(outputs.length),
    ...outputs,
    u32le(0),
  ]);
  const transactionId = Buffer.from(
    createHash('sha256')
      .update(createHash('sha256').update(raw).digest())
      .digest(),
  ).reverse().toString('hex');
  return { raw, transactionId };
}

function profileCore() {
  return {
    schema: 'shieldkit-profile-core-v2-direct',
    network: { id: 2, name: 'chipnet' },
    denominationSats: '10000000',
    proof: {
      system: 'groth16',
      curve: 'bn254',
      relationId: 'shieldkit-pool-action-v2-direct',
      relationSha256: repeatedHash('1'),
      r1csSha256: repeatedHash('2'),
      verificationKeySha256: repeatedHash('3'),
      witnessWasmSha256: repeatedHash('4'),
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
      { id: 'carrier-base', sha256: repeatedHash('5') },
      { id: 'state-base', sha256: repeatedHash('6') },
    ],
    toolchain: [
      {
        name: 'circom',
        version: '2.2.3',
        sha256: repeatedHash('7'),
      },
      {
        name: 'snarkjs',
        version: '0.7.6',
        sha256: repeatedHash('8'),
      },
    ],
  };
}

async function createPinnedPoolFiles(
  root,
  {
    topologyId = DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  } = {},
) {
  const instanceDirectory = path.join(root, 'instance');
  await mkdir(path.join(instanceDirectory, 'locks'), {
    recursive: true,
    mode: 0o700,
  });
  await mkdir(path.join(instanceDirectory, 'profile'), {
    recursive: true,
    mode: 0o700,
  });
  const core = profileCore();
  const profileBaseArtifacts = [
    ['carrier-base', 'profile/carrier-base.bin', Buffer.from('carrier base')],
    ['state-base', 'profile/state-base.bin', Buffer.from('state base')],
  ];
  core.baseVerifierArtifacts = profileBaseArtifacts.map(([id, _path, bytes]) => ({
    id,
    sha256: sha256(bytes),
  }));
  const profileId = deriveProfileId(core);
  const profileCoreBytes = Buffer.from(canonicalizeJcs(core), 'utf8');
  const instanceId = 'ab'.repeat(32);
  const topology = directV2VerifierTopologyById(topologyId);
  const model = createDirectV2PoolModel({
    profileId,
    maximumLiveNotes: '32',
    denominationSats: core.denominationSats,
  });
  const initialState = encodeStateNftCommitment(
    model.state,
    { denominationSats: core.denominationSats },
  ).toString('hex');
  const bindingRedeem = Buffer.from([0x51]);
  const bindingLock =
    deriveDirectV2BindingP2sh32Lock(bindingRedeem);
  const verifierArtifacts = topology.verifierRoles.map(
    (role, index) => [
      `verifier-${role}-lock`,
      `locks/verifier-${role}.bin`,
      Buffer.from([0x51 + index, 0x75, 0x51]),
    ],
  );
  const verifierBases = verifierArtifacts.map((entry) =>
    deriveV2RollingBaseSats({ lockingBytecode: entry[2] }));
  const bindingBase = deriveV2RollingBaseSats({
    lockingBytecode: bindingLock,
  });
  // The state output's serialized size does not depend on its fixed-width
  // satoshi amount. Construct once with the minimum then derive and use the
  // exact state base in the final structural helper/lock fixed point.
  const stateHelper = Buffer.from(buildDirectV2StateHelper({
    bindingLock,
    verifierLocks: verifierArtifacts.map((entry) => entry[2]),
    verifierBaseValues: verifierBases,
    bindingBaseValueSats: bindingBase,
    stateBaseValueSats: '1000',
    denominationSats: core.denominationSats,
    stateCategory: instanceId,
    minimumChangeSats: '546',
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  const provisionalStateLock = Buffer.from(buildDirectV2StateTrampolineLock({
    helper: stateHelper,
    bindingLock,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  const stateBase = deriveV2RollingBaseSats({
    lockingBytecode: provisionalStateLock,
    token: {
      category: Buffer.from(instanceId, 'hex'),
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: Buffer.from(initialState, 'hex'),
      },
    },
  });
  const exactStateHelper = Buffer.from(buildDirectV2StateHelper({
    bindingLock,
    verifierLocks: verifierArtifacts.map((entry) => entry[2]),
    verifierBaseValues: verifierBases,
    bindingBaseValueSats: bindingBase,
    stateBaseValueSats: stateBase,
    denominationSats: core.denominationSats,
    stateCategory: instanceId,
    minimumChangeSats: '546',
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  const stateHelperUnlock = Buffer.from(
    buildDirectV2StateTrampolineUnlock(exactStateHelper),
  );
  const stateLock = Buffer.from(buildDirectV2StateTrampolineLock({
    helper: exactStateHelper,
    bindingLock,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  assert.equal(
    deriveV2RollingBaseSats({
      lockingBytecode: stateLock,
      token: {
        category: Buffer.from(instanceId, 'hex'),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Buffer.from(initialState, 'hex'),
        },
      },
    }),
    stateBase,
  );
  const artifacts = [
    ['binding-lock', 'locks/binding.bin', bindingLock],
    ['binding-redeem', 'locks/binding-redeem.bin', bindingRedeem],
    ['state-helper', 'locks/state-helper.bin', exactStateHelper],
    ['state-helper-unlock', 'locks/state-helper-unlock.bin', stateHelperUnlock],
    ['state-lock', 'locks/state.bin', stateLock],
    ['verification-key', 'locks/vk.bin', Buffer.from('verification key')],
    ['profile-core', 'profile-core.json', profileCoreBytes],
    ...profileBaseArtifacts,
    ...verifierArtifacts,
  ].sort(([left], [right]) => left.localeCompare(right));
  for (const [, relative, bytes] of artifacts) {
    await writeFile(path.join(instanceDirectory, relative), bytes);
  }
  const manifest = {
    schema: 'shieldkit-artifact-manifest-v2-direct',
    profileId,
    instanceId,
    artifacts: artifacts.map(([id, relative, bytes]) => ({
      id,
      path: relative,
      sha256: sha256(bytes),
    })),
  };
  const manifestBytes = Buffer.from(canonicalizeJcs(manifest), 'utf8');
  await writeFile(path.join(instanceDirectory, 'manifest.json'), manifestBytes);
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const genesis = buildRawGenesis({
    bases: {
      binding: bindingBase,
      state: stateBase,
      verifiers: verifierBases,
    },
    instanceId,
    initialState,
    stateLock,
    verifierLocks: verifierArtifacts.map((entry) => entry[2]),
    bindingLock,
  });
  const descriptor = {
    schema: 'shieldkit-instance-descriptor-v2-direct',
    profileId,
    instanceId,
    stateNftCategory: instanceId,
    genesis: {
      transactionId: genesis.transactionId,
      outpointIndex: 0,
    },
    initialState,
    manifest: {
      path: 'manifest.json',
      sha256: sha256(manifestBytes),
    },
    finalLocks: {
      topologyId: topology.id,
      verifiers: topology.verifierRoles.map((role, index) => ({
        role,
        lockingArtifactId: `verifier-${role}-lock`,
        baseSats: verifierBases[index].toString(),
      })),
      binding: {
        lockingArtifactId: 'binding-lock',
        redeemArtifactId: 'binding-redeem',
        baseSats: bindingBase.toString(),
      },
      state: {
        lockingArtifactId: 'state-lock',
        helperArtifactId: 'state-helper',
        helperUnlockArtifactId: 'state-helper-unlock',
        baseSats: stateBase.toString(),
      },
    },
    signature: {
      algorithm: 'ed25519',
      attestationDomain: 'shieldkit-instance-descriptor-attestation',
      attestationVersion: 1,
      signerId: 'release-signer',
      publicKey,
      signature: '',
    },
  };
  descriptor.signature.signature = sign(
    null,
    descriptorAttestationBytes({
      descriptor,
      canonicalManifestBytes: manifestBytes,
      signature: descriptor.signature,
    }),
    pair.privateKey,
  ).toString('base64');
  const profileCorePath = path.join(instanceDirectory, 'profile-core.json');
  const descriptorPath = path.join(instanceDirectory, 'instance.json');
  const chainConfigPath = path.join(instanceDirectory, 'chain.json');
  const trustedSignersPath = path.join(
    instanceDirectory,
    'trusted-signers.json',
  );
  const chainConfig = pinnedChipnetChainConfig();
  await writeFile(profileCorePath, profileCoreBytes);
  await writeFile(descriptorPath, canonicalizeJcs(descriptor));
  await writeFile(chainConfigPath, canonicalizeJcs(chainConfig));
  await writeFile(
    trustedSignersPath,
    canonicalizeJcs([{ signerId: 'release-signer', publicKey }]),
  );
  return {
    core,
    chainConfig,
    chainConfigPath,
    descriptor,
    descriptorPath,
    genesisRaw: genesis.raw.toString('hex'),
    initialState,
    instanceId,
    profileId,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256_HEX,
    topology,
    trustedSignersPath,
  };
}

async function setupPool(t, options = undefined) {
  const root = await createTestRoot('shieldkit-v2-cli-test-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const pool = await createPinnedPoolFiles(root, options);
  const dataDirectory = path.join(root, 'state');
  const args = [
    'pool',
    'add',
    pool.descriptorPath,
    '--protocol',
    'v2-direct',
    '--data-dir',
    dataDirectory,
    '--trusted-signers',
    pool.trustedSignersPath,
  ];
  const result = await executeV2Cli(args, {
    cwd: root,
    dependencies: {
      resolveRuntimeMaterialsSha256: async () =>
        Buffer.from(RUNTIME_MATERIALS_SHA256),
    },
  });
  return { root, dataDirectory, pool, result };
}

async function createWallet(subject) {
  return executeV2Cli([
    'wallet',
    'create',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], { cwd: subject.root });
}

test('strictly parses only the stated V2 command shapes and options', () => {
  assert.equal(V2_DIRECT_CARRIER_COUNT, 10);
  assert.deepEqual(
    parseV2CliArguments([
      'transfer',
      '--note',
      'note-7',
      '--to',
      `shieldkit-v2:${'00'.repeat(168)}`,
      '--broadcast',
      '--protocol',
      'v2-direct',
    ]),
    {
      command: 'transfer',
      options: {
        note: 'note-7',
        to: `shieldkit-v2:${'00'.repeat(168)}`,
        broadcast: true,
        protocol: 'v2-direct',
      },
      descriptor: undefined,
      operationId: undefined,
    },
  );
  const operationId = `v2op:${'a'.repeat(64)}`;
  const operationShapes = [
    ['abandon', ['--reason', 'operator cancelled'], {
      reason: 'operator cancelled', protocol: 'v2-direct',
    }],
    ['confirm', [], { protocol: 'v2-direct' }],
    ['rebase', [], { protocol: 'v2-direct' }],
    ['rebroadcast', [
      '--broadcast',
      '--acknowledgement', 'resubmit-exact-persisted-transaction',
      '--attempt-token', 'attempt-token-from-delivery-journal',
    ], {
      broadcast: true,
      acknowledgement: 'resubmit-exact-persisted-transaction',
      'attempt-token': 'attempt-token-from-delivery-journal',
      protocol: 'v2-direct',
    }],
    ['reconcile', [], { protocol: 'v2-direct' }],
    ['resume', ['--broadcast'], { broadcast: true, protocol: 'v2-direct' }],
  ];
  for (const [subcommand, options, expectedOptions] of operationShapes) {
    assert.deepEqual(
      parseV2CliArguments([
        'operation', subcommand, operationId, ...options,
        '--protocol', 'v2-direct',
      ]),
      {
        command: `operation.${subcommand}`,
        options: expectedOptions,
        descriptor: undefined,
        operationId,
      },
      subcommand,
    );
  }
  assert.throws(
    () => parseV2CliArguments(['operation', 'reconcile', 'not-an-operation']),
    (error) => error instanceof V2CliError
      && error.code === 'INVALID_OPERATION_ID',
  );
  assert.throws(
    () => parseV2CliArguments([
      'operation', 'reconcile', operationId, '--broadcast',
    ]),
    (error) => error instanceof V2CliError
      && error.code === 'OPTION_NOT_ALLOWED',
  );
  assert.throws(
    () => parseV2CliArguments(['wallet', 'erase']),
    (error) => error instanceof V2CliError && error.code === 'CLI_USAGE',
  );
  assert.throws(
    () => parseV2CliArguments(['status', '--rpc', 'https://example.invalid']),
    (error) => error instanceof V2CliError && error.code === 'UNKNOWN_OPTION',
  );
  assert.throws(
    () => parseV2CliArguments([
      'status',
      '--protocol',
      'v2-direct',
      '--protocol',
      'v2-direct',
    ]),
    (error) => error instanceof V2CliError
      && error.code === 'DUPLICATE_OPTION',
  );
});

test('rejects invalid operation recovery invocations before local state, network, or injected dependencies', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-operation-input-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const dataDirectory = path.join(root, 'state');
  const operationId = `v2op:${'e'.repeat(64)}`;
  const calls = [];
  const unavailable = (name) => () => {
    calls.push(name);
    throw new Error(`${name} must not be invoked for invalid operation input`);
  };
  const dependencies = {
    createActionLifecycle: unavailable('createActionLifecycle'),
    createBroadcastTransport: unavailable('createBroadcastTransport'),
    createCanonicalSynchronizer: unavailable('createCanonicalSynchronizer'),
    createChainClient: unavailable('createChainClient'),
    createPrivateActionStore: unavailable('createPrivateActionStore'),
    createSecretFile: unavailable('createSecretFile'),
    deriveRecoveryScanner: unavailable('deriveRecoveryScanner'),
    loadChainConfig: unavailable('loadChainConfig'),
    loadDescriptor: unavailable('loadDescriptor'),
    openDeliveryJournal: unavailable('openDeliveryJournal'),
    openStore: unavailable('openStore'),
    resolveRuntimeMaterialsSha256: unavailable('resolveRuntimeMaterialsSha256'),
  };
  const cases = [
    {
      argv: ['operation', 'abandon', operationId, '--reason', ''],
      code: 'ABANDON_REASON_INVALID',
    },
    {
      argv: ['operation', 'rebroadcast', operationId],
      code: 'BROADCAST_FLAG_REQUIRED',
    },
    {
      argv: [
        'operation', 'rebroadcast', operationId, '--broadcast',
        '--acknowledgement', 'resubmit-a-different-transaction',
        '--attempt-token', 'durable-attempt-token',
      ],
      code: 'EXACT_RESUBMISSION_ACKNOWLEDGEMENT_REQUIRED',
    },
    {
      argv: [
        'operation', 'rebroadcast', operationId, '--broadcast',
        '--acknowledgement', 'resubmit-exact-persisted-transaction',
      ],
      code: 'DELIVERY_ATTEMPT_TOKEN_REQUIRED',
    },
  ];
  for (const { argv, code } of cases) {
    await assert.rejects(
      executeV2Cli([
        ...argv,
        '--protocol', 'v2-direct',
        '--data-dir', dataDirectory,
      ], { cwd: root, dependencies }),
      (error) => error instanceof V2CliError && error.code === code,
      code,
    );
    assert.deepEqual(calls, [], `${code} invoked a dependency`);
    await assert.rejects(access(dataDirectory), `${code} created local state`);
  }
});

test('rejects every prohibited V2 topology switch before filesystem, network, or prover I/O', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-prohibited-switch-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const dataDirectory = path.join(root, 'must-not-exist');
  const calls = [];
  const unavailable = (name) => () => {
    calls.push(name);
    throw new Error(`${name} must not be invoked for a prohibited V2 switch`);
  };
  // This is the dispatcher dependency boundary for local state, chain, proof,
  // and broadcast work. The parser must reject every switch below before it
  // reaches any one of these capabilities.
  const dependencies = Object.freeze({
    authenticateRecoveryStream: unavailable('authenticateRecoveryStream'),
    createActionLifecycle: unavailable('createActionLifecycle'),
    createBroadcastTransport: unavailable('createBroadcastTransport'),
    createCanonicalSynchronizer: unavailable('createCanonicalSynchronizer'),
    createChainClient: unavailable('createChainClient'),
    createPrivateActionStore: unavailable('createPrivateActionStore'),
    createSecretFile: unavailable('createSecretFile'),
    deriveRecoveryScanner: unavailable('deriveRecoveryScanner'),
    loadChainConfig: unavailable('loadChainConfig'),
    loadDescriptor: unavailable('loadDescriptor'),
    openDeliveryJournal: unavailable('openDeliveryJournal'),
    openStore: unavailable('openStore'),
    randomBytes: unavailable('randomBytes'),
    resolveRuntimeMaterialsSha256: unavailable('resolveRuntimeMaterialsSha256'),
    scanRecoveryStream: unavailable('scanRecoveryStream'),
  });
  const prohibitedSwitches = [
    ['batching', '--batch'],
    ['batching', '--batching'],
    ['batching', '--batch-size'],
    ['batcher', '--batcher'],
    ['batcher', '--batcher-url'],
    ['coordinator', '--coordinator'],
    ['coordinator', '--coordinator-url'],
    ['sponsor', '--sponsor'],
    ['sponsor', '--sponsor-url'],
    ['faucet', '--faucet'],
    ['faucet', '--faucet-url'],
    ['remote prover', '--remote-prover'],
    ['remote prover', '--prover'],
    ['remote prover', '--prover-url'],
    ['preparation transaction', '--preparation'],
    ['preparation transaction', '--prepare'],
    ['preparation transaction', '--preparation-transaction'],
    ['preparation transaction', '--prep-transaction'],
    ['root-history accumulator', '--root-history'],
    ['root-history accumulator', '--root-history-accumulator'],
    ['root-history accumulator', '--history-accumulator'],
    ['fee credit', '--fee-credit'],
    ['fee credit', '--fee-credits'],
    ['fee ticket', '--fee-ticket'],
    ['fee ticket', '--fee-tickets'],
  ];
  for (const [topology, forbiddenSwitch] of prohibitedSwitches) {
    const argv = [
      'status',
      forbiddenSwitch,
      'must-never-be-consumed',
      '--protocol',
      'v2-direct',
      '--data-dir',
      dataDirectory,
    ];
    assert.throws(
      () => parseV2CliArguments(argv),
      (error) => error instanceof V2CliError
        && error.code === 'UNKNOWN_OPTION'
        && error.message === `unknown V2 CLI option: ${forbiddenSwitch}`,
      `${topology}: parser must reject ${forbiddenSwitch}`,
    );
    await assert.rejects(
      executeV2Cli(argv, { cwd: root, dependencies }),
      (error) => error instanceof V2CliError
        && error.code === 'UNKNOWN_OPTION'
        && error.message === `unknown V2 CLI option: ${forbiddenSwitch}`,
      `${topology}: dispatcher must reject ${forbiddenSwitch}`,
    );
    assert.deepEqual(calls, [], `${forbiddenSwitch} invoked an I/O dependency`);
    await assert.rejects(
      access(dataDirectory),
      `${forbiddenSwitch} created or touched local V2 state`,
    );
  }
});

test('does not activate V2 by default or create state during read-only status', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-empty-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const dataDirectory = path.join(root, 'does-not-exist');
  await assert.rejects(
    executeV2Cli(['status', '--data-dir', dataDirectory], { cwd: root }),
    (error) => error instanceof V2CliError
      && error.code === 'V2_DEFAULT_NOT_QUALIFIED',
  );
  await assert.rejects(access(dataDirectory));
  const status = await executeV2Cli([
    'status',
    '--protocol',
    'v2-direct',
    '--data-dir',
    dataDirectory,
  ], { cwd: root });
  assert.equal(status.configured, false);
  assert.equal(status.networkActivity, false);
  await assert.rejects(access(dataDirectory));
});

test('refuses symlinked or group-accessible local state directories', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-path-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const actual = path.join(root, 'actual');
  const linked = path.join(root, 'linked');
  await mkdir(actual, { mode: 0o700 });
  await symlink(actual, linked);
  await assert.rejects(
    executeV2Cli([
      'status',
      '--protocol',
      'v2-direct',
      '--data-dir',
      linked,
    ], { cwd: root }),
    (error) => error instanceof V2CliError
      && error.code === 'DATA_DIRECTORY_UNTRUSTED',
  );
  await chmod(actual, 0o750);
  await assert.rejects(
    executeV2Cli([
      'status',
      '--protocol',
      'v2-direct',
      '--data-dir',
      actual,
    ], { cwd: root }),
    (error) => error instanceof V2CliError
      && error.code === 'DATA_DIRECTORY_PERMISSIONS',
  );
});

test('refuses a group- or world-writable data-directory ancestor', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-writable-ancestor-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  for (const [name, mode] of [
    ['group', 0o720],
    ['world', 0o702],
  ]) {
    const ancestor = path.join(root, name);
    const dataDirectory = path.join(ancestor, 'state');
    await mkdir(ancestor, { mode: 0o700 });
    await chmod(ancestor, mode);
    await assert.rejects(
      executeV2Cli([
        'status',
        '--protocol', 'v2-direct',
        '--data-dir', dataDirectory,
      ], { cwd: root }),
      (error) => error instanceof V2CliError
        && error.code === 'DATA_DIRECTORY_UNTRUSTED',
      name,
    );
    await assert.rejects(access(dataDirectory), `${name} ancestor created state`);
  }
});

test('adds only a fully pinned descriptor and persists a private immutable binding', async (t) => {
  const subject = await setupPool(t);
  assert.equal(subject.result.descriptorPinsValidated, true);
  assert.equal(subject.result.descriptorSignatureValidated, true);
  assert.equal(subject.result.pool.carrierCount, 10);
  assert.equal(subject.result.pool.profileId, subject.pool.profileId);
  assert.equal(subject.result.qualification, 'blocked');
  const state = await lstat(path.join(subject.dataDirectory, 'pool.json'));
  assert.equal(state.mode & 0o777, 0o600);
  const stored = JSON.parse(
    await readFile(path.join(subject.dataDirectory, 'pool.json'), 'utf8'),
  );
  assert.equal(stored.schema, 'shieldkit-v2-cli-pool-v4');
  assert.equal(stored.runtimeMaterialsSha256, RUNTIME_MATERIALS_SHA256_HEX);
  assert.deepEqual(stored.chainConfig, subject.pool.chainConfig);
  assert.equal(stored.chainConfig.endpoint.url, 'https://node.example.com/rpc');
  assert.equal(stored.chainConfig.endpoint.network, 'chipnet');
  assert.equal(stored.chainConfig.endpoint.allowRedirects, false);
  assert.equal(stored.chainConfig.endpoint.tls.rejectUnauthorized, true);
  assert.equal(stored.chainConfig.endpoint.tls.minVersion, 'TLSv1.3');
  assert.equal(
    stored.chainConfig.endpoint.tls.certificateSha256,
    'ab'.repeat(32),
  );
  assert.equal(
    stored.descriptor.attestation.signerId,
    'release-signer',
  );
  assert.equal(
    stored.descriptor.attestation.publicKey,
    subject.pool.descriptor.signature.publicKey,
  );
  assert.equal(
    stored.descriptor.attestation.publicKeySha256,
    sha256(Buffer.from(subject.pool.descriptor.signature.publicKey, 'utf8')),
  );
  assert.deepEqual(
    stored.descriptor.settlementArtifacts.verifiers.map(({ role }) => role),
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  );
  assert.equal(
    stored.descriptor.settlementArtifacts.binding.locking.bytesHex,
    deriveDirectV2BindingP2sh32Lock(Buffer.from([0x51])).toString('hex'),
  );
  assert.equal(
    stored.descriptor.settlementArtifacts.binding.redeem.bytesHex,
    '51',
  );
  assert.equal(
    stored.descriptor.settlementArtifacts.state.helper.artifactId,
    'state-helper',
  );
  assert.equal(
    stored.descriptor.settlementArtifacts.state.helperUnlock.artifactId,
    'state-helper-unlock',
  );
  await assert.rejects(
    executeV2Cli([
      'pool',
      'add',
      subject.pool.descriptorPath,
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
      '--trusted-signers',
      subject.pool.trustedSignersPath,
    ], {
      cwd: subject.root,
      dependencies: {
        resolveRuntimeMaterialsSha256: async () =>
          Buffer.from(RUNTIME_MATERIALS_SHA256),
      },
    }),
    (error) => error instanceof V2CliError
      && error.code === 'POOL_ALREADY_CONFIGURED',
  );
});

test('pool add derives PF10 carrier count and roles only from the signed descriptor', async (t) => {
  const subject = await setupPool(t, {
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  });
  assert.equal(subject.result.pool.carrierCount, 10);
  const stored = JSON.parse(
    await readFile(path.join(subject.dataDirectory, 'pool.json'), 'utf8'),
  );
  assert.equal(stored.carrierCount, 10);
  assert.equal(
    stored.descriptor.settlementArtifacts.topologyId,
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  );
  assert.deepEqual(
    stored.descriptor.settlementArtifacts.verifiers.map(({ role }) => role),
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  );
});

test('pool add requires trusted signers and rejects an unsigned descriptor', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-signature-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const pool = await createPinnedPoolFiles(root);
  const dataDirectory = path.join(root, 'state');
  await assert.rejects(
    executeV2Cli([
      'pool',
      'add',
      pool.descriptorPath,
      '--protocol',
      'v2-direct',
      '--data-dir',
      dataDirectory,
    ], { cwd: root }),
    (error) => error instanceof V2CliError
      && error.code === 'TRUSTED_SIGNERS_REQUIRED',
  );
  pool.descriptor.signature = null;
  await writeFile(
    pool.descriptorPath,
    canonicalizeJcs(pool.descriptor),
  );
  await assert.rejects(
    executeV2Cli([
      'pool',
      'add',
      pool.descriptorPath,
      '--protocol',
      'v2-direct',
      '--data-dir',
      dataDirectory,
      '--trusted-signers',
      pool.trustedSignersPath,
    ], { cwd: root }),
    (error) => error instanceof V2CliError
      && error.code === 'INSTANCE_DESCRIPTOR_INVALID'
      && /signature is required/.test(error.message),
  );
  await assert.rejects(
    access(path.join(dataDirectory, 'pool.json')),
    /ENOENT/,
  );
});

test('pool add rejects failing or malformed PF10 runtime resolution and does not persist a pool', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-runtime-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const pool = await createPinnedPoolFiles(root);
  const base = [
    'pool', 'add', pool.descriptorPath,
    '--protocol', 'v2-direct',
    '--trusted-signers', pool.trustedSignersPath,
  ];
  const cases = [
    {
      name: 'resolver failure',
      resolveRuntimeMaterialsSha256: async () => {
        throw new Error('PF10 runtime resolution unavailable');
      },
    },
    {
      name: 'short digest',
      resolveRuntimeMaterialsSha256: async () => Buffer.alloc(31),
    },
  ];
  for (const [index, scenario] of cases.entries()) {
    const dataDirectory = path.join(root, `state-${index}`);
    await assert.rejects(
      executeV2Cli([
        ...base,
        '--data-dir', dataDirectory,
      ], {
        cwd: root,
        dependencies: {
          resolveRuntimeMaterialsSha256: scenario.resolveRuntimeMaterialsSha256,
        },
      }),
      (error) => error instanceof V2CliError
        && error.code === 'INSTANCE_DESCRIPTOR_INVALID',
      scenario.name,
    );
    await assert.rejects(access(path.join(dataDirectory, 'pool.json')));
  }
});

test('stored V4 pool binding rejects legacy schema and chain or signer drift', async (t) => {
  const subject = await setupPool(t);
  const filename = path.join(subject.dataDirectory, 'pool.json');
  const stored = JSON.parse(await readFile(filename, 'utf8'));
  const cases = [
    (value) => { delete value.runtimeMaterialsSha256; },
    (value) => { value.runtimeMaterialsSha256 = 'not-a-sha256'; },
    (value) => { value.schema = 'shieldkit-v2-cli-pool-v3'; },
    (value) => { delete value.chainConfig; },
    (value) => { value.chainConfig.endpoint.allowRedirects = true; },
    (value) => { value.chainConfig.endpoint.tls.rejectUnauthorized = false; },
    (value) => { value.chainConfig.endpoint.tls.certificateSha256 = '00'; },
    (value) => { value.chainConfig.network = 'mainnet'; },
    (value) => { value.descriptor.attestation.publicKeySha256 = '00'.repeat(32); },
  ];
  for (const mutate of cases) {
    const tampered = structuredClone(stored);
    mutate(tampered);
    await writeFile(filename, canonicalizeJcs(tampered));
    await assert.rejects(
      executeV2Cli([
        'status', '--protocol', 'v2-direct',
        '--data-dir', subject.dataDirectory,
      ], { cwd: subject.root }),
      (error) => error instanceof V2CliError
        && error.code === 'LOCAL_STATE_INVALID',
    );
  }
});

test('pool add requires a canonical sibling chain.json unless --chain-config supplies one', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-chain-config-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const pool = await createPinnedPoolFiles(root);
  const dataDirectory = path.join(root, 'state');
  await unlink(pool.chainConfigPath);
  const base = [
    'pool', 'add', pool.descriptorPath,
    '--protocol', 'v2-direct',
    '--data-dir', dataDirectory,
    '--trusted-signers', pool.trustedSignersPath,
  ];
  await assert.rejects(
    executeV2Cli(base, {
      cwd: root,
      dependencies: {
        resolveRuntimeMaterialsSha256: async () =>
          Buffer.from(RUNTIME_MATERIALS_SHA256),
      },
    }),
    (error) => error instanceof V2CliError
      && error.code === 'CHAIN_CONFIG_INVALID',
  );
  await assert.rejects(access(path.join(dataDirectory, 'pool.json')));

  const explicitConfig = path.join(root, 'pinned-chipnet.json');
  await writeFile(explicitConfig, canonicalizeJcs(pool.chainConfig));
  const configured = await executeV2Cli([
    ...base,
    '--chain-config', explicitConfig,
  ], {
    cwd: root,
    dependencies: {
      resolveRuntimeMaterialsSha256: async () =>
        Buffer.from(RUNTIME_MATERIALS_SHA256),
    },
  });
  assert.equal(configured.pool.network, 'chipnet');
  const stored = JSON.parse(
    await readFile(path.join(dataDirectory, 'pool.json'), 'utf8'),
  );
  assert.deepEqual(stored.chainConfig, pool.chainConfig);
});

test('PF11 semantic-oracle descriptors fail before an injected runtime resolver can make them operational', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-pf11-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const pool = await createPinnedPoolFiles(root, {
    topologyId: DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  });
  const dataDirectory = path.join(root, 'state');
  let runtimeResolverCalled = false;
  await assert.rejects(
    executeV2Cli([
      'pool', 'add', pool.descriptorPath,
      '--protocol', 'v2-direct',
      '--data-dir', dataDirectory,
      '--trusted-signers', pool.trustedSignersPath,
    ], {
      cwd: root,
      dependencies: {
        resolveRuntimeMaterialsSha256: async () => {
          runtimeResolverCalled = true;
          return Buffer.from(RUNTIME_MATERIALS_SHA256);
        },
      },
    }),
    (error) => error instanceof V2CliError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY'
      && /semantic correctness oracle only/.test(error.message),
  );
  assert.equal(runtimeResolverCalled, false);
  await assert.rejects(access(path.join(dataDirectory, 'pool.json')));
});

test('stored descriptor artifacts fail closed on hash or binding-pair drift', async (t) => {
  const subject = await setupPool(t);
  const filename = path.join(subject.dataDirectory, 'pool.json');
  const stored = JSON.parse(await readFile(filename, 'utf8'));
  const originalVerifierBytesHex =
    stored.descriptor.settlementArtifacts.verifiers[0]
      .locking.bytesHex;
  stored.descriptor.settlementArtifacts.verifiers[0]
    .locking.bytesHex = '52';
  await writeFile(filename, canonicalizeJcs(stored));
  await assert.rejects(
    executeV2Cli([
      'status',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'LOCAL_STATE_INVALID'
      && /SHA-256 pin mismatch/.test(error.message),
  );
  const restored = JSON.parse(
    await readFile(filename, 'utf8'),
  );
  restored.descriptor.settlementArtifacts.verifiers[0]
    .locking.bytesHex = originalVerifierBytesHex;
  const alternativeRedeem = Buffer.from([0x52, 0x75, 0x51]);
  restored.descriptor.settlementArtifacts.binding.redeem.bytesHex =
    alternativeRedeem.toString('hex');
  restored.descriptor.settlementArtifacts.binding.redeem.sha256 =
    sha256(alternativeRedeem);
  await writeFile(filename, canonicalizeJcs(restored));
  await assert.rejects(
    executeV2Cli([
      'status',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'LOCAL_STATE_INVALID'
      && /exact P2SH32 pair/.test(error.message),
  );
});

test('persists only exact dust-derived verifier, binding, and mutable-state bases', async (t) => {
  const subject = await setupPool(t);
  const filename = path.join(subject.dataDirectory, 'pool.json');
  const stored = JSON.parse(await readFile(filename, 'utf8'));
  const artifacts = stored.descriptor.settlementArtifacts;
  for (const verifier of artifacts.verifiers) {
    assert.equal(
      verifier.baseSats,
      deriveV2RollingBaseSats({
        lockingBytecode: Buffer.from(verifier.locking.bytesHex, 'hex'),
      }).toString(),
    );
  }
  assert.equal(
    artifacts.binding.baseSats,
    deriveV2RollingBaseSats({
      lockingBytecode: Buffer.from(artifacts.binding.locking.bytesHex, 'hex'),
    }).toString(),
  );
  assert.equal(
    artifacts.state.baseSats,
    deriveV2RollingBaseSats({
      lockingBytecode: Buffer.from(artifacts.state.locking.bytesHex, 'hex'),
      token: {
        category: Buffer.from(subject.pool.instanceId, 'hex'),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Buffer.from(subject.pool.initialState, 'hex'),
        },
      },
    }).toString(),
  );

  const mutations = [
    (value) => {
      value.descriptor.settlementArtifacts.verifiers[0].baseSats = (
        BigInt(value.descriptor.settlementArtifacts.verifiers[0].baseSats)
          + 100n
      ).toString();
    },
    (value) => {
      value.descriptor.settlementArtifacts.binding.baseSats = (
        BigInt(value.descriptor.settlementArtifacts.binding.baseSats) - 100n
      ).toString();
    },
    (value) => {
      value.descriptor.settlementArtifacts.state.baseSats = (
        BigInt(value.descriptor.settlementArtifacts.state.baseSats) + 100n
      ).toString();
    },
  ];
  for (const mutate of mutations) {
    const tampered = JSON.parse(JSON.stringify(stored));
    mutate(tampered);
    await writeFile(filename, canonicalizeJcs(tampered));
    await assert.rejects(
      executeV2Cli([
        'status',
        '--protocol',
        'v2-direct',
        '--data-dir',
        subject.dataDirectory,
      ], { cwd: subject.root }),
      (error) => error instanceof V2CliError
        && error.code === 'LOCAL_STATE_INVALID'
        && /exact dust-derived/.test(error.message),
    );
  }
});

test('creates a 0600 V2 wallet with self-funded Chipnet material and receives through an authenticated query', async (t) => {
  const subject = await setupPool(t);
  const scalarBytes = [3, 4, 5];
  const wallet = await executeV2Cli([
    'wallet',
    'create',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], {
    cwd: subject.root,
    dependencies: {
      randomBytes(length) {
        assert.equal(length, 32);
        const bytes = Buffer.alloc(32);
        bytes[31] = scalarBytes.shift();
        return bytes;
      },
    },
  });
  assert.match(wallet.shieldAddress, /^shieldkit-v2:[0-9a-f]{336}$/);
  assert.match(wallet.fundingAddress, /^bchtest:q[a-z0-9]+$/);
  assert.equal(wallet.secretFileMode, '0600');
  const walletPath = path.join(subject.dataDirectory, 'wallet.json');
  const metadata = await lstat(walletPath);
  assert.equal(metadata.mode & 0o077, 0);
  const persisted = JSON.parse(await readFile(walletPath, 'utf8'));
  assert.equal(persisted.schema, 'shieldkit-v2-cli-wallet-v3');
  assert.equal(persisted.protocol, 'v2-direct');
  assert.equal(persisted.fundingWallet.schema, 'shieldkit-v2-cli-funding-wallet-v1');
  assert.equal(persisted.fundingWallet.networkId, 2);
  assert.equal(persisted.fundingWallet.cashAddress, wallet.fundingAddress);
  assert.equal(persisted.fundingWallet.privateKeyHex, `${'0'.repeat(63)}5`);
  assert.deepEqual(persisted.changeWallets, []);
  const calls = [];
  const receive = await executeV2Cli([
    'wallet',
    'receive',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], {
    cwd: subject.root,
    dependencies: {
      createChainClient({ chainConfig }) {
        calls.push(['create-chain-client', chainConfig]);
        assert.deepEqual(chainConfig, subject.pool.chainConfig);
        assert.equal(chainConfig.endpoint.url, 'https://node.example.com/rpc');
        assert.equal(chainConfig.endpoint.network, 'chipnet');
        assert.equal(chainConfig.endpoint.allowRedirects, false);
        assert.equal(chainConfig.endpoint.tls.rejectUnauthorized, true);
        assert.equal(chainConfig.endpoint.tls.minVersion, 'TLSv1.3');
        assert.equal(chainConfig.endpoint.tls.certificateSha256, 'ab'.repeat(32));
        return Object.freeze({
          async queryWalletUtxos(request) {
            calls.push(['query-wallet-utxos', request]);
            assert.deepEqual(request, {
              cashAddress: wallet.fundingAddress,
              instanceId: subject.pool.descriptor.instanceId,
              lockingBytecodeHex: persisted.fundingWallet.lockingBytecodeHex,
            });
            return Object.freeze({
              canonicalTip: Object.freeze({
                actionSequence: 0,
                blockHash: '21'.repeat(32),
                confirmations: 6,
                height: 100,
                state: subject.pool.initialState,
                txid: subject.pool.descriptor.genesis.transactionId,
                vout: subject.pool.descriptor.genesis.outpointIndex,
              }),
              cashAddress: wallet.fundingAddress,
              lockingBytecodeHex:
                persisted.fundingWallet.lockingBytecodeHex,
              utxos: Object.freeze([
                Object.freeze({
                  txid: '31'.repeat(32),
                  vout: 0,
                  valueSats: '10000000',
                }),
                Object.freeze({
                  txid: '32'.repeat(32),
                  vout: 1,
                  valueSats: '100546',
                }),
              ]),
            });
          },
        });
      },
    },
  });
  assert.equal(receive.shieldAddress, wallet.shieldAddress);
  assert.deepEqual(receive.funding, {
    address: wallet.fundingAddress,
    observedBalanceSats: '10100546',
    observedUtxoCount: 2,
    watchedAddressCount: 1,
    observationStatus: 'authenticated-chipnet-query',
  });
  assert.deepEqual(receive.requiredUtxo, {
    denominationPrincipalSats: '10000000',
    guaranteedSufficientValueSats: '10100546',
    feeRateSatsPerByte: '1',
    changeDustFloorSats: '546',
    basis: '100000-byte hard-policy ceiling',
  });
  assert.equal(receive.observedBalanceSats, null);
  assert.equal(receive.observationStatus, 'not-synced');
  assert.equal(receive.networkActivity, true);
  assert.equal(calls.length, 2);
  assert.doesNotMatch(JSON.stringify(receive), /faucet/i);
  await assert.rejects(
    executeV2Cli([
      'wallet',
      'create',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'WALLET_ALREADY_EXISTS',
  );
});

test('public wallet create persists an exact 0600 V3 wallet file', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const filename = path.join(subject.dataDirectory, 'wallet.json');
  const metadata = await lstat(filename);
  assert.equal(metadata.mode & 0o777, 0o600);
  const persisted = JSON.parse(await readFile(filename, 'utf8'));
  assert.equal(persisted.schema, 'shieldkit-v2-cli-wallet-v3');
  assert.deepEqual(persisted.changeWallets, []);
});

test('public wallet receive rejects malformed and duplicate change wallets before network queries', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const filename = path.join(subject.dataDirectory, 'wallet.json');
  const base = JSON.parse(await readFile(filename, 'utf8'));
  const duplicateChangeWallet = deriveV2ChipnetFundingWallet({
    privateKeyHex: `${'0'.repeat(63)}6`,
  });
  const cases = [
    {
      name: 'malformed',
      changeWallets: [{
        operationId: `v2op:${'a'.repeat(64)}`,
        wallet: {},
      }],
    },
    {
      name: 'duplicate key',
      changeWallets: [
        {
          operationId: `v2op:${'b'.repeat(64)}`,
          wallet: duplicateChangeWallet,
        },
        {
          operationId: `v2op:${'c'.repeat(64)}`,
          wallet: duplicateChangeWallet,
        },
      ],
    },
  ];
  for (const scenario of cases) {
    await writeFile(filename, canonicalizeJcs({
      ...base,
      changeWallets: scenario.changeWallets,
    }));
    let clientCalls = 0;
    let queryCalls = 0;
    await assert.rejects(
      executeV2Cli([
        'wallet', 'receive', '--protocol', 'v2-direct',
        '--data-dir', subject.dataDirectory,
      ], {
        cwd: subject.root,
        dependencies: {
          createChainClient() {
            clientCalls += 1;
            return Object.freeze({
              async queryWalletUtxos() {
                queryCalls += 1;
                throw new Error('network query must not occur');
              },
            });
          },
        },
      }),
      (error) => error instanceof V2CliError
        && error.code === 'LOCAL_STATE_INVALID',
      scenario.name,
    );
    assert.equal(clientCalls, 0, `${scenario.name} created a chain client`);
    assert.equal(queryCalls, 0, `${scenario.name} queried the chain`);
  }
});

test('wallet V3 receives across its primary and operation-bound change addresses', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const filename = path.join(subject.dataDirectory, 'wallet.json');
  const persisted = JSON.parse(await readFile(filename, 'utf8'));
  const changeWallet = deriveV2ChipnetFundingWallet({
    privateKeyHex: `${'0'.repeat(63)}6`,
  });
  const operationId = `v2op:${'d'.repeat(64)}`;
  const updated = {
    ...persisted,
    changeWallets: [{ operationId, wallet: changeWallet }],
  };
  await writeFile(filename, canonicalizeJcs(updated), { mode: 0o600 });

  const calls = [];
  const canonicalTip = {
    actionSequence: 0,
    blockHash: '01'.repeat(32),
    height: 100,
    state: subject.pool.initialState,
    txid: subject.pool.descriptor.genesis.transactionId,
    vout: subject.pool.descriptor.genesis.outpointIndex,
  };
  const result = await executeV2Cli([
    'wallet', 'receive', '--protocol', 'v2-direct',
    '--data-dir', subject.dataDirectory,
  ], {
    cwd: subject.root,
    dependencies: {
      createChainClient() {
        return Object.freeze({
          async queryWalletUtxos(request) {
            calls.push(request);
            const valueSats = request.cashAddress
              === persisted.fundingWallet.cashAddress
              ? '10000001'
              : '20000002';
            return Object.freeze({
              canonicalTip,
              cashAddress: request.cashAddress,
              lockingBytecodeHex: request.lockingBytecodeHex,
              utxos: Object.freeze([Object.freeze({
                txid: request.cashAddress
                  === persisted.fundingWallet.cashAddress
                  ? '11'.repeat(32)
                  : '22'.repeat(32),
                vout: 0,
                valueSats,
              })]),
            });
          },
        });
      },
    },
  });
  assert.equal(result.funding.watchedAddressCount, 2);
  assert.equal(result.funding.observedUtxoCount, 2);
  assert.equal(result.funding.observedBalanceSats, '30000003');
  assert.deepEqual(
    calls.map((call) => call.cashAddress),
    [persisted.fundingWallet.cashAddress, changeWallet.cashAddress],
  );
  assert.deepEqual(
    calls.map((call) => call.instanceId),
    [subject.pool.descriptor.instanceId, subject.pool.descriptor.instanceId],
  );
});

test('validates V2 action arguments and fails closed before journal or network activity when the configured descriptor is not operational', async (t) => {
  const subject = await setupPool(t);
  const wallet = await executeV2Cli([
    'wallet',
    'create',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], { cwd: subject.root });
  await assert.rejects(
    executeV2Cli([
      'deposit',
      '--to',
      wallet.shieldAddress,
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'BROADCAST_FLAG_REQUIRED',
  );
  let unavailable;
  try {
    await executeV2Cli([
      'transfer',
      '--note',
      'note-7',
      '--to',
      wallet.shieldAddress,
      '--broadcast',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root });
  } catch (error) {
    unavailable = error;
  }
  assert.equal(unavailable.code, 'INSTANCE_DESCRIPTOR_INVALID');
  await assert.rejects(
    access(path.join(subject.dataDirectory, 'delivery.sqlite')),
  );
});

test('validates network-specific P2PKH withdrawal addresses before operational descriptor admission', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const encoded = encodeCashAddress({
    prefix: 'bchtest',
    type: 'p2pkh',
    payload: Uint8Array.from({ length: 20 }, () => 7),
  });
  assert.equal(typeof encoded, 'object');
  await assert.rejects(
    executeV2Cli([
      'withdraw',
      '--note',
      'note-9',
      '--to',
      encoded.address,
      '--broadcast',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'INSTANCE_DESCRIPTOR_INVALID',
  );
  const wrong = encodeCashAddress({
    prefix: 'bitcoincash',
    type: 'p2pkh',
    payload: Uint8Array.from({ length: 20 }, () => 7),
  });
  await assert.rejects(
    executeV2Cli([
      'withdraw',
      '--note',
      'note-9',
      '--to',
      wrong.address,
      '--broadcast',
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], { cwd: subject.root }),
    (error) => error instanceof V2CliError
      && error.code === 'CASH_ADDRESS_INVALID',
  );
});

test('sync and recover reject caller-supplied recovery material at parse time', () => {
  const forbidden = [
    ['request', '/tmp/request.json'],
    ['binary', '/tmp/scanner'],
    ['binary-sha256', '00'.repeat(32)],
    ['actions', '/tmp/actions.jsonl'],
    ['timeout-ms', '1000'],
  ];
  for (const command of ['sync', 'recover']) {
    for (const [option, value] of forbidden) {
      assert.throws(
        () => parseV2CliArguments([
          command,
          `--${option}`,
          value,
          '--protocol',
          'v2-direct',
        ]),
        (error) => error instanceof V2CliError
          && error.code === 'OPTION_NOT_ALLOWED',
        `${command} --${option}`,
      );
    }
  }
});

test('sync and recover use the descriptor-bound authenticated online path', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const canonical = Object.freeze({
    state: Buffer.from(subject.pool.initialState, 'hex'),
    outpoint: Object.freeze({
      txid: Buffer.from(
        subject.pool.descriptor.genesis.transactionId,
        'hex',
      ),
      vout: subject.pool.descriptor.genesis.outpointIndex,
    }),
    actionSequence: 0,
    height: 100,
    blockHash: Buffer.from('21'.repeat(32), 'hex'),
  });
  const phases = [];
  const clients = [];
  const stores = [];
  const dependencies = {
    resolveRuntimeMaterialsSha256: async () =>
      Buffer.from(RUNTIME_MATERIALS_SHA256),
    deriveRecoveryScanner() {
      return Object.freeze({ descriptorBoundScanner: true });
    },
    createPrivateActionStore: async () => Object.freeze({}),
    createChainClient() {
      const client = Object.freeze({
        async fetchCanonicalHistoryPage(request) {
          assert.equal(
            request.instanceId,
            subject.pool.descriptor.instanceId,
          );
          assert.equal(
            request.genesisTransactionId,
            subject.pool.descriptor.genesis.transactionId,
          );
          return Object.freeze({
            genesis: Object.freeze({
              transactionId:
                subject.pool.descriptor.genesis.transactionId,
              outputIndex:
                subject.pool.descriptor.genesis.outpointIndex,
              initialStateHex: subject.pool.initialState,
              height: canonical.height,
              blockHash: canonical.blockHash.toString('hex'),
            }),
          });
        },
        async queryWalletUtxos(request) {
          return Object.freeze({
            canonicalTip: Object.freeze({
              actionSequence: canonical.actionSequence,
              blockHash: canonical.blockHash.toString('hex'),
              confirmations: 6,
              height: canonical.height,
              instanceId: subject.pool.descriptor.instanceId,
              state: canonical.state.toString('hex'),
              txid: canonical.outpoint.txid.toString('hex'),
              vout: canonical.outpoint.vout,
            }),
            cashAddress: request.cashAddress,
            lockingBytecodeHex: request.lockingBytecodeHex,
            utxos: Object.freeze([]),
          });
        },
      });
      clients.push(client);
      return client;
    },
    openStore(options) {
      assert.deepEqual(
        options.runtimeMaterialsSha256,
        Buffer.from(RUNTIME_MATERIALS_SHA256),
      );
      const store = {
        canonicalState() {
          return canonical;
        },
        listOperations() {
          return [];
        },
        reconcileAuthenticatedFundingInventory(value) {
          assert.equal(value.canonical, canonical);
          assert.deepEqual(value.fundingInventory, []);
        },
        close() {},
      };
      stores.push(store);
      return store;
    },
    createCanonicalSynchronizer(options) {
      assert.equal(options.chainClient, clients.at(-1));
      assert.equal(options.store, stores.at(-1));
      assert.deepEqual(
        options.recoveryScanner,
        { descriptorBoundScanner: true },
      );
      return async (request) => {
        assert.equal(request.operationId, null);
        assert.deepEqual(request.priorCanonicalTip, {
          state: canonical.state.toString('hex'),
          txid: canonical.outpoint.txid.toString('hex'),
          vout: canonical.outpoint.vout,
          actionSequence: canonical.actionSequence,
          height: canonical.height,
          blockHash: canonical.blockHash.toString('hex'),
        });
        phases.push(request.phase);
        return canonical;
      };
    },
  };

  for (const command of ['sync', 'recover']) {
    const result = await executeV2Cli([
      command,
      '--protocol',
      'v2-direct',
      '--data-dir',
      subject.dataDirectory,
    ], {
      cwd: subject.root,
      dependencies,
    });
    assert.equal(result.command, command);
    assert.equal(result.networkActivity, true);
    assert.equal(result.pendingOperationCount, 0);
    assert.equal(
      result.canonical.transactionId,
      subject.pool.descriptor.genesis.transactionId,
    );
    assert.equal(result.canonical.stateHex, subject.pool.initialState);
  }
  assert.deepEqual(phases, ['cli-sync', 'cli-recover']);
});

test('status derives owned-note balance from the descriptor-bound durable store', async (t) => {
  const subject = await setupPool(t);
  await createWallet(subject);
  const databasePath = path.join(subject.dataDirectory, 'pool.sqlite');
  await writeFile(databasePath, Buffer.from('existing durable store'), {
    mode: 0o600,
  });
  const canonical = Object.freeze({
    state: Buffer.from(subject.pool.initialState, 'hex'),
    outpoint: Object.freeze({
      txid: Buffer.from(
        subject.pool.descriptor.genesis.transactionId,
        'hex',
      ),
      vout: subject.pool.descriptor.genesis.outpointIndex,
    }),
    actionSequence: 1,
    height: 101,
    blockHash: Buffer.from('02'.padStart(64, '0'), 'hex'),
  });
  let closes = 0;
  const status = await executeV2Cli([
    'status',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], {
    cwd: subject.root,
    dependencies: {
      openExistingStore(options) {
        assert.equal(options.path, databasePath);
        assert.deepEqual(
          options.profileId,
          Buffer.from(subject.pool.profileId, 'hex'),
        );
        assert.deepEqual(
          options.instanceId,
          Buffer.from(subject.pool.instanceId, 'hex'),
        );
        assert.deepEqual(
          options.state,
          Buffer.from(subject.pool.initialState, 'hex'),
        );
        return {
          canonicalState: () => canonical,
          ownedNoteStatistics: () => ({
            total: 1,
            unspent: 1,
            spent: 0,
          }),
          recoveryCheckpoint: () => null,
          close() {
            closes += 1;
          },
        };
      },
    },
  });
  assert.equal(status.wallet.observedBalanceSats, '10000000');
  assert.equal(status.wallet.observedNoteCount, 1);
  assert.equal(
    status.wallet.observationStatus,
    'local-authenticated-canonical-store',
  );
  assert.equal(status.recovery.available, true);
  assert.equal(
    status.recovery.source,
    'authenticated-canonical-store',
  );
  assert.equal(status.recovery.actionCount, '1');
  assert.equal(
    status.recovery.tip.transactionId,
    subject.pool.descriptor.genesis.transactionId,
  );
  assert.equal(closes, 1);
});

test('doctor reports exact policy ceilings and closed qualification without network I/O', async (t) => {
  const subject = await setupPool(t);
  const doctor = await executeV2Cli([
    'doctor',
    '--protocol',
    'v2-direct',
    '--data-dir',
    subject.dataDirectory,
  ], { cwd: subject.root });
  assert.equal(doctor.ready, false);
  assert.deepEqual(doctor.hardPolicyCeilings, {
    transactionBytes: 100000,
    eachUnlockingBytecodeBytes: 10000,
    eachStandardVmResourcePercent: 100,
  });
  assert.deepEqual(doctor.mandatoryNetworkGate, {
    exported: true,
    invoked: false,
  });
  assert.equal(doctor.qualification.defaultActivation, false);
  assert.equal(doctor.networkActivity, false);
});

test('serializes typed CLI failures without stacks or qualification claims', () => {
  const rendered = v2CliErrorResult(new V2CliError(
    'ACTION_CONSTRUCTION_UNAVAILABLE',
    'blocked',
    {
      details: {
        mandatoryNetworkGateInvoked: false,
        broadcastAttempted: false,
      },
      exitCode: 3,
    },
  ));
  assert.equal(rendered.exitCode, 3);
  assert.deepEqual(rendered.body.error, {
    code: 'ACTION_CONSTRUCTION_UNAVAILABLE',
    message: 'blocked',
    details: {
      mandatoryNetworkGateInvoked: false,
      broadcastAttempted: false,
    },
  });
  assert.equal(Object.hasOwn(rendered.body.error, 'stack'), false);
  assert.equal(rendered.body.qualification, 'blocked');
});

test('script dispatch requires explicit legacy protocol and emits the linkability warning', () => {
  const script = path.resolve(
    import.meta.dirname,
    '../../../scripts/shieldkit.mjs',
  );
  const missing = spawnSync(
    process.execPath,
    [script, 'deposit', '--to', 'invalid', '--broadcast'],
    { encoding: 'utf8' },
  );
  assert.equal(missing.status, 2);
  assert.equal(JSON.parse(missing.stdout).error.code, 'PROTOCOL_REQUIRED');
  assert.equal(missing.stderr, '');

  const legacy = spawnSync(
    process.execPath,
    [script, 'deposit', '--protocol', 'v1-legacy'],
    { encoding: 'utf8' },
  );
  assert.equal(legacy.status, 2);
  assert.equal(JSON.parse(legacy.stdout).error.code, 'INPUT_REQUIRED');
  const warning = JSON.parse(legacy.stderr);
  assert.equal(warning.warning.code, 'V1_LINKABILITY_WARNING');
  assert.match(warning.warning.message, /linkable/i);
});

test('script hides low-level V2 commands from product help and exposes them only in developer help', () => {
  const script = path.resolve(
    import.meta.dirname,
    '../../../scripts/shieldkit.mjs',
  );
  const productHelp = spawnSync(
    process.execPath,
    [script, '--help'],
    { encoding: 'utf8' },
  );
  assert.equal(productHelp.status, 0);
  assert.match(productHelp.stdout, /pool create/u);
  assert.match(productHelp.stdout, /shieldkit dev --help/u);
  assert.doesNotMatch(productHelp.stdout, /V2 Direct local surface/u);
  assert.doesNotMatch(productHelp.stdout, /wallet create\|receive/u);
  assert.doesNotMatch(productHelp.stdout, /--protocol v2-direct/u);

  const developerHelp = spawnSync(
    process.execPath,
    [script, 'dev', '--help'],
    { encoding: 'utf8' },
  );
  assert.equal(developerHelp.status, 0);
  assert.match(developerHelp.stdout, /V2 Direct internals/u);
  assert.match(developerHelp.stdout, /shieldkit dev wallet create\|receive/u);
  assert.match(developerHelp.stdout, /shieldkit dev operation reconcile/u);
  assert.match(developerHelp.stdout, /--protocol is forbidden/u);
  assert.doesNotMatch(developerHelp.stdout, /pool create --funding-wallet/u);
});

test('script rejects former top-level V2 routing and an explicit protocol inside dev', () => {
  const script = path.resolve(
    import.meta.dirname,
    '../../../scripts/shieldkit.mjs',
  );
  for (const argv of [
    ['status', '--protocol', 'v2-direct'],
    ['wallet', 'create'],
    ['pool', 'add', '/tmp/descriptor.json'],
    ['deposit', '--protocol', 'v2-direct', '--broadcast'],
  ]) {
    const moved = spawnSync(process.execPath, [script, ...argv], {
      encoding: 'utf8',
    });
    assert.equal(moved.status, 2);
    assert.equal(
      JSON.parse(moved.stdout).error.code,
      'DEV_NAMESPACE_REQUIRED',
    );
    assert.equal(moved.stderr, '');
  }

  const duplicateSelection = spawnSync(
    process.execPath,
    [script, 'dev', 'status', '--protocol', 'v2-direct'],
    { encoding: 'utf8' },
  );
  assert.equal(duplicateSelection.status, 2);
  assert.equal(
    JSON.parse(duplicateSelection.stdout).error.code,
    'DEV_PROTOCOL_OPTION_FORBIDDEN',
  );
  assert.equal(duplicateSelection.stderr, '');
});

test('script dispatches developer V2 status without creating its missing data directory', async (t) => {
  const root = await createTestRoot('shieldkit-v2-cli-script-');
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true });
  });
  const dataDirectory = path.join(root, 'absent');
  const script = path.resolve(
    import.meta.dirname,
    '../../../scripts/shieldkit.mjs',
  );
  const result = spawnSync(
    process.execPath,
    [
      script,
      'dev',
      'status',
      '--data-dir',
      dataDirectory,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.protocol, 'v2-direct');
  assert.equal(output.configured, false);
  assert.equal(output.qualification, 'blocked');
  await assert.rejects(access(dataDirectory));
});
