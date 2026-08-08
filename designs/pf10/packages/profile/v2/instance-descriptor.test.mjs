import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeDataPush,
} from '@bitauth/libauth';

import {
  deriveDirectV2BindingP2sh32Lock,
} from '../../action/v2/binding-unlock.mjs';
import {
  PF11_VERIFIER_ROLES,
} from '../../action/v2/settlement.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  directV2VerifierTopologyById,
} from '../../action/v2/topology.mjs';
import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import {
  DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA,
  validateDirectV2Pf10LibauthEvidence,
} from '../../unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  DIRECT_V2_PF10_RUNTIME_SCHEMA,
  validateDirectV2Pf10RuntimeMaterial,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../../unlock-builder/v2/structural-covenants.mjs';
import {
  canonicalCircuitBuildAttestation,
  canonicalDevelopmentSetupAttestation,
  CIRCUIT_BUILD_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
} from './build-attestation.mjs';
import { collectNpmBuildClosure } from './npm-closure.mjs';
import { canonicalizeJcs, deriveProfileId, V2_PROFILE_DOMAINS } from './profile-core.mjs';
import { collectV2RelationSourceManifest } from './relation-source-manifest.mjs';
import {
  createV2SecretFile,
  derivePf11SettlementPinsFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2PreparedPackageRuntimeMaterialSha256,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
  deriveV2RecoveryScannerExecutionPin,
  deriveV2RecoveryScannerFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  descriptorAttestationBytes,
  loadV2InstanceDescriptor,
  PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
  PF10_RUNTIME_ARTIFACT_SCHEMA,
  PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT,
  PF10_UNSIGNED_RUNTIME_REFERENCE_VALIDATION_SCHEMA,
  V2_INSTANCE_VERIFIER_ROLES,
  validateV2DevelopmentPf10QualificationArtifacts,
  validateV2UnsignedPf10RuntimeArtifactReferences,
} from './instance-descriptor.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const RECOVERY_SCANNER_ARTIFACT_SCHEMA =
  'shieldkit-v2-recovery-scanner-artifact-v1';
const RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID = 'recovery-scanner-manifest';
const RECOVERY_SCANNER_BINARY_ARTIFACT_ID = 'recovery-scanner-linux-x64';
const repositoryRoot = path.resolve(import.meta.dirname, '../../../../..');
const repeat = (byte) => byte.repeat(64);
const core = () => ({
  schema: 'shieldkit-profile-core-v2-direct', network: { id: 2, name: 'chipnet' }, denominationSats: '10000000',
  proof: { system: 'groth16', curve: 'bn254', relationId: 'shieldkit-pool-action-v2-direct', relationSha256: repeat('1'), r1csSha256: repeat('2'), verificationKeySha256: repeat('3'), witnessWasmSha256: repeat('4') },
  trees: { note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' }, nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' } },
  crypto: { babyJubCurveId: 'circomlib-babyjub-base8', poseidonId: 'circomlib-poseidon-bn254', domains: { ...V2_PROFILE_DOMAINS } },
  encodings: { state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552', address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128', unlock: 'shieldkit-rolling-bundle-unlock-v2-direct' },
  publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' },
  baseVerifierArtifacts: [{ id: 'carrier-base', sha256: repeat('5') }, { id: 'state-base', sha256: repeat('6') }], toolchain: [{ name: 'circom', version: '2.2.3', sha256: repeat('7') }, { name: 'snarkjs', version: '0.7.6', sha256: repeat('8') }],
});
const stateObject = (profileId) => createDirectV2PoolModel({
  profileId,
  maximumLiveNotes: '7',
  denominationSats: '10000000',
}).state;
const state = (profileId) => encodeStateNftCommitment(
  stateObject(profileId),
  { denominationSats: '10000000' },
).toString('hex');
const nonGenesisState = (profileId) => encodeStateNftCommitment({
  ...stateObject(profileId),
  noteRoot: '03'.padStart(64, '0'),
  noteCount: '1',
  reserveSats: '10000000',
  actionSequence: '1',
}, { denominationSats: '10000000' }).toString('hex');

const bindingRedeemA = Buffer.from([0x51]);
const bindingRedeemB = Buffer.from([0x52, 0x75, 0x51]);
const bindingLockA = deriveDirectV2BindingP2sh32Lock(bindingRedeemA);
const bindingLockB = deriveDirectV2BindingP2sh32Lock(bindingRedeemB);
const pf10RuntimePrograms = Object.freeze({
  prefix: Object.freeze([
    Buffer.from('test-only-pf10-executor-0'),
    Buffer.from('test-only-pf10-executor-1'),
    Buffer.from('test-only-pf10-executor-2'),
    Buffer.from('test-only-pf10-executor-3'),
    Buffer.from('test-only-pf10-executor-4'),
  ]),
  exact: Object.freeze([
    Buffer.from('test-only-pf10-exact-msm-0'),
    Buffer.from('test-only-pf10-exact-msm-1'),
    Buffer.from('test-only-pf10-exact-msm-2'),
  ]),
  fused: Buffer.from('test-only-pf10-fused-redeem'),
  terminal: Buffer.from('test-only-pf10-terminal-redeem'),
});

async function fixture({
  signed = true,
  topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
} = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-descriptor-'));
  const profileCore = core(); const instanceId = '0123456789abcdef'.repeat(4);
  const topology = directV2VerifierTopologyById(topologyId);
  const verifierArtifacts = topology.verifierRoles.map((role, index) => {
    const program = topologyId === DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
      ? index < 5
        ? pf10RuntimePrograms.prefix[index]
        : index <= 7
        ? pf10RuntimePrograms.exact[index - 5]
        : index === 8
          ? pf10RuntimePrograms.fused
          : index === 9
            ? pf10RuntimePrograms.terminal
            : undefined
      : undefined;
    return [
      `verifier-${role}-lock`,
      `locks/verifier-${role}.bin`,
      program === undefined
        ? Buffer.from([0x51 + index, 0x75, 0x51])
        : deriveDirectV2BindingP2sh32Lock(program),
    ];
  });
  const stateHelper = Buffer.from(buildDirectV2StateHelper({
    bindingLock: bindingLockA,
    verifierLocks: verifierArtifacts.map((entry) => entry[2]),
    verifierBaseValues: topology.verifierRoles.map(() =>
      topologyId === DIRECT_V2_PF10_FUSED_TOPOLOGY_ID ? '1200' : '1000'),
    bindingBaseValueSats: '1200',
    stateBaseValueSats: '2500',
    denominationSats: profileCore.denominationSats,
    stateCategory: instanceId,
    minimumChangeSats: '546',
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  const stateHelperUnlock = Buffer.from(
    buildDirectV2StateTrampolineUnlock(stateHelper),
  );
  const stateLock = Buffer.from(buildDirectV2StateTrampolineLock({
    helper: stateHelper,
    bindingLock: bindingLockA,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  }));
  const artifacts = [
    ['base-carrier', 'base/carrier.bin', Buffer.from('base-carrier')],
    ['base-state', 'base/state.bin', Buffer.from('base-state')],
    ['binding-lock-a', 'locks/binding-a.bin', bindingLockA],
    ['binding-lock-b', 'locks/binding-b.bin', bindingLockB],
    ['binding-redeem-a', 'locks/binding-redeem-a.bin', bindingRedeemA],
    ['binding-redeem-b', 'locks/binding-redeem-b.bin', bindingRedeemB],
    ['state-helper', 'locks/state-helper.bin', stateHelper],
    ['state-helper-unlock', 'locks/state-helper-unlock.bin', stateHelperUnlock],
    ['state-lock', 'locks/state.bin', stateLock],
    ['verification-key', 'proof/vk.bin', Buffer.from('vk')],
    ...verifierArtifacts,
  ];
  profileCore.baseVerifierArtifacts = [
    ['base-carrier', 'base/carrier.bin'],
    ['base-state', 'base/state.bin'],
  ].map(([id, file]) => {
    const artifact = artifacts.find((entry) => entry[0] === id);
    assert.notEqual(artifact, undefined);
    return { id, sha256: hash(artifact[2]) };
  });
  const profileId = deriveProfileId(profileCore);
  artifacts.push([
    'profile-core',
    'profile/profile-core.json',
    Buffer.from(canonicalizeJcs(profileCore)),
  ]);
  artifacts.sort(([left], [right]) => left.localeCompare(right));
  for (const [, file, data] of artifacts) {
    const target = path.join(directory, file);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, data);
  }
  const manifest = { schema: 'shieldkit-artifact-manifest-v2-direct', profileId, instanceId, artifacts: artifacts.map(([id, file, data]) => ({ id, path: file, sha256: hash(data) })) };
  const manifestBytes = Buffer.from(canonicalizeJcs(manifest)); await writeFile(path.join(directory, 'manifest.json'), manifestBytes);
  const descriptor = {
    schema: 'shieldkit-instance-descriptor-v2-direct',
    profileId,
    instanceId,
    stateNftCategory: instanceId,
    genesis: { transactionId: 'aa'.repeat(32), outpointIndex: 0 },
    initialState: state(profileId),
    manifest: { path: 'manifest.json', sha256: hash(manifestBytes) },
    finalLocks: {
      topologyId: topology.id,
      verifiers: topology.verifierRoles.map((role) => ({
        role,
        lockingArtifactId: `verifier-${role}-lock`,
        baseSats: topologyId === DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
          ? '1200'
          : '1000',
      })),
      binding: {
        lockingArtifactId: 'binding-lock-a',
        redeemArtifactId: 'binding-redeem-a',
        baseSats: '1200',
      },
      state: {
        lockingArtifactId: 'state-lock',
        helperArtifactId: 'state-helper',
        helperUnlockArtifactId: 'state-helper-unlock',
        baseSats: '2500',
      },
    },
    signature: null,
  };
  let trustedSigners;
  let privateKey;
  if (signed) {
    const pair = generateKeyPairSync('ed25519');
    privateKey = pair.privateKey;
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
    descriptor.signature = {
      algorithm: 'ed25519',
      attestationDomain: 'shieldkit-instance-descriptor-attestation',
      attestationVersion: 1,
      signerId: 'release-signer',
      publicKey,
      signature: '',
    };
    descriptor.signature.signature = sign(null, descriptorAttestationBytes({
      descriptor,
      canonicalManifestBytes: manifestBytes,
      signature: descriptor.signature,
    }), pair.privateKey).toString('base64');
    trustedSigners = [{ signerId: 'release-signer', publicKey }];
  }
  const descriptorPath = path.join(directory, 'instance.json'); await writeFile(descriptorPath, canonicalizeJcs(descriptor));
  return {
    directory,
    descriptorPath,
    descriptor,
    manifest,
    privateKey,
    profileCore,
    trustedSigners,
    topology,
  };
}
const rewrite = async (subject) => writeFile(subject.descriptorPath, canonicalizeJcs(subject.descriptor));
const resign = async (subject) => {
  if (subject.descriptor.signature === null) {
    await rewrite(subject);
    return;
  }
  const canonicalManifestBytes = await readFile(
    path.join(subject.directory, 'manifest.json'),
  );
  subject.descriptor.signature.signature = '';
  subject.descriptor.signature.signature = sign(
    null,
    descriptorAttestationBytes({
      descriptor: subject.descriptor,
      canonicalManifestBytes,
      signature: subject.descriptor.signature,
    }),
    subject.privateKey,
  ).toString('base64');
  await rewrite(subject);
};
const replacePinnedArtifact = async (subject, artifactId, data) => {
  const artifact = subject.manifest.artifacts.find(
    (entry) => entry.id === artifactId,
  );
  assert.notEqual(artifact, undefined);
  const bytes = Buffer.from(data);
  await writeFile(path.join(subject.directory, artifact.path), bytes);
  artifact.sha256 = hash(bytes);
  const manifestBytes = Buffer.from(canonicalizeJcs(subject.manifest));
  await writeFile(
    path.join(subject.directory, 'manifest.json'),
    manifestBytes,
  );
  subject.descriptor.manifest.sha256 = hash(manifestBytes);
  await resign(subject);
};
const addPinnedArtifact = async (subject, artifactId, relativePath, data) => {
  const bytes = Buffer.from(data);
  await mkdir(path.dirname(path.join(subject.directory, relativePath)), {
    recursive: true,
  });
  await writeFile(path.join(subject.directory, relativePath), bytes);
  subject.manifest.artifacts.push({
    id: artifactId,
    path: relativePath,
    sha256: hash(bytes),
  });
  subject.manifest.artifacts.sort((left, right) =>
    left.id.localeCompare(right.id));
  const manifestBytes = Buffer.from(canonicalizeJcs(subject.manifest));
  await writeFile(path.join(subject.directory, 'manifest.json'), manifestBytes);
  subject.descriptor.manifest.sha256 = hash(manifestBytes);
  await resign(subject);
};

const recoveryScannerManifest = (binary) => ({
  schema: RECOVERY_SCANNER_ARTIFACT_SCHEMA,
  target: 'linux-x64',
  binaryArtifactId: RECOVERY_SCANNER_BINARY_ARTIFACT_ID,
  binarySha256: hash(binary),
  binaryBytes: binary.length,
  cargoLockSha256: hash(Buffer.from('version = 4\n')),
  cargoVersion: 'cargo 1.97.1 (fixture)',
  eligibility: 'clean-source-build',
  protocolSchemas: [
    'shieldkit-v2-recovery-authenticate-snapshot-stream-input-v2',
    'shieldkit-v2-recovery-authenticate-snapshot-v2',
    'shieldkit-v2-recovery-authenticated-material-v2',
    'shieldkit-v2-recovery-scan-result-v2',
    'shieldkit-v2-recovery-scan-v2',
    'shieldkit-v2-recovery-snapshot-v2',
    'shieldkit-v2-recovery-stream-input-v2',
    'shieldkit-v2-recovery-stream-output-v2',
    'shieldkit-v2-recovery-verify-v2',
  ],
  rustcVersion: 'rustc 1.97.1 (fixture)',
  sourceRevision: 'a'.repeat(40),
});

const addRecoveryScannerArtifacts = async (subject) => {
  const binary = Buffer.from('#!/bin/sh\nexit 0\n', 'utf8');
  const binaryPath = path.join(
    subject.directory,
    'recovery/recovery-scanner-linux-x64',
  );
  await addPinnedArtifact(
    subject,
    RECOVERY_SCANNER_BINARY_ARTIFACT_ID,
    'recovery/recovery-scanner-linux-x64',
    binary,
  );
  await chmod(binaryPath, 0o755);
  const metadata = recoveryScannerManifest(binary);
  await addPinnedArtifact(
    subject,
    RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
    'recovery/recovery-scanner-manifest.json',
    Buffer.from(canonicalizeJcs(metadata)),
  );
  return Object.freeze({
    binary,
    binaryPath,
    metadata,
  });
};

const mutateRecoveryScannerManifest = async (subject, mutate) => {
  const artifact = subject.manifest.artifacts.find(
    (entry) => entry.id === RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
  );
  assert.notEqual(artifact, undefined);
  const metadata = JSON.parse(await readFile(
    path.join(subject.directory, artifact.path),
    'utf8',
  ));
  const replacement = mutate(metadata);
  await replacePinnedArtifact(
    subject,
    RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
    Buffer.from(canonicalizeJcs(replacement === undefined ? metadata : replacement)),
  );
};

const artifactHash = (subject, artifactId) => {
  const artifact = subject.manifest.artifacts.find(
    (entry) => entry.id === artifactId,
  );
  assert.notEqual(artifact, undefined, `missing fixture artifact ${artifactId}`);
  return artifact.sha256;
};

const artifactBytes = async (subject, artifactId) => {
  const artifact = subject.manifest.artifacts.find(
    (entry) => entry.id === artifactId,
  );
  assert.notEqual(artifact, undefined, `missing fixture artifact ${artifactId}`);
  return readFile(path.join(subject.directory, artifact.path));
};

const rebindProfileCore = async (
  subject,
  proofArtifacts = undefined,
  mutate = (value) => value,
) => {
  const baseVerifierArtifacts = ['base-carrier', 'base-state'].map((id) => ({
    id,
    sha256: artifactHash(subject, id),
  }));
  subject.profileCore = mutate({
    ...subject.profileCore,
    proof: {
      ...subject.profileCore.proof,
      ...(proofArtifacts === undefined ? {} : {
        r1csSha256: artifactHash(subject, proofArtifacts.r1cs),
        verificationKeySha256: artifactHash(
          subject,
          proofArtifacts.verificationKey,
        ),
        witnessWasmSha256: artifactHash(subject, proofArtifacts.wasm),
      }),
    },
    baseVerifierArtifacts,
  });
  const profileId = deriveProfileId(subject.profileCore);
  const profileCoreArtifact = subject.manifest.artifacts.find(
    (entry) => entry.id === 'profile-core',
  );
  assert.notEqual(profileCoreArtifact, undefined);
  const profileCoreBytes = Buffer.from(canonicalizeJcs(subject.profileCore));
  await writeFile(
    path.join(subject.directory, profileCoreArtifact.path),
    profileCoreBytes,
  );
  profileCoreArtifact.sha256 = hash(profileCoreBytes);
  subject.manifest.profileId = profileId;
  subject.descriptor.profileId = profileId;
  subject.descriptor.initialState = state(profileId);
  const manifestBytes = Buffer.from(canonicalizeJcs(subject.manifest));
  await writeFile(path.join(subject.directory, 'manifest.json'), manifestBytes);
  subject.descriptor.manifest.sha256 = hash(manifestBytes);
  await resign(subject);
};

let runtimeFixtureContext;
const runtimeContractContext = async () => {
  if (runtimeFixtureContext === undefined) {
    runtimeFixtureContext = Promise.all([
      collectNpmBuildClosure({ repositoryRoot, roots: ['circom2'] }),
      collectNpmBuildClosure({ repositoryRoot, roots: ['snarkjs'] }),
      collectV2RelationSourceManifest({ repositoryRoot }),
    ]).then(([circomClosure, snarkjsClosure, relationManifest]) =>
      Object.freeze({
        circomClosure,
        snarkjsClosure,
        relationBytes: Buffer.from(canonicalizeJcs(relationManifest), 'utf8'),
      }));
  }
  return runtimeFixtureContext;
};

const closureArtifact = (closure, packagePath, relative) => {
  const record = closure.packages
    .find((entry) => entry.packagePath === packagePath)
    ?.installed.files.find((entry) => entry.path === relative);
  assert.notEqual(record, undefined, `missing ${packagePath}/${relative}`);
  return Object.freeze({
    bytes: record.bytes,
    path: `${packagePath}/${relative}`,
    sha256: record.sha256,
  });
};

const pf10RuntimeMaterialForFixture = async (
  subject,
  { proofArtifacts, unlockArtifacts },
) => validateDirectV2Pf10RuntimeMaterial({
  schema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
  eligibility: 'development-only',
  profileId: subject.descriptor.profileId,
  instanceId: subject.descriptor.instanceId,
  topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  proofArtifactHashes: {
    provingKey: artifactHash(subject, proofArtifacts.provingKey),
    r1cs: artifactHash(subject, proofArtifacts.r1cs),
    verificationKey: artifactHash(subject, proofArtifacts.verificationKey),
    wasm: artifactHash(subject, proofArtifacts.wasm),
  },
  verificationKeyBytes: await artifactBytes(
    subject,
    proofArtifacts.verificationKey,
  ),
  executorBody: await artifactBytes(subject, unlockArtifacts.executorBody),
  exactMsmRedeems: await Promise.all(unlockArtifacts.exactMsmRedeems.map(
    (id) => artifactBytes(subject, id),
  )),
  fixedCarrierPads: await Promise.all(unlockArtifacts.fixedCarrierPads.map(
    (id) => artifactBytes(subject, id),
  )),
  fusedRedeem: await artifactBytes(subject, unlockArtifacts.fusedRedeem),
  terminalRedeem: await artifactBytes(subject, unlockArtifacts.terminalRedeem),
  stateUnlockingBytecode: await artifactBytes(
    subject,
    subject.descriptor.finalLocks.state.helperUnlockArtifactId,
  ),
  bindingRedeemBytecode: await artifactBytes(
    subject,
    subject.descriptor.finalLocks.binding.redeemArtifactId,
  ),
  bindingLockingBytecode: await artifactBytes(
    subject,
    subject.descriptor.finalLocks.binding.lockingArtifactId,
  ),
  verifierLockingBytecodes: await Promise.all(
    subject.descriptor.finalLocks.verifiers.map((entry) => artifactBytes(
      subject,
      entry.lockingArtifactId,
    )),
  ),
});

const pf10LibauthEvidenceForFixture = ({
  instanceId,
  profileId,
  proofArtifactHashes,
  runtimeMaterialSha256,
}) => {
  // These are deliberately deterministic local unit-test records. They carry
  // no live-chain provenance and no release claim, but their hashes, row
  // schema, parent wiring, byte counts, and hard-limit arithmetic are all
  // internally consistent so the production semantic validator is exercised.
  const displayTransactionId = (bytes) => Buffer.from(
    createHash('sha256').update(
      createHash('sha256').update(bytes).digest(),
    ).digest(),
  ).reverse().toString('hex');
  const sourceParent = (label) => {
    const bytes = Buffer.from(`local-unit-${label}-parent`, 'utf8');
    return {
      rawTransactionHex: bytes.toString('hex'),
      rawTransactionSha256: hash(bytes),
      transactionId: displayTransactionId(bytes),
    };
  };
  const previousBundle = sourceParent('previous-bundle');
  const funding = sourceParent('funding');
  const rowNames = [
    'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'msm5', 'msm6',
    'msm7', 'fused-q-genesis8', 'terminal9', 'binding10', 'state11',
    'funding12',
  ];
  const mutationChecks = [
    ['local-table', 0, [0]],
    ['local-table', 1, [1]],
    ['local-table', 2, [2]],
    ['local-table', 3, [3]],
    ['local-table', 4, [4]],
    ['local-table', 9, [9]],
    ['remote-carrier', 5, [0, 5]],
    ['remote-carrier', 6, [1, 6]],
    ['remote-carrier', 7, [3, 7]],
  ].map(([kind, mutatedInput, rejectingInputs]) => ({
    kind,
    mutatedInput,
    rejectingInputs,
  }));
  const roleTableHash256 = Array.from({ length: 5 }, (_, index) =>
    hash(Buffer.from(`local-unit-fixed-role-table-${index}`)),
  );
  const terminalTableHash256 = hash(
    Buffer.from('local-unit-fixed-terminal-table'),
  );
  const action = (kind, transactionBytes, outputCount) => {
    const raw = Buffer.alloc(transactionBytes, kind.charCodeAt(0));
    const localVmBytes = Buffer.from(`local-unit-${kind}-vm-evidence`);
    const localVmEvidenceHash = hash(localVmBytes);
    const sourceOutputs = Array.from({ length: 13 }, () => ({
      lockingBytecodeHex: '', tokenPrefixHex: '', valueSats: '0',
    }));
    return {
      kind,
      inputCount: 13,
      outputCount,
      transactionBytes,
      transactionLimitBytes: 100_000,
      transactionHeadroomBytes: 100_000 - transactionBytes,
      feeRateSatsPerByte: '1',
      feeSats: transactionBytes.toString(),
      proofVerified: true,
      proofGenerationMs: 0,
      contextHash: hash(Buffer.from(`local-unit-${kind}-context`)),
      packetSha256: hash(Buffer.from(`local-unit-${kind}-packet`)),
      rawTransactionHex: raw.toString('hex'),
      rawTransactionSha256: hash(raw),
      transactionId: displayTransactionId(raw),
      construction: {
        assemblyHash: hash(Buffer.from(`local-unit-${kind}-assembly`)),
        inputSequence: 0,
        localVmEvidenceHash,
        path: [
          'prepareV2DirectSettlement',
          'assembleV2DirectSettlement',
          'signV2DirectSettlement',
        ],
        preparedPayloadHash: hash(Buffer.from(`local-unit-${kind}-payload`)),
      },
      sourceParents: { funding, previousBundle },
      inputSources: Array.from({ length: 13 }, (_, index) => ({
        inputIndex: index,
        outputIndex: index < 10 ? index + 1 : index === 10 ? 11 : 0,
        parentKind: index === 12 ? 'funding' : 'previous-bundle',
        serializedOutputSha256: hash(Buffer.from(`local-unit-${kind}-source-${index}`)),
        transactionId: index === 12
          ? funding.transactionId
          : previousBundle.transactionId,
      })),
      sourceOutputs,
      localVmEvidence: {
        evidenceHash: localVmEvidenceHash,
        hex: localVmBytes.toString('hex'),
        sha256: hash(localVmBytes),
      },
      mutationChecks: mutationChecks.map((entry) => ({
        ...entry,
        rejectingInputs: [...entry.rejectingInputs],
      })),
      rows: rowNames.map((name, index) => ({
        arithmeticCost: 0,
        definedFunctions: 0,
        evaluatedInstructionCount: 0,
        hashDigestIterations: 0,
        index,
        maximumHashDigestIterations: 0,
        maximumLegalOperationCost: 0,
        maximumOperationCost: 0,
        maximumSignatureChecks: 0,
        name,
        operationCost: 0,
        operationPercent: 0,
        signatureCheckCount: 0,
        stackPushedBytes: 0,
        unlockBytes: 0,
        hardAccepted: true,
        semanticAccepted: true,
      })),
    };
  };
  return {
    schema: DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA,
    eligibility: 'development-only',
    generatedAt: '2026-01-01T00:00:00.000Z',
    environment: { architecture: 'x64', node: process.version, platform: 'linux' },
    qualificationScope: {
      feePolicy: 'exact signed bytes at 1 satoshi per byte',
      inputSequence: 0,
      parentTransactions: 'deterministically constructed local serialized transactions; every child outpoint and source output is authenticated from exact parent bytes; no live-chain provenance is claimed',
      settlementPath: 'prepareV2DirectSettlement -> assembleV2DirectSettlement -> signV2DirectSettlement -> createV2LocalVmEvidence',
    },
    claims: {
      authenticatedSerializedParentOutputs: true,
      bchnMempool: false,
      bchnMined: false,
      finalKey: false,
      leanBch: false,
      libauthBch2026: true,
      liveChainParentProvenance: false,
      production: false,
      productionSettlementBuilderPath: true,
      releaseQualified: false,
      unmodifiedMaintainerBenchmark: false,
    },
    identity: {
      profileId,
      instanceId,
      proofArtifactHashes,
      runtimeMaterialSha256,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    },
    exactDustBases: {
      bindingSats: '1200',
      minimumChangeSats: '546',
      stateSats: '2500',
      verifierSats: Array(10).fill('1200'),
    },
    hardLimits: {
      standardVmResourcePercent: 100,
      transactionBytes: 100_000,
      unlockingBytecodeBytes: 10_000,
    },
    pf10FusedQGenesisActions: {
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      actionCount: 3,
      actions: [
        action('deposit', 97_852, 13),
        action('transfer', 97_852, 13),
        action('withdrawal', 97_886, 14),
      ],
      fixedLineDerivation: {
        digestMutationChecks: [
          ...roleTableHash256.map((honestHash256, index) => ({
            table: `executor${index}`,
            honestHash256,
            mutatedHash256: hash(Buffer.from(`local-unit-mutated-role-${index}`)),
          })),
          {
            table: 'terminal9',
            honestHash256: terminalTableHash256,
            mutatedHash256: hash(Buffer.from('local-unit-mutated-terminal')),
          },
        ],
        inputs: [
          'deployment verification key gamma',
          'deployment verification key delta',
          'BN254 constants',
          'ATE NAF digits',
        ],
        proofOrPublicInputs: false,
        roleTableBytes: [6_912, 5_760, 6_144, 6_144, 7_296],
        roleTableHash256,
        terminalTableBytes: 768,
        terminalTableHash256,
      },
      fixedPrograms: {
        bindingRedeemBytes: 2_195,
        exactFinalRawBytes: 1_924,
        exactFinalRedeemBytes: 1_597,
        exactRawBytes: [1_682, 1_667, 1_675],
        exactRedeemBytes: [1_387, 1_372, 1_380],
        executorBodyBytes: 5_573,
        executorDensityPadBytes: 384,
        fixedLineCarrierBytes: 20_864,
        fusedRedeemBytes: 6_404,
        loaderBytes: 108,
        millerRawBytes: 5_430,
        millerRedeemBytes: 4_620,
        rawExecutorBytes: 10_937,
        rawTerminalBytes: 9_359,
        stateHelperBytes: 2_674,
        terminalRedeemBytes: pf10RuntimePrograms.terminal.length,
      },
      identityExecutorRows: Array.from({ length: 5 }, (_, index) => ({
        index,
        operationCost: 1,
        unlockBytes: 1,
      })),
      verdict: 'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
    },
  };
};

/**
 * Construct only local schema documents. These are deliberately untrusted
 * parser inputs: this helper never calls a prover, VM, compiler, or runtime
 * resolver, and does not claim to create qualification evidence.
 */
const addPf10QualificationEnvelope = async (
  subject,
  mutateEvidence = (value) => value,
) => {
  const profileArtifacts = {
    profileCore: 'profile-core',
    profilePackage: 'development-profile-package',
    baseVerifierManifest: 'pf10-base-verifier-sources',
    topologySpec: 'pf10-topology-spec',
    toolchainManifest: 'toolchain-manifest',
  };
  const attestationArtifacts = {
    circuitBuildAttestation: 'circuit-build-attestation',
    developmentSetupAttestation: 'development-setup-attestation',
    relationManifest: 'relation-source-manifest',
  };
  const setupArtifacts = {
    circuitSymbols: 'proof-circuit-symbols',
    initialProvingKey: 'proof-initial-proving-key',
    powersOfTau: 'proof-powers-of-tau',
  };
  const alternateTopologySpec = 'alternate-topology-spec';
  const proofArtifacts = {
    provingKey: 'proof-proving-key',
    r1cs: 'proof-r1cs',
    verificationKey: 'proof-verification-key',
    wasm: 'proof-wasm',
  };
  const unlockArtifacts = {
    executorBody: 'pf10-executor-body',
    exactMsmRedeems: ['pf10-exact-0', 'pf10-exact-1', 'pf10-exact-2'],
    fixedCarrierPads: ['pf10-pad-0', 'pf10-pad-1', 'pf10-pad-2'],
    fusedRedeem: 'pf10-fused-redeem',
    terminalRedeem: 'pf10-terminal-redeem',
  };
  for (const [name, id] of Object.entries(proofArtifacts)) {
    const bytes = name === 'verificationKey'
      ? await readFile(path.join(
        repositoryRoot,
        'designs/pf10/packages/prove/test-fixtures/two-public/verification_key.json',
      ))
      : Buffer.from(`fixture-${id}`);
    await addPinnedArtifact(
      subject,
      id,
      `proof/${name}.bin`,
      bytes,
    );
  }
  const context = await runtimeContractContext();
  for (const [name, id] of Object.entries({
    baseVerifierManifest: profileArtifacts.baseVerifierManifest,
    topologySpec: profileArtifacts.topologySpec,
    toolchainManifest: profileArtifacts.toolchainManifest,
    alternateTopologySpec,
    ...setupArtifacts,
  })) {
    await addPinnedArtifact(
      subject,
      id,
      `runtime-contract/${name}.bin`,
      Buffer.from(`fixture-${id}`),
    );
  }
  await addPinnedArtifact(
    subject,
    attestationArtifacts.relationManifest,
    'runtime-contract/relation-manifest.json',
    context.relationBytes,
  );
  for (const id of [
    unlockArtifacts.executorBody,
    ...unlockArtifacts.exactMsmRedeems,
    ...unlockArtifacts.fixedCarrierPads,
    unlockArtifacts.fusedRedeem,
    unlockArtifacts.terminalRedeem,
  ]) {
    const bytes = id === unlockArtifacts.executorBody
      ? Buffer.from(`fixture-${id}`)
      : id === unlockArtifacts.fusedRedeem
        ? pf10RuntimePrograms.fused
        : id === unlockArtifacts.terminalRedeem
          ? pf10RuntimePrograms.terminal
          : unlockArtifacts.exactMsmRedeems.includes(id)
            ? pf10RuntimePrograms.exact[
              unlockArtifacts.exactMsmRedeems.indexOf(id)
            ]
            : Buffer.alloc(7_500, id.charCodeAt(id.length - 1));
    await addPinnedArtifact(
      subject,
      id,
      `runtime/${id}.bin`,
      bytes,
    );
  }
  await rebindProfileCore(subject, proofArtifacts);
  const runtimeMaterial = await pf10RuntimeMaterialForFixture(subject, {
    proofArtifacts,
    unlockArtifacts,
  });
  const libauthEvidenceArtifactId = 'pf10-libauth-evidence';
  const libauthEvidence = pf10LibauthEvidenceForFixture({
    profileId: subject.descriptor.profileId,
    instanceId: subject.descriptor.instanceId,
    proofArtifactHashes: {
      provingKey: artifactHash(subject, proofArtifacts.provingKey),
      r1cs: artifactHash(subject, proofArtifacts.r1cs),
      verificationKey: artifactHash(subject, proofArtifacts.verificationKey),
      wasm: artifactHash(subject, proofArtifacts.wasm),
    },
    runtimeMaterialSha256: runtimeMaterial.materialSha256,
  });
  const libauthEvidenceBytes = Buffer.from(canonicalizeJcs(libauthEvidence));
  // Exercise the production semantic validator before the evidence becomes a
  // signed runtime artifact; this is local fixture validation, not a release
  // claim or a substitute for a qualification campaign.
  assert.equal(
    validateDirectV2Pf10LibauthEvidence({
      bytes: libauthEvidenceBytes,
      expectedTerminalProgramBytes: Object.freeze({
        raw: 9_359,
        redeem: pf10RuntimePrograms.terminal.length,
      }),
      profileId: subject.descriptor.profileId,
      instanceId: subject.descriptor.instanceId,
      proofArtifactHashes: libauthEvidence.identity.proofArtifactHashes,
      runtimeMaterialSha256: runtimeMaterial.materialSha256,
    }).runtimeMaterialSha256,
    runtimeMaterial.materialSha256,
  );
  await addPinnedArtifact(
    subject,
    libauthEvidenceArtifactId,
    'qualification/libauth-evidence.json',
    libauthEvidenceBytes,
  );

  // Manifest records do not retain byte counts, so derive the exact evidence
  // from the file instead of duplicating fixture literals.
  const evidenceRecord = async (id, expectedPath) => {
    const entry = subject.manifest.artifacts.find((value) => value.id === id);
    assert.notEqual(entry, undefined, `missing fixture artifact ${id}`);
    const bytes = await readFile(path.join(subject.directory, entry.path));
    return Object.freeze({ bytes: bytes.length, path: expectedPath, sha256: entry.sha256 });
  };
  const [r1cs, circuitSymbols, witnessWasm, initialProvingKey, powersOfTau,
    provingKey, verificationKey, relationManifest] = await Promise.all([
    evidenceRecord(proofArtifacts.r1cs, 'main-chipnet.r1cs'),
    evidenceRecord(setupArtifacts.circuitSymbols, 'main-chipnet.sym'),
    evidenceRecord(proofArtifacts.wasm, 'main-chipnet_js/main-chipnet.wasm'),
    evidenceRecord(setupArtifacts.initialProvingKey, 'initial.zkey'),
    evidenceRecord(setupArtifacts.powersOfTau, 'powers-of-tau.ptau'),
    evidenceRecord(proofArtifacts.provingKey, 'final.zkey'),
    evidenceRecord(proofArtifacts.verificationKey, 'verification_key.json'),
    evidenceRecord(
      attestationArtifacts.relationManifest,
      'relation-source-manifest.json',
    ),
  ]);
  const build = canonicalCircuitBuildAttestation({
    schema: CIRCUIT_BUILD_ATTESTATION_SCHEMA,
    claims: { developmentOnly: true, production: false, release: false },
    compilation: {
      argv: [
        'node_modules/circom2/cli.js',
        'designs/pf10/circuits/v2-direct/main-chipnet.circom',
        '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2',
        '--output', '$BUILD_OUTPUT',
      ],
      circomCompilerVersion: '2.2.3',
      circomPackageVersion: '0.2.23',
      cli: closureArtifact(context.circomClosure, 'node_modules/circom2', 'cli.js'),
      executable: 'process.execPath',
      node: { modulesAbi: process.versions.modules, version: process.versions.node },
      optimization: 'O1',
      packageMetadata: closureArtifact(
        context.circomClosure,
        'node_modules/circom2',
        'package.json',
      ),
      sanityCheck: 2,
    },
    npmClosure: context.circomClosure,
    r1csAbi: {
      constraints: 1,
      field: 'bn254',
      privateInputs: 1,
      publicInputs: 2,
      publicOutputs: 0,
      wires: 4,
    },
    sourceManifest: relationManifest,
    artifacts: { r1cs, sym: circuitSymbols, wasm: witnessWasm },
  });
  await addPinnedArtifact(
    subject,
    attestationArtifacts.circuitBuildAttestation,
    'runtime-contract/circuit-build-attestation.json',
    build.bytes,
  );
  const buildAttestation = await evidenceRecord(
    attestationArtifacts.circuitBuildAttestation,
    'circuit-build-attestation.json',
  );
  const setup = canonicalDevelopmentSetupAttestation({
    schema: DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
    claims: {
      contributionIndependence: 'not-established',
      developmentOnly: true,
      externalTranscript: false,
      finalCeremony: false,
      production: false,
      release: false,
    },
    buildAttestation,
    r1cs,
    ptau: {
      artifact: powersOfTau,
      ceremonyPower: 4,
      power: 4,
      source: 'descriptor-runtime-contract-fixture',
      verified: true,
    },
    snarkjs: {
      cli: closureArtifact(context.snarkjsClosure, 'node_modules/snarkjs', 'build/cli.cjs'),
      node: { modulesAbi: process.versions.modules, version: process.versions.node },
      npmClosure: context.snarkjsClosure,
      packageMetadata: closureArtifact(
        context.snarkjsClosure,
        'node_modules/snarkjs',
        'package.json',
      ),
      version: '0.7.6',
    },
    commands: {
      powersOfTauVerify: ['node_modules/snarkjs/build/cli.cjs', 'powersoftau', 'verify', '$PTAU'],
      setup: ['node_modules/snarkjs/build/cli.cjs', 'groth16', 'setup', '$R1CS', '$PTAU', '$INITIAL_ZKEY'],
      contribute: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'contribute', '$INPUT_ZKEY', '$OUTPUT_ZKEY'],
      verifyFinalZkey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'verify', '$R1CS', '$PTAU', '$FINAL_ZKEY'],
      exportVerificationKey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'export', 'verificationkey', '$FINAL_ZKEY', '$VERIFICATION_KEY'],
    },
    zkeyChain: {
      contributions: [{
        entropyCommitment: '11'.repeat(32),
        entropyCommitmentDomain: DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
        inputZkeySha256: initialProvingKey.sha256,
        output: provingKey,
        sequence: 1,
      }],
      initial: initialProvingKey,
    },
    finalEvidence: {
      finalZkeySha256: provingKey.sha256,
      finalZkeyVerified: true,
      verificationKey,
      verificationKeyExported: true,
    },
  });
  await addPinnedArtifact(
    subject,
    attestationArtifacts.developmentSetupAttestation,
    'runtime-contract/development-setup-attestation.json',
    setup.bytes,
  );
  const profilePackage = {
    schema: 'shieldkit-v2-direct-development-profile-package-v1',
    eligibility: 'development-only',
    profileId: subject.descriptor.profileId,
    profileCoreSha256: artifactHash(subject, profileArtifacts.profileCore),
    proofArtifacts: {
      circuitSymbols: await evidenceRecord(setupArtifacts.circuitSymbols, 'proof/circuit-symbols.bin'),
      initialProvingKey: await evidenceRecord(setupArtifacts.initialProvingKey, 'proof/initial.zkey'),
      powersOfTau: await evidenceRecord(setupArtifacts.powersOfTau, 'proof/powers-of-tau.ptau'),
      provingKey: await evidenceRecord(proofArtifacts.provingKey, 'proof/development.zkey'),
      r1cs: await evidenceRecord(proofArtifacts.r1cs, 'proof/main-chipnet.r1cs'),
      verificationKey: await evidenceRecord(proofArtifacts.verificationKey, 'proof/verification_key.json'),
      witnessWasm: await evidenceRecord(proofArtifacts.wasm, 'proof/main-chipnet.wasm'),
    },
    generatedArtifacts: {
      baseVerifierManifest: await evidenceRecord(profileArtifacts.baseVerifierManifest, 'base-verifier-manifest.json'),
      circuitBuildAttestation: await evidenceRecord(attestationArtifacts.circuitBuildAttestation, 'circuit-build-attestation.json'),
      developmentSetupAttestation: await evidenceRecord(attestationArtifacts.developmentSetupAttestation, 'development-setup-attestation.json'),
      profileCore: await evidenceRecord(profileArtifacts.profileCore, 'profile-core.json'),
      relationManifest: await evidenceRecord(attestationArtifacts.relationManifest, 'relation-manifest.json'),
      toolchainManifest: await evidenceRecord(profileArtifacts.toolchainManifest, 'toolchain-manifest.json'),
      topologySpec: await evidenceRecord(profileArtifacts.topologySpec, 'pf10-topology-spec.json'),
    },
  };
  await addPinnedArtifact(
    subject,
    profileArtifacts.profilePackage,
    'runtime-contract/profile-package.json',
    Buffer.from(canonicalizeJcs(profilePackage)),
  );

  const source = async (id) => {
    const artifact = subject.manifest.artifacts.find(
      (entry) => entry.id === id,
    );
    assert.notEqual(artifact, undefined);
    const bytes = await readFile(path.join(subject.directory, artifact.path));
    return {
      path: artifact.path,
      bytes: bytes.length,
      sha256: artifact.sha256,
    };
  };
  const action = (name) => {
    const packet = Buffer.alloc(552, name.charCodeAt(0));
    const file = (suffix) => {
      const bytes = Buffer.from(`${name}-${suffix}`);
      return {
        path: `qualification/${name}-${suffix}`,
        bytes: bytes.length,
        sha256: hash(bytes),
      };
    };
    return {
      files: {
        v2DirectGroth16Adapter: file('v2-direct-groth16-adapter'),
        input: file('input'),
        packet: {
          path: `qualification/${name}-packet.bin`,
          bytes: packet.length,
          sha256: hash(packet),
        },
        proof: file('proof'),
        publicSignals: file('public'),
        witness: file('witness'),
      },
      packetDigest: hash(packet),
      witnessValid: true,
      proofVerified: true,
      publicInputs: ['0', '1'],
      timingsMs: {
        proofGeneration: 0,
        proofVerification: 0,
        total: 0,
        witnessCalculation: 0,
        witnessCheck: 0,
      },
    };
  };
  const evidence = {
    schema: 'shieldkit-v2-direct-development-groth16-qualification-v4',
    evidenceClass: 'deterministic-development-key-proof-test-evidence',
    fixture: 'deterministic-deposit-transfer-withdrawal-chain',
    claims: {
      developmentKey: true,
      finalKey: false,
      bchVm: false,
      production: false,
    },
    identity: {
      profileId: subject.descriptor.profileId,
      instanceId: subject.descriptor.instanceId,
      maximumLiveNotes: '7',
      denominationSats: subject.profileCore.denominationSats,
    },
    sourceArtifacts: {
      profileCore: {
        path: 'profile/profile-core.json',
        bytes: (await readFile(
          path.join(subject.directory, 'profile/profile-core.json'),
        )).length,
        sha256: artifactHash(subject, 'profile-core'),
      },
      r1cs: await source(proofArtifacts.r1cs),
      wasm: await source(proofArtifacts.wasm),
      developmentZkey: await source(proofArtifacts.provingKey),
      verificationKey: await source(proofArtifacts.verificationKey),
    },
    actions: {
      deposit: action('deposit'),
      transfer: action('transfer'),
      withdrawal: action('withdrawal'),
    },
    versions: { node: 'v25.0.0', snarkjs: '0.7.6' },
    prover: {
      backend: 'snarkjs',
      provingSystem: 'groth16',
      mode: 'single-thread',
    },
    measurements: {
      totalWallMs: 0,
      peakRss: {
        available: false,
        reason: 'fixture parser input does not execute a prover',
      },
    },
  };
  const mutatedEvidence = mutateEvidence(structuredClone(evidence));
  const rawEvidenceBytes = Buffer.from(canonicalizeJcs(mutatedEvidence));
  await addPinnedArtifact(
    subject,
    'pf10-raw-qualification-evidence',
    'qualification/raw-evidence.json',
    rawEvidenceBytes,
  );
  // The canonical record is deliberately a distinct manifest artifact, bound
  // to the raw artifact digest. In mutation cases it remains well-formed so
  // the test proves malformed raw evidence is rejected before this compact
  // record could mask it.
  const qualificationRecord = {
    schema: PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
    qualificationSchema: evidence.schema,
    evidenceClass: evidence.evidenceClass,
    identity: {
      profileId: evidence.identity.profileId,
      instanceId: evidence.identity.instanceId,
      maximumLiveNotes: evidence.identity.maximumLiveNotes,
      denominationSats: evidence.identity.denominationSats,
    },
    claims: {
      developmentKey: evidence.claims.developmentKey,
      finalKey: evidence.claims.finalKey,
      bchVm: evidence.claims.bchVm,
      production: evidence.claims.production,
    },
    sourceArtifacts: {
      r1csSha256: evidence.sourceArtifacts.r1cs.sha256,
      witnessWasmSha256: evidence.sourceArtifacts.wasm.sha256,
      verificationKeySha256:
        evidence.sourceArtifacts.verificationKey.sha256,
      developmentZkeySha256:
        evidence.sourceArtifacts.developmentZkey.sha256,
    },
    rawEvidenceSha256: hash(rawEvidenceBytes),
    actions: Object.fromEntries(
      ['deposit', 'transfer', 'withdrawal'].map((name) => [name, {
        witnessValid: evidence.actions[name].witnessValid,
        proofVerified: evidence.actions[name].proofVerified,
      }]),
    ),
  };
  await addPinnedArtifact(
    subject,
    'pf10-qualification-record',
    'qualification/canonical-record.json',
    Buffer.from(canonicalizeJcs(qualificationRecord)),
  );
  await addPinnedArtifact(
    subject,
    'pf10-runtime-material',
    'runtime/pf10-runtime-material.json',
    Buffer.from(canonicalizeJcs({
      schema: PF10_RUNTIME_ARTIFACT_SCHEMA,
      eligibility: 'development-only',
      profileId: subject.descriptor.profileId,
      instanceId: subject.descriptor.instanceId,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      profileArtifacts: {
        profileCoreArtifactId: profileArtifacts.profileCore,
        profilePackageArtifactId: profileArtifacts.profilePackage,
        baseVerifierManifestArtifactId: profileArtifacts.baseVerifierManifest,
        topologySpecArtifactId: profileArtifacts.topologySpec,
        toolchainManifestArtifactId: profileArtifacts.toolchainManifest,
      },
      attestationArtifacts: {
        circuitBuildAttestationArtifactId:
          attestationArtifacts.circuitBuildAttestation,
        developmentSetupAttestationArtifactId:
          attestationArtifacts.developmentSetupAttestation,
        relationManifestArtifactId: attestationArtifacts.relationManifest,
      },
      setupArtifacts: {
        circuitSymbolsArtifactId: setupArtifacts.circuitSymbols,
        initialProvingKeyArtifactId: setupArtifacts.initialProvingKey,
        powersOfTauArtifactId: setupArtifacts.powersOfTau,
      },
      proofArtifacts: {
        provingKeyArtifactId: proofArtifacts.provingKey,
        r1csArtifactId: proofArtifacts.r1cs,
        verificationKeyArtifactId: proofArtifacts.verificationKey,
        witnessWasmArtifactId: proofArtifacts.wasm,
      },
      unlockArtifacts: {
        executorBodyArtifactId: unlockArtifacts.executorBody,
        exactMsmRedeemArtifactIds: unlockArtifacts.exactMsmRedeems,
        fixedCarrierPadArtifactIds: unlockArtifacts.fixedCarrierPads,
        fusedRedeemArtifactId: unlockArtifacts.fusedRedeem,
        terminalRedeemArtifactId: unlockArtifacts.terminalRedeem,
      },
      qualificationEvidenceArtifactId: 'pf10-qualification-record',
      rawQualificationEvidenceArtifactId: 'pf10-raw-qualification-evidence',
      libauthEvidenceArtifactId,
    })),
  );
  return Object.freeze({
    evidence: mutatedEvidence,
    qualificationRecord: Object.freeze(qualificationRecord),
    profileArtifacts: Object.freeze({ ...profileArtifacts }),
    attestationArtifacts: Object.freeze({ ...attestationArtifacts }),
    alternateTopologySpec,
    setupArtifacts: Object.freeze({ ...setupArtifacts }),
    proofArtifacts: Object.freeze({ ...proofArtifacts }),
    libauthEvidenceArtifactId,
    libauthEvidence: Object.freeze(libauthEvidence),
    runtimeMaterialSha256: runtimeMaterial.materialSha256,
  });
};

const mutatePf10LibauthEvidence = async (subject, mutate) => {
  const bytes = await artifactBytes(subject, 'pf10-libauth-evidence');
  const evidence = JSON.parse(bytes.toString('utf8'));
  const replacement = mutate(evidence);
  await replacePinnedArtifact(
    subject,
    'pf10-libauth-evidence',
    Buffer.from(canonicalizeJcs(replacement === undefined ? evidence : replacement)),
  );
};
const unsignedPf10RuntimeReferenceInput = async (subject) => {
  const runtimeArtifact = JSON.parse((await artifactBytes(
    subject,
    'pf10-runtime-material',
  )).toString('utf8'));
  const referencedArtifactIds = [
    ...Object.values(runtimeArtifact.profileArtifacts),
    ...Object.values(runtimeArtifact.attestationArtifacts),
    ...Object.values(runtimeArtifact.setupArtifacts),
    ...Object.values(runtimeArtifact.proofArtifacts),
    runtimeArtifact.unlockArtifacts.executorBodyArtifactId,
    ...runtimeArtifact.unlockArtifacts.exactMsmRedeemArtifactIds,
    ...runtimeArtifact.unlockArtifacts.fixedCarrierPadArtifactIds,
    runtimeArtifact.unlockArtifacts.fusedRedeemArtifactId,
    runtimeArtifact.unlockArtifacts.terminalRedeemArtifactId,
    runtimeArtifact.qualificationEvidenceArtifactId,
    runtimeArtifact.rawQualificationEvidenceArtifactId,
    runtimeArtifact.libauthEvidenceArtifactId,
  ];
  return {
    profileId: subject.descriptor.profileId,
    instanceId: subject.descriptor.instanceId,
    runtimeArtifact,
    artifactEntries: Object.fromEntries(referencedArtifactIds.map((id) => [
      id,
      { id, sha256: artifactHash(subject, id) },
    ])),
  };
};
const rejects = async (operation, pattern) => await assert.rejects(operation, pattern);
const load = async (subject, options = {}) => loadV2InstanceDescriptor({
  descriptorPath: subject.descriptorPath,
  profileCore: subject.profileCore,
  trustedSigners: subject.trustedSigners,
  ...options,
});

test('requires each profile-core base verifier artifact to be present and hash-identical in the signed manifest', async (t) => {
  await t.test('missing or unknown base artifact id', async () => {
    const subject = await fixture();
    await rebindProfileCore(subject, undefined, (profileCore) => ({
      ...profileCore,
      baseVerifierArtifacts: [
        { id: 'absent-base', sha256: '00'.repeat(32) },
        profileCore.baseVerifierArtifacts[1],
      ],
    }));
    await rejects(
      () => load(subject),
      /profile base verifier artifact absent-base/i,
    );
  });

  await t.test('manifest-present base artifact hash mismatch', async () => {
    const subject = await fixture();
    await rebindProfileCore(subject, undefined, (profileCore) => ({
      ...profileCore,
      baseVerifierArtifacts: [
        { id: 'base-carrier', sha256: '00'.repeat(32) },
        profileCore.baseVerifierArtifacts[1],
      ],
    }));
    await rejects(
      () => load(subject),
      /profile base verifier artifact base-carrier/i,
    );
  });
});

test('emits distinct raw and canonical PF10 qualification artifacts with exact bindings', async () => {
  const subject = await fixture({
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  });
  const envelope = await addPf10QualificationEnvelope(subject);
  const artifact = (id) => {
    const entry = subject.manifest.artifacts.find((value) => value.id === id);
    assert.notEqual(entry, undefined);
    return entry;
  };
  const raw = artifact('pf10-raw-qualification-evidence');
  const canonical = artifact('pf10-qualification-record');
  assert.notEqual(raw.id, canonical.id);
  assert.notEqual(raw.path, canonical.path);
  const rawBytes = await readFile(path.join(subject.directory, raw.path));
  const canonicalRecord = JSON.parse(await readFile(
    path.join(subject.directory, canonical.path),
    'utf8',
  ));
  assert.equal(canonicalRecord.schema, PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA);
  assert.equal(canonicalRecord.rawEvidenceSha256, hash(rawBytes));
  assert.deepEqual(canonicalRecord.identity, envelope.evidence.identity);
  assert.deepEqual(canonicalRecord.actions, Object.fromEntries(
    ['deposit', 'transfer', 'withdrawal'].map((name) => [name, {
      witnessValid: true,
      proofVerified: true,
    }]),
  ));
  assert.deepEqual(canonicalRecord.sourceArtifacts, {
    r1csSha256: envelope.evidence.sourceArtifacts.r1cs.sha256,
    witnessWasmSha256: envelope.evidence.sourceArtifacts.wasm.sha256,
    verificationKeySha256:
      envelope.evidence.sourceArtifacts.verificationKey.sha256,
    developmentZkeySha256:
      envelope.evidence.sourceArtifacts.developmentZkey.sha256,
  });
  const validatedQualification =
    validateV2DevelopmentPf10QualificationArtifacts({
      canonicalRecordBytes: Buffer.from(canonicalizeJcs(canonicalRecord)),
      rawEvidenceBytes: rawBytes,
      profileId: envelope.evidence.identity.profileId,
      instanceId: envelope.evidence.identity.instanceId,
      maximumLiveNotes: envelope.evidence.identity.maximumLiveNotes,
      denominationSats: envelope.evidence.identity.denominationSats,
      profileCoreSha256: artifact('profile-core').sha256,
      proofArtifactHashes: {
        provingKey:
          envelope.evidence.sourceArtifacts.developmentZkey.sha256,
        r1cs: envelope.evidence.sourceArtifacts.r1cs.sha256,
        verificationKey:
          envelope.evidence.sourceArtifacts.verificationKey.sha256,
        wasm: envelope.evidence.sourceArtifacts.wasm.sha256,
      },
    });
  assert.equal(
    validatedQualification.rawEvidenceSha256,
    hash(rawBytes),
  );
  assert.equal(
    validatedQualification.canonicalRecordSha256,
    canonical.sha256,
  );
  assert.throws(
    () => validateV2DevelopmentPf10QualificationArtifacts({
      canonicalRecordBytes: Buffer.from(canonicalizeJcs({
        ...canonicalRecord,
        rawEvidenceSha256: '00'.repeat(32),
      })),
      rawEvidenceBytes: rawBytes,
      profileId: envelope.evidence.identity.profileId,
      instanceId: envelope.evidence.identity.instanceId,
      maximumLiveNotes: envelope.evidence.identity.maximumLiveNotes,
      denominationSats: envelope.evidence.identity.denominationSats,
      profileCoreSha256: artifact('profile-core').sha256,
      proofArtifactHashes: {
        provingKey:
          envelope.evidence.sourceArtifacts.developmentZkey.sha256,
        r1cs: envelope.evidence.sourceArtifacts.r1cs.sha256,
        verificationKey:
          envelope.evidence.sourceArtifacts.verificationKey.sha256,
        wasm: envelope.evidence.sourceArtifacts.wasm.sha256,
      },
    }),
    /differs from its signed raw v4 evidence/u,
  );
  const runtime = JSON.parse(await readFile(path.join(
    subject.directory,
    artifact('pf10-runtime-material').path,
  ), 'utf8'));
  assert.equal(runtime.schema, PF10_RUNTIME_ARTIFACT_SCHEMA);
  assert.deepEqual(runtime.profileArtifacts, {
    profileCoreArtifactId: envelope.profileArtifacts.profileCore,
    profilePackageArtifactId: envelope.profileArtifacts.profilePackage,
    baseVerifierManifestArtifactId:
      envelope.profileArtifacts.baseVerifierManifest,
    topologySpecArtifactId: envelope.profileArtifacts.topologySpec,
    toolchainManifestArtifactId: envelope.profileArtifacts.toolchainManifest,
  });
  assert.deepEqual(runtime.attestationArtifacts, {
    circuitBuildAttestationArtifactId:
      envelope.attestationArtifacts.circuitBuildAttestation,
    developmentSetupAttestationArtifactId:
      envelope.attestationArtifacts.developmentSetupAttestation,
    relationManifestArtifactId: envelope.attestationArtifacts.relationManifest,
  });
  assert.deepEqual(runtime.setupArtifacts, {
    circuitSymbolsArtifactId: envelope.setupArtifacts.circuitSymbols,
    initialProvingKeyArtifactId: envelope.setupArtifacts.initialProvingKey,
    powersOfTauArtifactId: envelope.setupArtifacts.powersOfTau,
  });
  assert.equal(runtime.qualificationEvidenceArtifactId, canonical.id);
  assert.equal(runtime.rawQualificationEvidenceArtifactId, raw.id);
  assert.equal(
    runtime.libauthEvidenceArtifactId,
    envelope.libauthEvidenceArtifactId,
  );
  assert.equal(
    envelope.libauthEvidence.identity.runtimeMaterialSha256,
    envelope.runtimeMaterialSha256,
  );
});

test('requires one distinct semantic Libauth evidence artifact for PF10 runtime-v3', async (t) => {
  const runtimeCases = [
    ['missing Libauth evidence reference', (runtime) => {
      delete runtime.libauthEvidenceArtifactId;
    }, /PF10 runtime artifact has missing or unknown/],
    ['Libauth evidence aliases raw qualification', (runtime) => {
      runtime.libauthEvidenceArtifactId = runtime.rawQualificationEvidenceArtifactId;
    }, /PF10 runtime artifact references must be unique/],
  ];
  for (const [name, mutate, expected] of runtimeCases) {
    await t.test(name, async () => {
      const subject = await fixture({
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      });
      await addPf10QualificationEnvelope(subject);
      const runtime = JSON.parse(await artifactBytes(
        subject,
        'pf10-runtime-material',
      ));
      mutate(runtime);
      await replacePinnedArtifact(
        subject,
        'pf10-runtime-material',
        Buffer.from(canonicalizeJcs(runtime)),
      );
      const descriptor = await load(subject);
      await rejects(
        () => deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
        expected,
      );
    });
  }

  const evidenceCases = [
    ['malformed evidence', (evidence) => ({ schema: evidence.schema })],
    ['profile drift', (evidence) => {
      evidence.identity.profileId = '00'.repeat(32);
      return evidence;
    }],
    ['instance drift', (evidence) => {
      evidence.identity.instanceId = '00'.repeat(32);
      return evidence;
    }],
    ['proof artifact drift', (evidence) => {
      evidence.identity.proofArtifactHashes.r1cs = '00'.repeat(32);
      return evidence;
    }],
    ['runtime digest drift', (evidence) => {
      evidence.identity.runtimeMaterialSha256 = '00'.repeat(32);
      return evidence;
    }],
  ];
  for (const [name, mutate] of evidenceCases) {
    await t.test(name, async () => {
      const subject = await fixture({
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      });
      await addPf10QualificationEnvelope(subject);
      await mutatePf10LibauthEvidence(subject, mutate);
      const descriptor = await load(subject);
      await rejects(
        () => deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
        /PF10 per-instance Libauth evidence is invalid/i,
      );
    });
  }
});

test('unsigned staged PF10 runtime validation returns only semantic digest and eligibility', async () => {
  const subject = await fixture({
    signed: false,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  });
  const envelope = await addPf10QualificationEnvelope(subject);
  const staged = await deriveV2PreparedPackageRuntimeMaterialSha256({
    profileCore: subject.profileCore,
    unsignedDescriptorPath: subject.descriptorPath,
  });
  assert.deepEqual(Object.keys(staged).sort(), [
    'eligibility',
    'runtimeMaterialSha256',
    'schema',
  ]);
  assert.equal(staged.eligibility, 'development-only');
  assert.equal(staged.runtimeMaterialSha256, envelope.runtimeMaterialSha256);
  assert.equal(Object.hasOwn(staged, 'runtimeMaterial'), false);
  assert.equal(Object.hasOwn(staged, 'proofArtifacts'), false);
  assert.throws(
    () => deriveV2Pf10StoreRuntimeMaterialsSha256(staged),
    /runtime resolution returned by deriveV2Pf10RuntimeFromValidatedDescriptor/,
  );
});

test('unsigned PF10 runtime reference validation is exact and complete', async (t) => {
  const subject = await fixture({
    signed: false,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  });
  await addPf10QualificationEnvelope(subject);
  const input = await unsignedPf10RuntimeReferenceInput(subject);

  await t.test('returns the full normalized 27-ID development topology', () => {
    const result = validateV2UnsignedPf10RuntimeArtifactReferences(input);
    assert.deepEqual(Object.keys(result).sort(), [
      'eligibility',
      'referencedArtifactCount',
      'referencedArtifactIds',
      'references',
      'schema',
    ]);
    assert.equal(result.schema, PF10_UNSIGNED_RUNTIME_REFERENCE_VALIDATION_SCHEMA);
    assert.equal(result.eligibility, 'development-only');
    assert.equal(result.referencedArtifactCount, PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT);
    assert.equal(result.referencedArtifactIds.length, PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT);
    assert.equal(
      new Set(result.referencedArtifactIds).size,
      PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT,
    );
    assert.equal(
      result.referencedArtifactIds.includes('pf10-runtime-material'),
      false,
    );
    assert.deepEqual(result.references.proofArtifacts, {
      provingKey: input.runtimeArtifact.proofArtifacts.provingKeyArtifactId,
      r1cs: input.runtimeArtifact.proofArtifacts.r1csArtifactId,
      verificationKey:
        input.runtimeArtifact.proofArtifacts.verificationKeyArtifactId,
      wasm: input.runtimeArtifact.proofArtifacts.witnessWasmArtifactId,
    });
  });

  await t.test('rejects a missing referenced artifact entry', () => {
    const malformed = structuredClone(input);
    delete malformed.artifactEntries[
      malformed.runtimeArtifact.proofArtifacts.r1csArtifactId
    ];
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences(malformed),
      /PF10 R1CS is not a signed manifest artifact/,
    );
  });

  await t.test('rejects a reused runtime artifact ID', () => {
    const malformed = structuredClone(input);
    malformed.runtimeArtifact.proofArtifacts.r1csArtifactId =
      malformed.runtimeArtifact.proofArtifacts.witnessWasmArtifactId;
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences(malformed),
      /PF10 runtime artifact references must be unique/,
    );
  });

  await t.test('rejects wrong identity and topology', () => {
    const wrongIdentity = structuredClone(input);
    wrongIdentity.runtimeArtifact.instanceId = '00'.repeat(32);
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences(wrongIdentity),
      /identity, topology, or eligibility is invalid/,
    );
    const wrongTopology = structuredClone(input);
    wrongTopology.runtimeArtifact.topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID;
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences(wrongTopology),
      /identity, topology, or eligibility is invalid/,
    );
  });

  await t.test('rejects unreferenced supplied entries', () => {
    const malformed = structuredClone(input);
    malformed.artifactEntries['unreferenced-artifact'] = {
      id: 'unreferenced-artifact',
      sha256: '00'.repeat(32),
    };
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences(malformed),
      /must contain exactly the 27 referenced artifact IDs/,
    );
  });

  await t.test('rejects unknown wrapper properties', () => {
    assert.throws(
      () => validateV2UnsignedPf10RuntimeArtifactReferences({
        ...input,
        unexpected: true,
      }),
      /unsigned PF10 runtime reference validation options has missing or unknown properties/,
    );
  });
});

test('rejects v2 runtime profile, attestation, and setup tampering before qualification', async (t) => {
  const cases = [
    ['missing profile package', (runtime) => {
      delete runtime.profileArtifacts.profilePackageArtifactId;
    }, /PF10 runtime profileArtifacts has missing or unknown/],
    ['profile alias', (runtime) => {
      runtime.profileArtifacts.profilePackageArtifactId =
        runtime.profileArtifacts.profileCoreArtifactId;
    }, /PF10 runtime artifact references must be unique/],
    ['attestation alias', (runtime) => {
      runtime.attestationArtifacts.relationManifestArtifactId =
        runtime.attestationArtifacts.circuitBuildAttestationArtifactId;
    }, /PF10 runtime artifact references must be unique/],
    ['missing setup artifact', (runtime) => {
      delete runtime.setupArtifacts.powersOfTauArtifactId;
    }, /PF10 runtime setupArtifacts has missing or unknown/],
    ['setup/proof alias', (runtime) => {
      runtime.setupArtifacts.circuitSymbolsArtifactId =
        runtime.proofArtifacts.r1csArtifactId;
    }, /PF10 runtime artifact references must be unique/],
    ['package/provenance semantic drift', (runtime, envelope) => {
      runtime.profileArtifacts.topologySpecArtifactId =
        envelope.alternateTopologySpec;
    }, /PF10 generated profile artifact topologySpec differs/],
  ];
  for (const [name, mutate, expected] of cases) {
    await t.test(name, async () => {
      const subject = await fixture({
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      });
      const envelope = await addPf10QualificationEnvelope(subject);
      const runtimeEntry = subject.manifest.artifacts.find(
        (entry) => entry.id === 'pf10-runtime-material',
      );
      assert.notEqual(runtimeEntry, undefined);
      const runtime = JSON.parse(await readFile(
        path.join(subject.directory, runtimeEntry.path),
        'utf8',
      ));
      mutate(runtime, envelope);
      await replacePinnedArtifact(
        subject,
        'pf10-runtime-material',
        Buffer.from(canonicalizeJcs(runtime)),
      );
      const descriptor = await load(subject);
      await rejects(
        () => deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
        expected,
      );
    });
  }
});

test('rejects every malformed PF10 development-qualification binding before runtime derivation', async (t) => {
  const cases = [
    ['legacy schema', (value) => {
      value.schema = 'shieldkit-v2-direct-development-groth16-qualification-v3';
      return value;
    }],
    ['unknown evidence field', (value) => ({ ...value, unbound: true })],
    ['development key disabled', (value) => {
      value.claims.developmentKey = false;
      return value;
    }],
    ['final key claimed', (value) => {
      value.claims.finalKey = true;
      return value;
    }],
    ['BCH VM claimed', (value) => {
      value.claims.bchVm = true;
      return value;
    }],
    ['production claimed', (value) => {
      value.claims.production = true;
      return value;
    }],
    ['profile identity mismatch', (value) => {
      value.identity.profileId = '00'.repeat(32);
      return value;
    }],
    ['instance identity mismatch', (value) => {
      value.identity.instanceId = '00'.repeat(32);
      return value;
    }],
    ['maximum live notes mismatch', (value) => {
      value.identity.maximumLiveNotes = '8';
      return value;
    }],
    ['missing action', (value) => {
      delete value.actions.withdrawal;
      return value;
    }],
    ['unknown action', (value) => ({
      ...value,
      actions: { ...value.actions, unexpected: value.actions.deposit },
    })],
    ['witness not verified', (value) => {
      value.actions.transfer.witnessValid = false;
      return value;
    }],
    ['proof not verified', (value) => {
      value.actions.transfer.proofVerified = false;
      return value;
    }],
    ['R1CS source hash mismatch', (value) => {
      value.sourceArtifacts.r1cs.sha256 = '00'.repeat(32);
      return value;
    }],
    ['WASM source hash mismatch', (value) => {
      value.sourceArtifacts.wasm.sha256 = '00'.repeat(32);
      return value;
    }],
    ['proving-key source hash mismatch', (value) => {
      value.sourceArtifacts.developmentZkey.sha256 = '00'.repeat(32);
      return value;
    }],
    ['verification-key source hash mismatch', (value) => {
      value.sourceArtifacts.verificationKey.sha256 = '00'.repeat(32);
      return value;
    }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const subject = await fixture({
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      });
      await addPf10QualificationEnvelope(subject, mutate);
      const descriptor = await load(subject);
      await rejects(
        () => deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
        /PF10.*qualification/i,
      );
    });
  }
});

test('loads only a fully pinned canonical descriptor and artifact set', async () => {
  const subject = await fixture();
  const loaded = await load(subject);
  assert.equal(loaded.profileId, subject.descriptor.profileId); assert.equal(loaded.instanceId, subject.descriptor.instanceId);
  assert.equal(loaded.stateNftCategory, loaded.instanceId); assert.equal(loaded.initialState.length, 128);
  assert.equal(loaded.artifacts.size, 22);
  assert.equal(loaded.artifacts.get('verification-key').data, undefined);
  assert.equal(loaded.artifacts.get('verification-key').sha256, hash('vk'));
  assert.equal(loaded.artifacts.get('state-lock').data.length > 0, true);
  assert.deepEqual(V2_INSTANCE_VERIFIER_ROLES, PF11_VERIFIER_ROLES);
  assert.equal(
    loaded.finalLocks.topology.id,
    DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  );
  assert.deepEqual(
    loaded.finalLocks.verifiers.map(({ role }) => role),
    PF11_VERIFIER_ROLES,
  );
  assert.equal(loaded.finalLocks.binding.baseSats, '1200');
  assert.equal(loaded.finalLocks.binding.redeemArtifactId, 'binding-redeem-a');
  assert.equal(loaded.finalLocks.state.helperArtifactId, 'state-helper');
  assert.equal(loaded.attestation.signerId, 'release-signer');
  assert.equal(loaded.descriptor.sha256, hash(await readFile(subject.descriptorPath)));
  const attestation = JSON.parse(descriptorAttestationBytes({
    descriptor: subject.descriptor,
    canonicalManifestBytes: await readFile(
      path.join(subject.directory, 'manifest.json'),
    ),
    signature: subject.descriptor.signature,
  }).toString('utf8'));
  assert.deepEqual(Object.keys(attestation).sort(), [
    'descriptorJcs',
    'domain',
    'manifestSha256',
    'signer',
    'version',
  ]);
  assert.equal(Object.hasOwn(attestation, 'manifestJcs'), false);
});

test('streams large opaque artifacts without retaining bytes while preserving structural artifacts', async () => {
  const subject = await fixture();
  const opaque = Buffer.alloc(4 * 1024 * 1024, 0x5a);
  await addPinnedArtifact(
    subject,
    'proving-key',
    'proof/action.zkey',
    opaque,
  );
  const loaded = await load(subject);
  const provingKey = loaded.artifacts.get('proving-key');
  assert.equal(provingKey.data, undefined);
  assert.equal(provingKey.sha256, hash(opaque));
  assert.equal(provingKey.filename, path.join(subject.directory, 'proof/action.zkey'));
  const stateLock = loaded.artifacts.get('state-lock');
  assert.deepEqual(stateLock.data, await readFile(stateLock.filename));

  await writeFile(provingKey.filename, Buffer.alloc(opaque.length, 0x5b));
  await rejects(() => load(subject), /SHA-256 pin mismatch/);
});

test('loads and pins the distinct signed PF10 topology without PF11 reinterpretation', async () => {
  const subject = await fixture({
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  });
  const loaded = await load(subject);
  assert.equal(
    loaded.finalLocks.topology.id,
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  );
  assert.deepEqual(
    loaded.finalLocks.verifiers.map(({ role }) => role),
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  );
  assert.equal(loaded.artifacts.size, 21);
  const pins = deriveV2SettlementPinsFromValidatedDescriptor(loaded);
  assert.equal(pins.topologyId, DIRECT_V2_PF10_FUSED_TOPOLOGY_ID);
  assert.deepEqual(pins.verifierRoles, DIRECT_V2_PF10_FUSED_VERIFIER_ROLES);
  assert.equal(pins.verifierCarriers.length, 10);
  assert.throws(
    () => derivePf11SettlementPinsFromValidatedDescriptor(loaded),
    /signed PF11 oracle topology/,
  );
  await assert.rejects(
    () => deriveV2Pf10RuntimeFromValidatedDescriptor(loaded),
    /missing pf10-runtime-material/,
  );
  await assert.rejects(
    () => deriveV2Pf10RuntimeFromValidatedDescriptor({ ...loaded }),
    /validated by loadV2InstanceDescriptor/,
  );
  assert.throws(
    () => deriveV2Pf10StoreRuntimeMaterialsSha256({
      schema: 'shieldkit-v2-direct-pf10-runtime-resolution-v1',
      runtimeMaterial: { materialSha256: '00'.repeat(32) },
    }),
    /runtime resolution returned by deriveV2Pf10RuntimeFromValidatedDescriptor/,
  );
});

test('derives exact settlement pins only from a validated descriptor', async () => {
  const subject = await fixture();
  const loaded = await load(subject);
  const pins = derivePf11SettlementPinsFromValidatedDescriptor(loaded);
  assert.equal(pins.verifierCarriers.length, 11);
  assert.equal(pins.verifierCarriers[0].baseValueSats, '1000');
  assert.deepEqual(pins.bindingLockingBytecode, bindingLockA);
  assert.deepEqual(pins.bindingRedeemBytecode, bindingRedeemA);
  assert.deepEqual(
    pins.stateLockingBytecode,
    loaded.artifacts.get('state-lock').data,
  );
  pins.bindingLockingBytecode[0] ^= 1;
  assert.deepEqual(
    derivePf11SettlementPinsFromValidatedDescriptor(loaded)
      .bindingLockingBytecode,
    bindingLockA,
  );
  assert.throws(
    () => derivePf11SettlementPinsFromValidatedDescriptor({ ...loaded }),
    /validated by loadV2InstanceDescriptor/,
  );
});

test('derives the native recovery scanner only from an exact signed descriptor artifact pair', async (t) => {
  // This profile intentionally has one supported scanner target. There are no
  // platform skips: a non-Linux/x64 test runner must fail closed.
  assert.equal(process.platform, 'linux');
  assert.equal(process.arch, 'x64');

  await t.test('accepts the exact branded descriptor and returns immutable binary pins', async () => {
    const subject = await fixture();
    const scanner = await addRecoveryScannerArtifacts(subject);
    const loaded = await load(subject);
    const resolved = await deriveV2RecoveryScannerFromValidatedDescriptor(loaded);
    assert.equal(resolved.target, 'linux-x64');
    assert.equal(resolved.binaryPath, scanner.binaryPath);
    assert.equal(resolved.binarySha256, hash(scanner.binary));
    assert.equal(resolved.binaryBytes, scanner.binary.length);
    assert.equal((await lstat(resolved.binaryPath)).mode & 0o111, 0o111);
    assert.equal(Object.isFrozen(resolved), true);
    const executionPin = deriveV2RecoveryScannerExecutionPin(resolved);
    assert.deepEqual(executionPin, {
      binaryPath: scanner.binaryPath,
      binarySha256: hash(scanner.binary),
      binaryBytes: scanner.binary.length,
    });
    assert.equal(Object.isFrozen(executionPin), true);
    assert.throws(
      () => deriveV2RecoveryScannerExecutionPin({ ...resolved }),
      /resolution derived from a validated descriptor/,
    );
    await assert.rejects(
      () => deriveV2RecoveryScannerFromValidatedDescriptor({ ...loaded }),
      /validated by loadV2InstanceDescriptor/,
    );
  });

  await t.test('requires both canonical signed outer-manifest artifacts', async () => {
    const noMetadata = await fixture();
    await addPinnedArtifact(
      noMetadata,
      RECOVERY_SCANNER_BINARY_ARTIFACT_ID,
      'recovery/recovery-scanner-linux-x64',
      Buffer.from('#!/bin/sh\nexit 0\n'),
    );
    await chmod(
      path.join(noMetadata.directory, 'recovery/recovery-scanner-linux-x64'),
      0o755,
    );
    const noMetadataLoaded = await load(noMetadata);
    await assert.rejects(
      () => deriveV2RecoveryScannerFromValidatedDescriptor(noMetadataLoaded),
      /recovery-scanner-manifest/,
    );

    const noBinary = await fixture();
    const metadata = recoveryScannerManifest(Buffer.from('#!/bin/sh\nexit 0\n'));
    await addPinnedArtifact(
      noBinary,
      RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
      'recovery/recovery-scanner-manifest.json',
      Buffer.from(canonicalizeJcs(metadata)),
    );
    const noBinaryLoaded = await load(noBinary);
    await assert.rejects(
      () => deriveV2RecoveryScannerFromValidatedDescriptor(noBinaryLoaded),
      /recovery-scanner-linux-x64/,
    );
  });

  await t.test(
    'rejects noncanonical and nonexact scanner metadata',
    async (metadataTest) => {
      const cases = [
        ['noncanonical JCS', async (subject) => {
          const artifact = subject.manifest.artifacts.find(
            (entry) => entry.id === RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
          );
          assert.notEqual(artifact, undefined);
          const bytes = JSON.parse(await readFile(
            path.join(subject.directory, artifact.path),
            'utf8',
          ));
          await replacePinnedArtifact(
            subject,
            RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
            Buffer.from(JSON.stringify(bytes, null, 2)),
          );
        }, /RFC8785|canonical/],
        ['unknown field', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            unexpected: true,
          }));
        }, /missing or unknown/],
        ['alternate platform', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            target: 'darwin-arm64',
          }));
        }, /linux-x64/],
        ['alternate binary artifact provenance', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            binaryArtifactId: 'verification-key',
          }));
        }, /recovery-scanner-linux-x64|binaryArtifactId/],
        ['unsupported schema', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            schema: 'shieldkit-v2-recovery-scanner-artifact-v0',
          }));
        }, /schema is unsupported/],
        ['noncanonical source revision', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            sourceRevision: 'A'.repeat(40),
          }));
        }, /Git object ID/],
        ['unsupported eligibility', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            eligibility: 'production',
          }));
        }, /eligibility is unsupported/],
        ['protocol ABI drift', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            protocolSchemas: metadata.protocolSchemas.slice(1),
          }));
        }, /protocol schemas/],
        ['binary hash mismatch', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            binarySha256: '00'.repeat(32),
          }));
        }, /SHA-256|binarySha256/],
        ['binary byte count mismatch', async (subject) => {
          await mutateRecoveryScannerManifest(subject, (metadata) => ({
            ...metadata,
            binaryBytes: metadata.binaryBytes + 1,
          }));
        }, /binaryBytes|byte count/],
      ];
      for (const [name, mutate, expected] of cases) {
        await metadataTest.test(name, async () => {
          const subject = await fixture();
          await addRecoveryScannerArtifacts(subject);
          await mutate(subject);
          const loaded = await load(subject);
          await assert.rejects(
            () => deriveV2RecoveryScannerFromValidatedDescriptor(loaded),
            expected,
          );
        });
      }
    },
  );

  await t.test('rejects descriptor path escape before scanner resolution', async () => {
    const subject = await fixture();
    await addRecoveryScannerArtifacts(subject);
    const artifact = subject.manifest.artifacts.find(
      (entry) => entry.id === RECOVERY_SCANNER_BINARY_ARTIFACT_ID,
    );
    assert.notEqual(artifact, undefined);
    artifact.path = '../recovery-scanner-linux-x64';
    const manifestBytes = Buffer.from(canonicalizeJcs(subject.manifest));
    await writeFile(path.join(subject.directory, 'manifest.json'), manifestBytes);
    subject.descriptor.manifest.sha256 = hash(manifestBytes);
    await resign(subject);
    await assert.rejects(() => load(subject), /traversal|relative slash-separated/);
  });

  await t.test('rechecks executable identity and hash after descriptor load', async (t) => {
    const cases = [
      ['not executable', async (scanner) => {
        await chmod(scanner.binaryPath, 0o644);
      }, /executable/],
      ['content hash changed', async (scanner) => {
        await writeFile(scanner.binaryPath, '#!/bin/sh\necho changed\n');
        await chmod(scanner.binaryPath, 0o755);
      }, /SHA-256|changed while reading|byte count/],
      ['hardlink substituted', async (scanner, subject) => {
        const sibling = path.join(subject.directory, 'recovery/scanner-hardlink');
        await link(scanner.binaryPath, sibling);
        await unlink(scanner.binaryPath);
        await link(sibling, scanner.binaryPath);
      }, /regular non-symlink|changed while/],
      ['symlink substituted', async (scanner) => {
        await unlink(scanner.binaryPath);
        await symlink('/bin/true', scanner.binaryPath);
      }, /regular non-symlink|changed while/],
    ];
    for (const [name, mutate, expected] of cases) {
      await t.test(name, async () => {
        const subject = await fixture();
        const scanner = await addRecoveryScannerArtifacts(subject);
        const loaded = await load(subject);
        await mutate(scanner, subject);
        await assert.rejects(
          () => deriveV2RecoveryScannerFromValidatedDescriptor(loaded),
          expected,
        );
      });
    }
  });
});

test('fails closed before exposing files on path, schema, pin, and descriptor binding drift', async () => {
  for (const mutate of [
    (s) => { s.descriptor.manifest.path = '../manifest.json'; }, (s) => { s.descriptor.manifest.path = '/tmp/manifest.json'; },
    (s) => { s.descriptor.extra = true; }, (s) => { s.descriptor.profileId = 'AA'.repeat(32); }, (s) => { s.descriptor.profileId = '00'.repeat(32); },
    (s) => { s.descriptor.instanceId = '00'.repeat(32); }, (s) => { s.descriptor.stateNftCategory = '00'.repeat(32); },
    (s) => { s.descriptor.initialState = '00'.repeat(128); }, (s) => { s.descriptor.manifest.sha256 = '00'.repeat(32); },
    (s) => { s.descriptor.finalLocks.topologyId = DIRECT_V2_PF10_FUSED_TOPOLOGY_ID; },
    (s) => { s.descriptor.finalLocks.verifiers[0].lockingArtifactId = 'missing'; }, (s) => { s.descriptor.genesis.outpointIndex = -1; }, (s) => { s.descriptor.genesis.transactionId = 'zz'.repeat(32); },
  ]) { const subject = await fixture(); mutate(subject); await rewrite(subject); await rejects(() => load(subject), /instance descriptor|artifact manifest|profileId|initialState|ArtifactId|outpoint/i); }
  const subject = await fixture(); await writeFile(path.join(subject.directory, 'locks', 'state.bin'), 'drift');
  await rejects(() => load(subject), /SHA-256 pin mismatch/);
  const unused = await fixture();
  await writeFile(path.join(unused.directory, 'proof', 'vk.bin'), 'drift');
  await rejects(() => load(unused), /SHA-256 pin mismatch/);
});

test('rejects duplicate and unknown manifest keys, noncanonical bytes, and symlink artifacts', async () => {
  const duplicate = await fixture(); duplicate.manifest.artifacts[1].id = duplicate.manifest.artifacts[0].id;
  const duplicateBytes = Buffer.from(canonicalizeJcs(duplicate.manifest)); await writeFile(path.join(duplicate.directory, 'manifest.json'), duplicateBytes); duplicate.descriptor.manifest.sha256 = hash(duplicateBytes); await rewrite(duplicate);
  await rejects(() => load(duplicate), /sorted and unique/);
  const unknown = await fixture(); unknown.manifest.extra = true; const unknownBytes = Buffer.from(canonicalizeJcs(unknown.manifest)); await writeFile(path.join(unknown.directory, 'manifest.json'), unknownBytes); unknown.descriptor.manifest.sha256 = hash(unknownBytes); await rewrite(unknown);
  await rejects(() => load(unknown), /missing or unknown/);
  const noncanonical = await fixture(); const noncanonicalBytes = Buffer.from(JSON.stringify(noncanonical.manifest, null, 2)); await writeFile(path.join(noncanonical.directory, 'manifest.json'), noncanonicalBytes); noncanonical.descriptor.manifest.sha256 = hash(noncanonicalBytes); await rewrite(noncanonical);
  await rejects(() => load(noncanonical), /RFC8785/);
  const linked = await fixture(); await (await import('node:fs/promises')).unlink(path.join(linked.directory, 'locks', 'state.bin')); await symlink('/etc/hosts', path.join(linked.directory, 'locks', 'state.bin'));
  await rejects(() => load(linked), /regular non-symlink/);
});

test('verifies real Ed25519 signatures against the pinned signer and rejects signature drift', async () => {
  const unsigned = await fixture({ signed: false });
  await rejects(
    () => loadV2InstanceDescriptor({
      descriptorPath: unsigned.descriptorPath,
      profileCore: unsigned.profileCore,
      trustedSigners: [],
    }),
    /signature is required/,
  );
  const subject = await fixture();
  subject.descriptor.signature.signature = Buffer.alloc(64, 0).toString('base64'); await rewrite(subject);
  await rejects(() => load(subject), /signature verification/);
  const unpinned = await fixture();
  await rejects(
    () => load(unpinned, {
      trustedSigners: [{
        signerId: 'other-signer',
        publicKey: unpinned.trustedSigners[0].publicKey,
      }],
    }),
    /not pinned/,
  );
});

test('rejects reordered, duplicated, missing, or aliased PF11 verifier roles', async () => {
  for (const mutate of [
    (subject) => {
      subject.descriptor.finalLocks.verifiers.reverse();
    },
    (subject) => {
      subject.descriptor.finalLocks.verifiers[1].role = 'exec0';
    },
    (subject) => {
      subject.descriptor.finalLocks.verifiers.pop();
    },
    (subject) => {
      subject.descriptor.finalLocks.verifiers[1].lockingArtifactId =
        subject.descriptor.finalLocks.verifiers[0].lockingArtifactId;
    },
  ]) {
    const subject = await fixture();
    mutate(subject);
    await rewrite(subject);
    await rejects(
      () => load(subject),
      /verifier topology is invalid|exact, ordered, and unique|locking artifacts must be unique/,
    );
  }
});

test('rejects substitution between independently accepting binding redeem pairs', async () => {
  assert.notDeepEqual(bindingRedeemA, bindingRedeemB);
  assert.notDeepEqual(bindingLockA, bindingLockB);
  for (const [redeemScript, lockingBytecode] of [
    [bindingRedeemA, bindingLockA],
    [bindingRedeemB, bindingLockB],
  ]) {
    const result = createVirtualMachineBch2026(true).evaluate(
      createTestAuthenticationProgramBch({
        lockingBytecode,
        unlockingBytecode: encodeDataPush(redeemScript),
        valueSatoshis: 1_000n,
      }),
    );
    assert.equal(result.error, undefined);
  }
  for (const mutate of [
    (subject) => {
      subject.descriptor.finalLocks.binding.lockingArtifactId =
        'binding-lock-b';
    },
    (subject) => {
      subject.descriptor.finalLocks.binding.redeemArtifactId =
        'binding-redeem-b';
    },
  ]) {
    const subject = await fixture();
    mutate(subject);
    await resign(subject);
    await rejects(
      () => load(subject),
      /do not form the exact P2SH32 pair/,
    );
  }
});

test('rejects alternate valid helper, helper-unlock, and state-lock substitutions', async () => {
  const reference = await fixture();
  const verifierLocks = await Promise.all(
    V2_INSTANCE_VERIFIER_ROLES.map(async (role) => {
      const artifact = reference.manifest.artifacts.find(
        (entry) => entry.id === `verifier-${role}-lock`,
      );
      return readFile(path.join(reference.directory, artifact.path));
    }),
  );
  const alternativeHelper = Buffer.from(buildDirectV2StateHelper({
    bindingLock: bindingLockA,
    verifierLocks,
    verifierBaseValues: V2_INSTANCE_VERIFIER_ROLES.map(
      (_role, index) => index === 0 ? '1001' : '1000',
    ),
    bindingBaseValueSats: '1200',
    stateBaseValueSats: '2500',
    denominationSats: reference.profileCore.denominationSats,
    stateCategory: reference.descriptor.instanceId,
    minimumChangeSats: '546',
  }));
  const alternativeHelperUnlock = Buffer.from(
    buildDirectV2StateTrampolineUnlock(alternativeHelper),
  );
  const alternativeStateLock = Buffer.from(
    buildDirectV2StateTrampolineLock({
      helper: alternativeHelper,
      bindingLock: bindingLockA,
    }),
  );
  for (const [artifactId, replacement, pattern] of [
    [
      'state-helper',
      alternativeHelper,
      /not the exact structural helper/,
    ],
    [
      'state-helper-unlock',
      alternativeHelperUnlock,
      /not canonical for the exact structural helper/,
    ],
    [
      'state-lock',
      alternativeStateLock,
      /not the exact structural trampoline lock/,
    ],
  ]) {
    const subject = await fixture();
    await replacePinnedArtifact(subject, artifactId, replacement);
    await rejects(() => load(subject), pattern);
  }
});

test('rejects signed, structurally self-consistent noncanonical rolling bases', async () => {
  for (const [label, mutateBases] of [
    ['verifier', (subject) => {
      subject.descriptor.finalLocks.verifiers[0].baseSats = '1100';
    }],
    ['binding', (subject) => {
      subject.descriptor.finalLocks.binding.baseSats = '1300';
    }],
    ['state', (subject) => {
      subject.descriptor.finalLocks.state.baseSats = '2600';
    }],
  ]) {
    const subject = await fixture();
    mutateBases(subject);
    const verifierLocks = await Promise.all(
      subject.topology.verifierRoles.map(async (role) => {
        const artifact = subject.manifest.artifacts.find(
          (entry) => entry.id === `verifier-${role}-lock`,
        );
        assert.notEqual(artifact, undefined);
        return readFile(path.join(subject.directory, artifact.path));
      }),
    );
    const helper = Buffer.from(buildDirectV2StateHelper({
      bindingLock: bindingLockA,
      verifierLocks,
      verifierBaseValues:
        subject.descriptor.finalLocks.verifiers.map((entry) => entry.baseSats),
      bindingBaseValueSats:
        subject.descriptor.finalLocks.binding.baseSats,
      stateBaseValueSats: subject.descriptor.finalLocks.state.baseSats,
      denominationSats: subject.profileCore.denominationSats,
      stateCategory: subject.descriptor.instanceId,
      minimumChangeSats: '546',
      topologyId: subject.topology.id,
      verifierRoles: subject.topology.verifierRoles,
    }));
    const helperUnlock = Buffer.from(
      buildDirectV2StateTrampolineUnlock(helper),
    );
    const stateLock = Buffer.from(buildDirectV2StateTrampolineLock({
      helper,
      bindingLock: bindingLockA,
      topologyId: subject.topology.id,
      verifierRoles: subject.topology.verifierRoles,
    }));
    await replacePinnedArtifact(subject, 'state-helper', helper);
    await replacePinnedArtifact(
      subject,
      'state-helper-unlock',
      helperUnlock,
    );
    await replacePinnedArtifact(subject, 'state-lock', stateLock);
    await rejects(
      () => load(subject),
      new RegExp(`${label}.*exact dust-derived`, 'i'),
    );
  }
});

test('signed attestations commit every descriptor binding and reject legacy manifest-only envelopes', async () => {
  const mutations = [
    (s) => { s.descriptor.genesis.transactionId = 'bb'.repeat(32); },
    (s) => { s.descriptor.genesis.outpointIndex = 1; },
    (s) => { s.descriptor.initialState = state('cc'.repeat(32)); },
    (s) => { s.descriptor.finalLocks.binding.lockingArtifactId = 'binding-lock-b'; },
    (s) => { s.descriptor.finalLocks.binding.redeemArtifactId = 'binding-redeem-b'; },
    (s) => { s.descriptor.finalLocks.binding.baseSats = '9'; },
    (s) => { s.descriptor.finalLocks.verifiers[0].lockingArtifactId = 'state-lock'; },
    (s) => { s.descriptor.finalLocks.verifiers[0].baseSats = '9'; },
    (s) => { s.descriptor.finalLocks.state.lockingArtifactId = 'verification-key'; },
    (s) => { s.descriptor.finalLocks.state.helperArtifactId = 'verification-key'; },
    (s) => { s.descriptor.finalLocks.state.helperUnlockArtifactId = 'verification-key'; },
    (s) => { s.descriptor.finalLocks.state.baseSats = '9'; },
    (s) => { s.descriptor.manifest.path = 'proof/vk.bin'; },
    (s) => { s.descriptor.manifest.sha256 = '00'.repeat(32); },
    (s) => { s.descriptor.instanceId = 'ee'.repeat(32); },
    (s) => { s.descriptor.profileId = 'dd'.repeat(32); },
    (s) => { s.descriptor.stateNftCategory = 'ff'.repeat(32); },
  ];
  for (const mutate of mutations) {
    const subject = await fixture({ signed: true });
    mutate(subject); await rewrite(subject);
    await rejects(
      () => load(subject),
      /signature verification|profileId|stateNftCategory|artifact manifest|SHA-256|locking artifacts/i,
    );
  }
  const legacy = await fixture({ signed: true });
  delete legacy.descriptor.signature.attestationDomain;
  delete legacy.descriptor.signature.attestationVersion;
  legacy.descriptor.signature.signature = sign(
    null,
    Buffer.from(canonicalizeJcs(legacy.manifest)),
    generateKeyPairSync('ed25519').privateKey,
  ).toString('base64');
  await rewrite(legacy);
  await rejects(() => load(legacy), /legacy attestation semantics|missing or unknown/);
});

test('rejects a valid state commitment whose embedded profileId differs from the descriptor profile', async () => {
  const subject = await fixture();
  subject.descriptor.initialState = state('cc'.repeat(32));
  await rewrite(subject);
  await rejects(() => load(subject), /initialState profileId/);
});

test('requires the exact protocol-derived empty genesis state', async () => {
  const mutations = [
    (profileId) => encodeStateNftCommitment({
      ...stateObject(profileId),
      noteRoot: '03'.padStart(64, '0'),
    }, { denominationSats: '10000000' }).toString('hex'),
    (profileId) => encodeStateNftCommitment({
      ...stateObject(profileId),
      nullifierRoot: '04'.padStart(64, '0'),
    }, { denominationSats: '10000000' }).toString('hex'),
    (profileId) => nonGenesisState(profileId),
  ];
  for (const mutate of mutations) {
    const subject = await fixture();
    subject.descriptor.initialState = mutate(subject.descriptor.profileId);
    await rewrite(subject);
    await rejects(
      () => load(subject),
      /exact canonical empty genesis state/,
    );
  }
});

test('creates local secret files atomically at mode 0600 and refuses overwrite', async () => {
  const subject = await fixture(); const filename = path.join(subject.directory, 'secret.bin');
  await createV2SecretFile(filename, Buffer.from('secret'));
  assert.equal((await lstat(filename)).mode & 0o777, 0o600); assert.equal((await readFile(filename)).toString(), 'secret');
  await rejects(() => createV2SecretFile(filename, Buffer.from('overwrite')), /already exists/);
  assert.equal((await readFile(filename)).toString(), 'secret');
  const failed = path.join(subject.directory, 'failed-secret.bin');
  await rejects(
    () => createV2SecretFile(
      failed,
      Buffer.from('never-publish-partial'),
      {
        async writeTemporaryFile(handle, bytes) {
          await handle.write(bytes.subarray(0, 4), 0, 4, 0);
          throw new Error('injected write failure');
        },
      },
    ),
    /secret file creation failed/,
  );
  await assert.rejects(lstat(failed), /ENOENT/);
  assert.deepEqual(
    (await readdir(subject.directory)).filter(
      (entry) => entry.startsWith('.shieldkit-secret-'),
    ),
    [],
  );
  await chmod(subject.directory, 0o700);
});
