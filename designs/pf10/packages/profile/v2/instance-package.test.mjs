// Local unit contract for the two-phase V2 instance package assembler.
//
// This fixture deliberately uses a small test-only runtime and a locally VM
// checked (but never broadcast, mined, or production-qualified) genesis. It
// establishes filesystem and identity invariants; it is not release evidence.
import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signEd25519,
} from 'node:crypto';
import {
  chmod,
  cp,
  lstat,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

import {
  encodeTransaction,
  hash160,
  secp256k1,
} from '@bitauth/libauth';

import {
  INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN,
  INSTANCE_DESCRIPTOR_ATTESTATION_VERSION,
  PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
  PF10_RUNTIME_ARTIFACT_SCHEMA,
  V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
  descriptorAttestationBytes,
} from './instance-descriptor.mjs';
import {
  canonicalCircuitBuildAttestation,
  canonicalDevelopmentSetupAttestation,
  CIRCUIT_BUILD_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
} from './build-attestation.mjs';
import {
  createV2GenesisRuntime,
  deriveV2FinalizedGenesisPackagePins,
  finalizeV2Genesis,
  prepareV2Genesis,
  V2_GENESIS_INTENT_SCHEMA,
} from './genesis.mjs';
import {
  canonicalizeJcs,
  V2_PROFILE_DOMAINS,
} from './profile-core.mjs';
import { collectNpmBuildClosure } from './npm-closure.mjs';
import { collectV2RelationSourceManifest } from './relation-source-manifest.mjs';
import { parseV2RawTransaction } from '../../kit/v2/transaction-policy.mjs';
import {
  buildDirectV2Pf10DevelopmentRuntime,
  DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA,
  validateDirectV2Pf10LibauthEvidence,
} from '../../unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value) => Buffer.from(value).toString('hex');
const repeat = (byte) => byte.repeat(64);
const repositoryRoot = path.resolve(import.meta.dirname, '../../../../../');
const testPrivateKey = Buffer.from(`${'00'.repeat(31)}01`, 'hex');
const testPublicKey = Buffer.from(secp256k1.derivePublicKeyCompressed(testPrivateKey));
const PRIVATE_KEY_CANARY = 'instance-package-private-key-canary-must-never-persist';

let base;

async function packageApi() {
  try {
    const subject = await import('./instance-package.mjs');
    assert.equal(typeof subject.prepareV2InstancePackage, 'function');
    assert.equal(typeof subject.finalizeV2InstancePackage, 'function');
    return subject;
  } catch (error) {
    assert.fail(
      `instance package API is not implemented: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function profileCore(pins) {
  return {
    schema: 'shieldkit-profile-core-v2-direct',
    network: { id: 2, name: 'chipnet' },
    denominationSats: '10000000',
    proof: {
      system: 'groth16', curve: 'bn254',
      relationId: 'shieldkit-pool-action-v2-direct', relationSha256: repeat('1'),
      r1csSha256: pins.r1cs.sha256,
      verificationKeySha256: pins.verificationKey.sha256,
      witnessWasmSha256: pins.wasm.sha256,
    },
    trees: {
      note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' },
      nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' },
    },
    crypto: {
      babyJubCurveId: 'circomlib-babyjub-base8',
      poseidonId: 'circomlib-poseidon-bn254', domains: { ...V2_PROFILE_DOMAINS },
    },
    encodings: {
      state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552',
      address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128',
      unlock: 'shieldkit-rolling-bundle-unlock-v2-direct',
    },
    publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' },
    baseVerifierArtifacts: [
      { id: 'carrier-base', sha256: pins.carrierBase.sha256 },
      { id: 'state-base', sha256: pins.stateBase.sha256 },
    ],
    toolchain: [
      { name: 'circom', version: '2.2.3', sha256: repeat('7') },
      { name: 'snarkjs', version: '0.7.6', sha256: repeat('8') },
    ],
  };
}

function p2pkhLock() {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]), Buffer.from(hash160(testPublicKey)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function sourceTransactionHex() {
  return hex(encodeTransaction({
    version: 2,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x42), outpointIndex: 1,
      sequenceNumber: 0, unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{ valueSatoshis: 80_000n, lockingBytecode: p2pkhLock() }],
    locktime: 0,
  }));
}

function sourceInstanceId(rawTransactionHex) {
  return Buffer.from(
    parseV2RawTransaction(rawTransactionHex).txid,
    'hex',
  ).reverse().toString('hex');
}

function descriptorFinalLocksFor(pins) {
  return {
    topologyId: pins.finalLocks.topology.id,
    verifiers: pins.finalLocks.verifiers.map((entry, index) => ({
      role: entry.role,
      lockingArtifactId: `verifier-lock-${index}`,
      baseSats: entry.baseSats.toString(),
    })),
    binding: {
      lockingArtifactId: 'binding-lock', redeemArtifactId: 'binding-redeem',
      baseSats: pins.finalLocks.binding.baseSats.toString(),
    },
    state: {
      lockingArtifactId: 'state-lock', helperArtifactId: 'state-helper',
      helperUnlockArtifactId: 'state-helper-unlock',
      baseSats: pins.finalLocks.state.baseSats.toString(),
    },
  };
}

async function baseFixture() {
  if (base !== undefined) return base;
  // The PF10 builder accepts only repository-relative staging paths. Keep this
  // unique/private and remove it in the file-level teardown below.
  const privateParent = path.join(repositoryRoot, '.codex-build', 'test-tmp');
  await mkdir(privateParent, { recursive: true, mode: 0o700 });
  await chmod(privateParent, 0o700);
  const root = await mkdtemp(path.join(privateParent, 'v2-instance-package-'));
  await chmod(root, 0o700);
  const proofDirectory = path.join(root, 'proof');
  const temporaryRoot = path.join(root, 'runtime-tmp');
  await mkdir(proofDirectory, { recursive: true, mode: 0o700 });
  await mkdir(temporaryRoot, { mode: 0o700 });
  const artifactPaths = {
    provingKey: path.join(proofDirectory, 'development.zkey'),
    r1cs: path.join(proofDirectory, 'main.r1cs'),
    wasm: path.join(proofDirectory, 'main.wasm'),
    verificationKey: path.join(
      repositoryRoot,
      'designs/pf10/packages/prove/test-fixtures/two-public/verification_key.json',
    ),
  };
  await Promise.all([
    writeFile(artifactPaths.provingKey, 'test-only-proving-key', { mode: 0o600 }),
    writeFile(artifactPaths.r1cs, 'test-only-r1cs', { mode: 0o600 }),
    writeFile(artifactPaths.wasm, 'test-only-wasm', { mode: 0o600 }),
  ]);
  const baseArtifactBytes = {
    carrierBase: Buffer.from('test-only-carrier-base', 'utf8'),
    stateBase: Buffer.from('test-only-state-base', 'utf8'),
  };
  const proofArtifacts = Object.fromEntries(await Promise.all(
    Object.entries(artifactPaths).map(async ([name, filename]) => [name, {
      path: filename, sha256: sha256(await readFile(filename)),
    }]),
  ));
  const core = profileCore({
    ...proofArtifacts,
    carrierBase: { sha256: sha256(baseArtifactBytes.carrierBase) },
    stateBase: { sha256: sha256(baseArtifactBytes.stateBase) },
  });
  const sourceTransaction = sourceTransactionHex();
  const runtime = await createV2GenesisRuntime({
    repositoryRoot, temporaryRoot, profileCore: core, proofArtifacts,
    instanceId: sourceInstanceId(sourceTransaction),
  });
  const prepared = prepareV2Genesis({
    schema: V2_GENESIS_INTENT_SCHEMA, profileCore: core,
    maximumLiveNotes: '32', fundingPublicKeyHex: hex(testPublicKey),
    changeLockingBytecodeHex: hex(p2pkhLock()), feeRateSatsPerByte: '1',
    sourceTransactionHex: sourceTransaction,
  }, runtime);
  const signature = secp256k1.signMessageHashSchnorr(
    testPrivateKey, Buffer.from(prepared.signingRequest.digestHex, 'hex'),
  );
  assert.notEqual(typeof signature, 'string');
  const finalizedGenesis = finalizeV2Genesis(prepared, Buffer.from(signature), runtime);
  assert.equal(finalizedGenesis.claims.productionQualified, false);
  const pins = deriveV2FinalizedGenesisPackagePins(finalizedGenesis, runtime);
  const baseCandidate = {
    root, core, finalizedGenesis, runtime, pins, baseArtifactBytes,
    proofArtifacts, temporaryRoot,
  };
  const runtimeTemplateRoot = path.join(root, 'canonical-runtime-template');
  await mkdir(runtimeTemplateRoot, { mode: 0o700 });
  const runtimeBuildManifest = await writeCanonicalPf10RuntimeBundle(
    baseCandidate,
    runtimeTemplateRoot,
    descriptorFinalLocksFor(pins),
  );
  base = {
    ...baseCandidate,
    runtimeTemplateRoot,
    runtimeBuildManifest,
  };
  return base;
}

after(async () => {
  if (base !== undefined) await rm(base.root, { recursive: true, force: true });
});

async function writeCanonical(filename, value) {
  const bytes = Buffer.from(canonicalizeJcs(value));
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await writeFile(filename, bytes, { mode: 0o600 });
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

let runtimeContract;
async function runtimeContractContext() {
  if (runtimeContract === undefined) {
    runtimeContract = Promise.all([
      collectNpmBuildClosure({ repositoryRoot, roots: ['circom2'] }),
      collectNpmBuildClosure({ repositoryRoot, roots: ['snarkjs'] }),
      collectV2RelationSourceManifest({ repositoryRoot }),
    ]).then(([circomClosure, snarkjsClosure, relationManifest]) => ({
      circomClosure,
      snarkjsClosure,
      relationBytes: Buffer.from(canonicalizeJcs(relationManifest)),
    }));
  }
  return runtimeContract;
}

function closureArtifact(closure, packagePath, relative) {
  const record = closure.packages.find((entry) => entry.packagePath === packagePath)
    ?.installed.files.find((entry) => entry.path === relative);
  assert.notEqual(record, undefined, `missing ${packagePath}/${relative}`);
  return { bytes: record.bytes, path: `${packagePath}/${relative}`, sha256: record.sha256 };
}

function libauthEvidence({ profileId, instanceId, proofArtifactHashes, runtimeMaterialSha256 }) {
  const transactionId = (bytes) => Buffer.from(
    createHash('sha256').update(
      createHash('sha256').update(bytes).digest(),
    ).digest(),
  ).reverse().toString('hex');
  const parent = (byte) => {
    const raw = Buffer.from([byte, 0, 0, 0]);
    return {
      rawTransactionHex: raw.toString('hex'),
      rawTransactionSha256: sha256(raw),
      transactionId: transactionId(raw),
    };
  };
  const action = (kind, transactionBytes, outputCount, byte) => {
    const raw = Buffer.alloc(transactionBytes, byte);
    const previousBundle = parent(byte);
    const funding = parent(byte + 1);
    const localVmBytes = Buffer.from(canonicalizeJcs({
      kind,
      rows: 13,
      verdict: 'all-local-vm-rows-accepted',
    }));
    const localVmEvidenceHash = sha256(localVmBytes);
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
      contextHash: sha256(Buffer.from(`${kind}-context`)),
      packetSha256: sha256(Buffer.from(`${kind}-packet`)),
      rawTransactionHex: raw.toString('hex'),
      rawTransactionSha256: sha256(raw),
      transactionId: transactionId(raw),
      construction: {
        assemblyHash: sha256(Buffer.from(`${kind}-assembly`)),
        inputSequence: 0,
        localVmEvidenceHash,
        path: [
          'prepareV2DirectSettlement',
          'assembleV2DirectSettlement',
          'signV2DirectSettlement',
        ],
        preparedPayloadHash: sha256(Buffer.from(`${kind}-payload`)),
      },
      sourceParents: { funding, previousBundle },
      inputSources: Array.from({ length: 13 }, (_, index) => ({
        inputIndex: index,
        outputIndex: index < 10 ? index + 1 : index === 10 ? 11 : 0,
        parentKind: index === 12 ? 'funding' : 'previous-bundle',
        serializedOutputSha256: sha256(Buffer.from(`${kind}-output-${index}`)),
        transactionId: index === 12 ? funding.transactionId : previousBundle.transactionId,
      })),
      sourceOutputs: Array.from({ length: 13 }, (_, index) => ({
        lockingBytecodeHex: index === 12 ? '51' : '',
        tokenPrefixHex: '',
        valueSats: index === 12 ? '100000000' : '1200',
      })),
      localVmEvidence: {
        evidenceHash: localVmEvidenceHash,
        hex: localVmBytes.toString('hex'),
        sha256: localVmEvidenceHash,
      },
      mutationChecks: [
        ['local-table', 0, [0]], ['local-table', 1, [1]],
        ['local-table', 2, [2]], ['local-table', 3, [3]],
        ['local-table', 4, [4]], ['local-table', 9, [9]],
        ['remote-carrier', 5, [0, 5]],
        ['remote-carrier', 6, [1, 6]],
        ['remote-carrier', 7, [3, 7]],
      ].map(([mutationKind, mutatedInput, rejectingInputs]) => ({
        kind: mutationKind,
        mutatedInput,
        rejectingInputs,
      })),
      rows: [
        'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'msm5', 'msm6',
        'msm7', 'fused-q-genesis8', 'terminal9', 'binding10', 'state11',
        'funding12',
      ].map((name, index) => ({
        arithmeticCost: 0,
        definedFunctions: 0,
        evaluatedInstructionCount: 0,
        hardAccepted: true,
        hashDigestIterations: 0,
        index,
        maximumHashDigestIterations: 0,
        maximumLegalOperationCost: 100,
        maximumOperationCost: 100,
        maximumSignatureChecks: 0,
        name,
        operationCost: 0,
        operationPercent: 0,
        semanticAccepted: true,
        signatureCheckCount: 0,
        stackPushedBytes: 0,
        unlockBytes: 0,
      })),
    };
  };
  const roleTableHash256 = Array.from({ length: 5 }, (_, index) =>
    sha256(Buffer.from(`fixed-role-table-${index}`)));
  const terminalTableHash256 = sha256(Buffer.from('fixed-terminal-table'));
  const fixedLineDerivation = {
    digestMutationChecks: [
      ...roleTableHash256.map((honestHash256, index) => ({
        table: `executor${index}`,
        honestHash256,
        mutatedHash256: sha256(Buffer.from(`mutated-role-table-${index}`)),
      })),
      {
        table: 'terminal9',
        honestHash256: terminalTableHash256,
        mutatedHash256: sha256(Buffer.from('mutated-terminal-table')),
      },
    ],
    inputs: [
      'deployment verification key gamma',
      'deployment verification key delta',
      'BN254 constants',
      'ATE NAF digits',
    ],
    proofOrPublicInputs: false,
    roleTableBytes: [6912, 5760, 6144, 6144, 7296],
    roleTableHash256,
    terminalTableBytes: 768,
    terminalTableHash256,
  };
  return {
    schema: DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA,
    eligibility: 'development-only',
    generatedAt: '2026-07-29T00:00:00.000Z',
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
      profileId, instanceId, proofArtifactHashes, runtimeMaterialSha256,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    },
    exactDustBases: {
      bindingSats: '1200', minimumChangeSats: '546', stateSats: '2500',
      verifierSats: Array(10).fill('1200'),
    },
    hardLimits: {
      standardVmResourcePercent: 100, transactionBytes: 100_000,
      unlockingBytecodeBytes: 10_000,
    },
    pf10FusedQGenesisActions: {
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      actionCount: 3,
      actions: [
        action('deposit', 97_852, 13, 0x44),
        action('transfer', 97_852, 13, 0x54),
        action('withdrawal', 97_886, 14, 0x57),
      ],
      fixedLineDerivation,
      fixedPrograms: {
        bindingRedeemBytes: 2195,
        exactFinalRawBytes: 1924,
        exactFinalRedeemBytes: 1597,
        exactRawBytes: [1682, 1667, 1675],
        exactRedeemBytes: [1387, 1372, 1380],
        executorBodyBytes: 5573,
        executorDensityPadBytes: 384,
        fixedLineCarrierBytes: 20864,
        fusedRedeemBytes: 6404,
        loaderBytes: 108,
        millerRawBytes: 5430,
        millerRedeemBytes: 4620,
        rawExecutorBytes: 10937,
        rawTerminalBytes: 9359,
        stateHelperBytes: 2674,
        terminalRedeemBytes: 6740,
      },
      identityExecutorRows: Array.from({ length: 5 }, (_, index) => ({
        index,
        operationCost: index + 1,
        unlockBytes: index + 1,
      })),
      verdict: 'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
    },
  };
}

async function writeCanonicalPf10RuntimeBundle(authenticated, runtimeRoot, descriptorFinalLocks) {
  const proofArtifactHashes = Object.fromEntries(
    Object.entries(authenticated.proofArtifacts).map(([name, value]) => [name, value.sha256]),
  );
  const evidence = libauthEvidence({
    profileId: authenticated.runtime.profileId,
    instanceId: authenticated.runtime.instanceId,
    proofArtifactHashes,
    runtimeMaterialSha256: authenticated.runtime.runtimeMaterialSha256,
  });
  const evidenceBytes = Buffer.from(canonicalizeJcs(evidence));
  assert.equal(validateDirectV2Pf10LibauthEvidence({
    bytes: evidenceBytes,
    expectedTerminalProgramBytes: Object.freeze({
      raw: 9_359,
      redeem: 6_740,
    }),
    profileId: authenticated.runtime.profileId,
    instanceId: authenticated.runtime.instanceId,
    proofArtifactHashes,
    runtimeMaterialSha256: authenticated.runtime.runtimeMaterialSha256,
  }).runtimeMaterialSha256, authenticated.runtime.runtimeMaterialSha256);
  const evidencePath = path.join(runtimeRoot, '.per-instance-libauth-evidence.json');
  await writeFile(evidencePath, evidenceBytes, { mode: 0o600 });
  const build = await buildDirectV2Pf10DevelopmentRuntime({
    repositoryRoot,
    temporaryRoot: authenticated.temporaryRoot,
    profileId: authenticated.runtime.profileId,
    instanceId: authenticated.runtime.instanceId,
    proofArtifacts: authenticated.proofArtifacts,
    libauthEvidence: { path: evidencePath, sha256: sha256(evidenceBytes) },
  });
  assert.equal(build.runtimeMaterial.materialSha256, authenticated.runtime.runtimeMaterialSha256);
  const artifacts = [];
  const add = async (id, relative, bytes) => {
    const data = Buffer.from(bytes);
    const filename = path.join(runtimeRoot, relative);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, data, { mode: 0o600 });
    artifacts.push({ id, path: relative, sha256: sha256(data), bytes: data.length });
  };
  const ids = {
    profileCore: 'profile-core', profilePackage: 'development-profile-package',
    baseVerifierManifest: 'pf10-base-verifier-sources', topologySpec: 'pf10-topology-spec',
    toolchainManifest: 'toolchain-manifest', circuitBuildAttestation: 'circuit-build-attestation',
    developmentSetupAttestation: 'development-setup-attestation', relationManifest: 'relation-source-manifest',
    circuitSymbols: 'proof-circuit-symbols', initialProvingKey: 'proof-initial-proving-key',
    powersOfTau: 'proof-powers-of-tau', provingKey: 'proof-proving-key', r1cs: 'proof-r1cs',
    verificationKey: 'proof-verification-key', wasm: 'proof-witness-wasm',
    executorBody: 'pf10-executor-body', exact: ['pf10-exact-msm-redeem-0', 'pf10-exact-msm-redeem-1', 'pf10-exact-msm-redeem-2'],
    pads: ['pf10-fixed-carrier-pad-0', 'pf10-fixed-carrier-pad-1', 'pf10-fixed-carrier-pad-2'],
    fused: 'pf10-fused-redeem', terminal: 'pf10-terminal-redeem',
    qualification: 'pf10-qualification-record', rawQualification: 'pf10-raw-qualification-evidence',
    libauth: 'pf10-libauth-evidence',
  };
  await add('carrier-base', 'base/carrier.bin', authenticated.baseArtifactBytes.carrierBase);
  await add('state-base', 'base/state.bin', authenticated.baseArtifactBytes.stateBase);
  await add(ids.profileCore, 'profile/profile-core.json', Buffer.from(canonicalizeJcs(authenticated.core)));
  await Promise.all([
    add(ids.provingKey, 'proof/development.zkey', await readFile(authenticated.proofArtifacts.provingKey.path)),
    add(ids.r1cs, 'proof/main-chipnet.r1cs', await readFile(authenticated.proofArtifacts.r1cs.path)),
    add(ids.verificationKey, 'proof/verification_key.json', await readFile(authenticated.proofArtifacts.verificationKey.path)),
    add(ids.wasm, 'proof/main-chipnet.wasm', await readFile(authenticated.proofArtifacts.wasm.path)),
  ]);
  await add(ids.circuitSymbols, 'proof/main-chipnet.sym', Buffer.from('canonical fixture circuit symbols'));
  await add(ids.initialProvingKey, 'proof/initial.zkey', Buffer.from('canonical fixture initial zkey'));
  await add(ids.powersOfTau, 'proof/powers-of-tau.ptau', Buffer.from('canonical fixture ptau'));
  await add(ids.baseVerifierManifest, 'reproducibility/base-verifier-manifest.json', Buffer.from('{"fixture":"canonical"}'));
  await add(ids.topologySpec, 'reproducibility/pf10-topology-spec.json', Buffer.from('{"topology":"pf10-fused-q-genesis"}'));
  await add(ids.toolchainManifest, 'reproducibility/toolchain-manifest.json', Buffer.from('{"toolchain":"pinned"}'));
  const context = await runtimeContractContext();
  await add(ids.relationManifest, 'reproducibility/relation-source-manifest.json', context.relationBytes);
  const artifact = (id) => artifacts.find((entry) => entry.id === id);
  const record = (id, expectedPath) => {
    const entry = artifact(id); assert.notEqual(entry, undefined, `missing ${id}`);
    return { bytes: entry.bytes, path: expectedPath, sha256: entry.sha256 };
  };
  const buildAttestation = canonicalCircuitBuildAttestation({
    schema: CIRCUIT_BUILD_ATTESTATION_SCHEMA,
    claims: { developmentOnly: true, production: false, release: false },
    compilation: {
      argv: ['node_modules/circom2/cli.js', 'designs/pf10/circuits/v2-direct/main-chipnet.circom', '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2', '--output', '$BUILD_OUTPUT'],
      circomCompilerVersion: '2.2.3', circomPackageVersion: '0.2.23',
      cli: closureArtifact(context.circomClosure, 'node_modules/circom2', 'cli.js'), executable: 'process.execPath',
      node: { modulesAbi: process.versions.modules, version: process.versions.node }, optimization: 'O1',
      packageMetadata: closureArtifact(context.circomClosure, 'node_modules/circom2', 'package.json'), sanityCheck: 2,
    },
    npmClosure: context.circomClosure,
    r1csAbi: { constraints: 1, field: 'bn254', privateInputs: 1, publicInputs: 2, publicOutputs: 0, wires: 4 },
    sourceManifest: record(ids.relationManifest, 'relation-source-manifest.json'),
    artifacts: { r1cs: record(ids.r1cs, 'main-chipnet.r1cs'), sym: record(ids.circuitSymbols, 'main-chipnet.sym'), wasm: record(ids.wasm, 'main-chipnet_js/main-chipnet.wasm') },
  });
  await add(ids.circuitBuildAttestation, 'reproducibility/circuit-build-attestation.json', buildAttestation.bytes);
  const setupAttestation = canonicalDevelopmentSetupAttestation({
    schema: DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
    claims: { contributionIndependence: 'not-established', developmentOnly: true, externalTranscript: false, finalCeremony: false, production: false, release: false },
    buildAttestation: record(ids.circuitBuildAttestation, 'circuit-build-attestation.json'),
    r1cs: record(ids.r1cs, 'main-chipnet.r1cs'),
    ptau: { artifact: record(ids.powersOfTau, 'powers-of-tau.ptau'), ceremonyPower: 4, power: 4, source: 'instance-package-canonical-fixture', verified: true },
    snarkjs: { cli: closureArtifact(context.snarkjsClosure, 'node_modules/snarkjs', 'build/cli.cjs'), node: { modulesAbi: process.versions.modules, version: process.versions.node }, npmClosure: context.snarkjsClosure, packageMetadata: closureArtifact(context.snarkjsClosure, 'node_modules/snarkjs', 'package.json'), version: '0.7.6' },
    commands: { powersOfTauVerify: ['node_modules/snarkjs/build/cli.cjs', 'powersoftau', 'verify', '$PTAU'], setup: ['node_modules/snarkjs/build/cli.cjs', 'groth16', 'setup', '$R1CS', '$PTAU', '$INITIAL_ZKEY'], contribute: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'contribute', '$INPUT_ZKEY', '$OUTPUT_ZKEY'], verifyFinalZkey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'verify', '$R1CS', '$PTAU', '$FINAL_ZKEY'], exportVerificationKey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'export', 'verificationkey', '$FINAL_ZKEY', '$VERIFICATION_KEY'] },
    zkeyChain: { contributions: [{ entropyCommitment: '11'.repeat(32), entropyCommitmentDomain: DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN, inputZkeySha256: record(ids.initialProvingKey, 'initial.zkey').sha256, output: record(ids.provingKey, 'final.zkey'), sequence: 1 }], initial: record(ids.initialProvingKey, 'initial.zkey') },
    finalEvidence: { finalZkeySha256: record(ids.provingKey, 'final.zkey').sha256, finalZkeyVerified: true, verificationKey: record(ids.verificationKey, 'verification_key.json'), verificationKeyExported: true },
  });
  await add(ids.developmentSetupAttestation, 'reproducibility/development-setup-attestation.json', setupAttestation.bytes);
  const profilePackage = {
    schema: 'shieldkit-v2-direct-development-profile-package-v1', eligibility: 'development-only',
    profileId: authenticated.runtime.profileId, profileCoreSha256: artifact(ids.profileCore).sha256,
    proofArtifacts: {
      circuitSymbols: record(ids.circuitSymbols, 'proof/circuit-symbols.bin'), initialProvingKey: record(ids.initialProvingKey, 'proof/initial.zkey'), powersOfTau: record(ids.powersOfTau, 'proof/powers-of-tau.ptau'), provingKey: record(ids.provingKey, 'proof/development.zkey'), r1cs: record(ids.r1cs, 'proof/main-chipnet.r1cs'), verificationKey: record(ids.verificationKey, 'proof/verification_key.json'), witnessWasm: record(ids.wasm, 'proof/main-chipnet.wasm'),
    },
    generatedArtifacts: {
      baseVerifierManifest: record(ids.baseVerifierManifest, 'base-verifier-manifest.json'), circuitBuildAttestation: record(ids.circuitBuildAttestation, 'circuit-build-attestation.json'), developmentSetupAttestation: record(ids.developmentSetupAttestation, 'development-setup-attestation.json'), profileCore: record(ids.profileCore, 'profile-core.json'), relationManifest: record(ids.relationManifest, 'relation-manifest.json'), toolchainManifest: record(ids.toolchainManifest, 'toolchain-manifest.json'), topologySpec: record(ids.topologySpec, 'pf10-topology-spec.json'),
    },
  };
  await add(ids.profilePackage, 'profile/profile-package.json', Buffer.from(canonicalizeJcs(profilePackage)));
  await add(ids.executorBody, 'runtime/executor-body.bin', build.runtimeMaterialInput.executorBody);
  for (let index = 0; index < 3; index += 1) {
    await add(ids.exact[index], `runtime/exact-msm-${index}.bin`, build.runtimeMaterialInput.exactMsmRedeems[index]);
    await add(ids.pads[index], `runtime/fixed-carrier-pad-${index}.bin`, build.runtimeMaterialInput.fixedCarrierPads[index]);
  }
  await add(ids.fused, 'runtime/fused-redeem.bin', build.runtimeMaterialInput.fusedRedeem);
  await add(ids.terminal, 'runtime/terminal-redeem.bin', build.runtimeMaterialInput.terminalRedeem);
  await add(ids.libauth, 'qualification/pf10-libauth-evidence.json', evidenceBytes);
  const source = (id, expectedPath) => record(id, expectedPath);
  const action = (kind) => {
    const packet = Buffer.alloc(552, kind.charCodeAt(0));
    const file = (suffix) => { const data = Buffer.from(`${kind}-${suffix}`); return { path: `qualification/${kind}-${suffix}`, bytes: data.length, sha256: sha256(data) }; };
    return { files: { v2DirectGroth16Adapter: file('adapter'), input: file('input'), packet: { path: `qualification/${kind}-packet.bin`, bytes: packet.length, sha256: sha256(packet) }, proof: file('proof'), publicSignals: file('public'), witness: file('witness') }, packetDigest: sha256(packet), proofVerified: true, publicInputs: ['0', '1'], timingsMs: { proofGeneration: 0, proofVerification: 0, total: 0, witnessCalculation: 0, witnessCheck: 0 }, witnessValid: true };
  };
  const rawQualification = { schema: 'shieldkit-v2-direct-development-groth16-qualification-v4', evidenceClass: 'deterministic-development-key-proof-test-evidence', fixture: 'deterministic-deposit-transfer-withdrawal-chain', claims: { developmentKey: true, finalKey: false, bchVm: false, production: false }, identity: { profileId: authenticated.runtime.profileId, instanceId: authenticated.runtime.instanceId, maximumLiveNotes: '32', denominationSats: authenticated.core.denominationSats }, sourceArtifacts: { profileCore: source(ids.profileCore, 'profile/profile-core.json'), r1cs: source(ids.r1cs, 'proof/main-chipnet.r1cs'), wasm: source(ids.wasm, 'proof/main-chipnet.wasm'), developmentZkey: source(ids.provingKey, 'proof/development.zkey'), verificationKey: source(ids.verificationKey, 'proof/verification_key.json') }, actions: { deposit: action('deposit'), transfer: action('transfer'), withdrawal: action('withdrawal') }, versions: { node: process.version, snarkjs: '0.7.6' }, prover: { backend: 'snarkjs', provingSystem: 'groth16', mode: 'single-thread' }, measurements: { totalWallMs: 0, peakRss: { available: false, reason: 'canonical package fixture does not run a prover' } } };
  const rawQualificationBytes = Buffer.from(canonicalizeJcs(rawQualification));
  await add(ids.rawQualification, 'qualification/raw-evidence.json', rawQualificationBytes);
  const qualificationRecord = { schema: PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA, qualificationSchema: rawQualification.schema, evidenceClass: rawQualification.evidenceClass, identity: rawQualification.identity, claims: rawQualification.claims, sourceArtifacts: { r1csSha256: rawQualification.sourceArtifacts.r1cs.sha256, witnessWasmSha256: rawQualification.sourceArtifacts.wasm.sha256, verificationKeySha256: rawQualification.sourceArtifacts.verificationKey.sha256, developmentZkeySha256: rawQualification.sourceArtifacts.developmentZkey.sha256 }, rawEvidenceSha256: sha256(rawQualificationBytes), actions: Object.fromEntries(['deposit', 'transfer', 'withdrawal'].map((kind) => [kind, { proofVerified: true, witnessValid: true }])) };
  await add(ids.qualification, 'qualification/canonical-record.json', Buffer.from(canonicalizeJcs(qualificationRecord)));
  const structural = { bindingLock: 'binding-lock', bindingRedeem: 'binding-redeem', stateLock: 'state-lock', stateHelper: 'state-helper', stateUnlock: 'state-helper-unlock', verifierLocks: authenticated.pins.finalLocks.verifiers.map((_, index) => `verifier-lock-${index}`) };
  for (const [id, relative, bytes] of [
    [structural.bindingLock, 'structural/binding-lock.bin', authenticated.pins.finalLocks.binding.lockingBytecode],
    [structural.bindingRedeem, 'structural/binding-redeem.bin', authenticated.pins.finalLocks.binding.redeemBytecode],
    [structural.stateLock, 'structural/state-lock.bin', authenticated.pins.finalLocks.state.lockingBytecode],
    [structural.stateHelper, 'structural/state-helper.bin', authenticated.pins.finalLocks.state.helperBytecode],
    [structural.stateUnlock, 'structural/state-helper-unlock.bin', authenticated.pins.finalLocks.state.helperUnlockingBytecode],
  ]) await add(id, relative, bytes);
  for (const [index, entry] of authenticated.pins.finalLocks.verifiers.entries()) await add(structural.verifierLocks[index], `structural/verifier-lock-${index}.bin`, entry.lockingBytecode);
  const runtimeArtifact = { schema: PF10_RUNTIME_ARTIFACT_SCHEMA, eligibility: 'development-only', profileId: authenticated.runtime.profileId, instanceId: authenticated.runtime.instanceId, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES, profileArtifacts: { profileCoreArtifactId: ids.profileCore, profilePackageArtifactId: ids.profilePackage, baseVerifierManifestArtifactId: ids.baseVerifierManifest, topologySpecArtifactId: ids.topologySpec, toolchainManifestArtifactId: ids.toolchainManifest }, attestationArtifacts: { circuitBuildAttestationArtifactId: ids.circuitBuildAttestation, developmentSetupAttestationArtifactId: ids.developmentSetupAttestation, relationManifestArtifactId: ids.relationManifest }, setupArtifacts: { circuitSymbolsArtifactId: ids.circuitSymbols, initialProvingKeyArtifactId: ids.initialProvingKey, powersOfTauArtifactId: ids.powersOfTau }, proofArtifacts: { provingKeyArtifactId: ids.provingKey, r1csArtifactId: ids.r1cs, verificationKeyArtifactId: ids.verificationKey, witnessWasmArtifactId: ids.wasm }, unlockArtifacts: { executorBodyArtifactId: ids.executorBody, exactMsmRedeemArtifactIds: ids.exact, fixedCarrierPadArtifactIds: ids.pads, fusedRedeemArtifactId: ids.fused, terminalRedeemArtifactId: ids.terminal }, qualificationEvidenceArtifactId: ids.qualification, rawQualificationEvidenceArtifactId: ids.rawQualification, libauthEvidenceArtifactId: ids.libauth };
  await add('pf10-runtime-material', 'runtime/pf10-runtime-material.json', Buffer.from(canonicalizeJcs(runtimeArtifact)));
  artifacts.sort((left, right) => left.id.localeCompare(right.id));
  return {
    schema: 'shieldkit-v2-direct-pf10-development-runtime-bundle-v2', eligibility: 'development-only',
    profileId: authenticated.runtime.profileId, instanceId: authenticated.runtime.instanceId,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    topologyId: descriptorFinalLocks.topologyId, verifierRoles: descriptorFinalLocks.verifiers.map((entry) => entry.role),
    finalLocks: descriptorFinalLocks,
    artifactManifestTemplate: { schema: 'shieldkit-artifact-manifest-v2-direct', profileId: authenticated.runtime.profileId, instanceId: authenticated.runtime.instanceId, artifacts: artifacts.map(({ id, path: artifactPath, sha256: artifactSha256 }) => ({ id, path: artifactPath, sha256: artifactSha256 })) },
  };
}

async function fixture(t, mutate = undefined) {
  const authenticated = await baseFixture();
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-instance-package-case-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runtimeRoot = path.join(root, 'runtime-source');
  const scannerRoot = path.join(root, 'scanner-source');
  const preparedDirectory = path.join(root, 'prepared');
  const outputDirectory = path.join(root, 'final');
  await cp(authenticated.runtimeTemplateRoot, runtimeRoot, { recursive: true });
  await mkdir(scannerRoot, { mode: 0o700 });
  const descriptorFinalLocks = descriptorFinalLocksFor(authenticated.pins);
  const runtimeBuildManifest = structuredClone(authenticated.runtimeBuildManifest);
  const artifactManifest = runtimeBuildManifest.artifactManifestTemplate;
  const runtimeBuildManifestPath = path.join(runtimeRoot, 'runtime-build-manifest.json');
  await writeCanonical(runtimeBuildManifestPath, runtimeBuildManifest);
  const scanner = Buffer.from('#!/bin/sh\nprintf test-only-scanner\n', 'utf8');
  const scannerPath = path.join(scannerRoot, 'shieldkit-v2-recovery-scanner');
  await writeFile(scannerPath, scanner, { mode: 0o755 });
  const recoveryScannerManifest = {
    schema: 'shieldkit-v2-recovery-scanner-artifact-v1', target: 'linux-x64',
    binaryArtifactId: 'recovery-scanner-linux-x64', binarySha256: sha256(scanner),
    binaryBytes: scanner.length, cargoLockSha256: repeat('a'),
    cargoVersion: 'cargo test-only-local-unit-fixture',
    eligibility: 'clean-source-build',
    protocolSchemas: [...V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS],
    rustcVersion: 'rustc test-only-local-unit-fixture', sourceRevision: 'b'.repeat(40),
  };
  const recoveryScannerManifestPath = path.join(
    scannerRoot, 'shieldkit-v2-recovery-scanner.manifest.json',
  );
  await writeCanonical(recoveryScannerManifestPath, recoveryScannerManifest);
  const signerPair = generateKeyPairSync('ed25519');
  const signer = {
    signerId: 'local-unit-signer',
    publicKey: signerPair.publicKey.export({ type: 'spki', format: 'pem' }),
  };
  const value = {
    finalizedGenesis: authenticated.finalizedGenesis,
    genesisRuntime: authenticated.runtime,
    runtimeBuildManifestPath,
    recoveryScannerManifestPath,
    signer,
    preparedDirectory,
  };
  const replaceRuntimeArtifact = async (id, bytes) => {
    const entry = artifactManifest.artifacts.find((artifact) => artifact.id === id);
    assert.notEqual(entry, undefined, `missing runtime artifact ${id}`);
    const data = Buffer.from(bytes);
    await writeFile(path.join(runtimeRoot, entry.path), data, { mode: 0o600 });
    entry.sha256 = sha256(data);
    await writeCanonical(runtimeBuildManifestPath, runtimeBuildManifest);
  };
  if (mutate !== undefined) await mutate({
    value, root, runtimeRoot, scannerRoot, runtimeBuildManifestPath,
    recoveryScannerManifestPath, scannerPath, outputDirectory, signerPair, signer,
    artifactManifest, runtimeBuildManifest, recoveryScannerManifest, authenticated,
    replaceRuntimeArtifact,
  });
  return { ...value, root, runtimeRoot, scannerRoot, outputDirectory, signerPair };
}

async function filesBelow(directory) {
  const entries = await readdir(directory, { recursive: true, withFileTypes: true });
  return entries.filter((entry) => entry.isFile()).map((entry) => entry.parentPath
    ? path.join(entry.parentPath, entry.name)
    : path.join(directory, entry.name));
}

async function assertMissing(target) {
  await assert.rejects(lstat(target), /ENOENT/);
}

const prepareInput = (subject) => ({
  finalizedGenesis: subject.finalizedGenesis,
  genesisRuntime: subject.genesisRuntime,
  runtimeBuildManifestPath: subject.runtimeBuildManifestPath,
  recoveryScannerManifestPath: subject.recoveryScannerManifestPath,
  signer: subject.signer,
  preparedDirectory: subject.preparedDirectory,
  ...(Object.hasOwn(subject, 'unexpected') ? { unexpected: subject.unexpected } : {}),
});

test('instance package module exposes the mandatory two-phase API', async () => {
  await packageApi();
});

test('prepare stages a canonical unsigned package and finalize atomically publishes an exact signed package', async (t) => {
  const api = await packageApi();
  const subject = await fixture(t);
  const prepared = await api.prepareV2InstancePackage({
    finalizedGenesis: subject.finalizedGenesis,
    genesisRuntime: subject.genesisRuntime,
    runtimeBuildManifestPath: subject.runtimeBuildManifestPath,
    recoveryScannerManifestPath: subject.recoveryScannerManifestPath,
    signer: subject.signer,
    preparedDirectory: subject.preparedDirectory,
  });
  assert.equal((await lstat(subject.preparedDirectory)).mode & 0o777, 0o700);
  for (const relative of [
    'manifest.json', 'instance.unsigned.json', 'signing-request.json',
    'genesis/genesis.raw.tx',
    'recovery/shieldkit-v2-recovery-scanner.manifest.json',
    'recovery/shieldkit-v2-recovery-scanner',
  ]) assert.equal((await lstat(path.join(subject.preparedDirectory, relative))).isFile(), true, relative);
  const [manifestBytes, unsignedBytes, requestBytes, rawGenesis] = await Promise.all([
    readFile(path.join(subject.preparedDirectory, 'manifest.json')),
    readFile(path.join(subject.preparedDirectory, 'instance.unsigned.json')),
    readFile(path.join(subject.preparedDirectory, 'signing-request.json')),
    readFile(path.join(subject.preparedDirectory, 'genesis/genesis.raw.tx')),
  ]);
  const manifest = JSON.parse(manifestBytes);
  const unsigned = JSON.parse(unsignedBytes);
  const request = JSON.parse(requestBytes);
  assert.equal(manifestBytes.toString('utf8'), canonicalizeJcs(manifest));
  assert.equal(unsignedBytes.toString('utf8'), canonicalizeJcs(unsigned));
  assert.equal(requestBytes.toString('utf8'), canonicalizeJcs(request));
  assert.deepEqual(manifest.artifacts.map((entry) => entry.id), [...manifest.artifacts.map((entry) => entry.id)].sort());
  assert.equal(rawGenesis.toString('hex'), subject.finalizedGenesis.genesis.rawTransactionHex);
  assert.equal(unsigned.signature, null);
  assert.equal(Object.hasOwn(unsigned, 'privateKey'), false);
  assert.deepEqual(request.signer, subject.signer);
  assert.equal(request.domain, INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN);
  assert.equal(request.version, INSTANCE_DESCRIPTOR_ATTESTATION_VERSION);
  assert.equal(request.descriptorSha256, sha256(unsignedBytes));
  assert.equal(request.manifestSha256, sha256(manifestBytes));
  const message = Buffer.from(request.messageBase64, 'base64');
  assert.equal(request.messageSha256, sha256(message));
  assert.deepEqual(message, descriptorAttestationBytes({
    descriptor: unsigned, canonicalManifestBytes: manifestBytes, signature: subject.signer,
  }));
  const signature = signEd25519(null, message, subject.signerPair.privateKey);
  await api.finalizeV2InstancePackage({
    preparedDirectory: subject.preparedDirectory, signature,
    outputDirectory: subject.outputDirectory, trustedSigners: [subject.signer],
  });
  assert.equal((await lstat(subject.outputDirectory)).mode & 0o777, 0o700);
  const instanceBytes = await readFile(path.join(subject.outputDirectory, 'instance.json'));
  const instance = JSON.parse(instanceBytes);
  assert.equal(instanceBytes.toString('utf8'), canonicalizeJcs(instance));
  assert.equal(instance.signature.signature, signature.toString('base64'));
  assert.equal(instance.signature.signerId, subject.signer.signerId);
  assert.equal((await lstat(path.join(subject.outputDirectory, 'manifest.json'))).isFile(), true);
  for (const file of await filesBelow(subject.preparedDirectory)) {
    assert.equal((await lstat(file)).nlink, 1, file);
    assert.equal((await readFile(file)).includes(PRIVATE_KEY_CANARY), false, file);
  }
  for (const file of await filesBelow(subject.outputDirectory)) {
    assert.equal((await lstat(file)).nlink, 1, file);
    assert.equal((await readFile(file)).includes(PRIVATE_KEY_CANARY), false, file);
  }
});

test('prepare rejects forged genesis, identity drift, noncanonical manifests, and unknown fields without publication residue', async (t) => {
  const api = await packageApi();
  const cases = [
    ['unknown option', async ({ value }) => { value.unexpected = true; }],
    ['cloned finalized genesis', async ({ value }) => { value.finalizedGenesis = { ...value.finalizedGenesis }; }],
    ['forged genesis transaction binding', async ({ value }) => {
      value.finalizedGenesis = {
        ...value.finalizedGenesis,
        genesis: { ...value.finalizedGenesis.genesis, transactionId: '33'.repeat(32) },
      };
    }],
    ['cloned runtime', async ({ value }) => { value.genesisRuntime = { ...value.genesisRuntime }; }],
    ['runtime instance mismatch', async ({ runtimeBuildManifestPath, runtimeBuildManifest }) => {
      await writeFile(runtimeBuildManifestPath, JSON.stringify({ ...runtimeBuildManifest, instanceId: '11'.repeat(32) }));
    }],
    ['runtime profile mismatch', async ({ runtimeBuildManifestPath, runtimeBuildManifest }) => {
      await writeCanonical(runtimeBuildManifestPath, { ...runtimeBuildManifest, profileId: '22'.repeat(32) });
    }],
    ['noncanonical runtime manifest', async ({ runtimeBuildManifestPath, runtimeBuildManifest }) => {
      await writeFile(runtimeBuildManifestPath, `${JSON.stringify(runtimeBuildManifest)}\n`);
    }],
    ['noncanonical scanner manifest', async ({ recoveryScannerManifestPath, recoveryScannerManifest }) => {
      await writeFile(recoveryScannerManifestPath, `${JSON.stringify(recoveryScannerManifest)}\n`);
    }],
    ['duplicate artifact ID', async ({ runtimeBuildManifestPath, runtimeBuildManifest }) => {
      const malformed = structuredClone(runtimeBuildManifest);
      malformed.artifactManifestTemplate.artifacts.push({ ...malformed.artifactManifestTemplate.artifacts[0] });
      await writeCanonical(runtimeBuildManifestPath, malformed);
    }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, async (t) => {
      const subject = await fixture(t, mutate);
      await assert.rejects(api.prepareV2InstancePackage(prepareInput(subject)));
      await assertMissing(subject.preparedDirectory);
    });
  }
});

test('prepare rejects hash drift, links, and path escape before copying a package', async (t) => {
  const api = await packageApi();
  const cases = [
    ['hash drift', async ({ scannerPath }) => { await writeFile(scannerPath, 'changed'); }],
    ['runtime bytes differ despite claimed digest', async ({ runtimeRoot }) => {
      await writeFile(
        path.join(runtimeRoot, 'runtime', 'pf10-runtime-material.json'),
        '{"runtime":"tampered"}',
      );
    }],
    ['missing scanner binary', async ({ scannerPath }) => { await rm(scannerPath); }],
    ['missing PF10 runtime artifact', async ({ runtimeRoot }) => {
      await rm(path.join(runtimeRoot, 'runtime', 'pf10-runtime-material.json'));
    }],
    ['symlinked runtime artifact', async ({ runtimeRoot }) => {
      const target = path.join(runtimeRoot, 'runtime', 'real.bin');
      await writeFile(target, 'real');
      await rm(path.join(runtimeRoot, 'runtime', 'pf10-runtime-material.json'));
      await symlink(target, path.join(runtimeRoot, 'runtime', 'pf10-runtime-material.json'));
    }],
    ['hardlinked scanner artifact', async ({ scannerPath, scannerRoot }) => {
      await link(scannerPath, path.join(scannerRoot, 'scanner-second-link'));
    }],
    ['manifest path escape', async ({ runtimeBuildManifestPath, runtimeBuildManifest }) => {
      const malformed = structuredClone(runtimeBuildManifest);
      malformed.artifactManifestTemplate.artifacts[0].path = '../escape';
      await writeCanonical(runtimeBuildManifestPath, malformed);
    }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, async (t) => {
      const subject = await fixture(t, mutate);
      await assert.rejects(api.prepareV2InstancePackage(prepareInput(subject)));
      await assertMissing(subject.preparedDirectory);
    });
  }
});

test('prepare rejects per-instance Libauth identity and runtime-digest drift', async (t) => {
  const api = await packageApi();
  const cases = [
    ['identity drift', async ({ runtimeRoot, replaceRuntimeArtifact }) => {
      const filename = path.join(runtimeRoot, 'qualification', 'pf10-libauth-evidence.json');
      const evidence = JSON.parse(await readFile(filename));
      evidence.identity.instanceId = '00'.repeat(32);
      await replaceRuntimeArtifact('pf10-libauth-evidence', Buffer.from(canonicalizeJcs(evidence)));
    }],
    ['runtime digest drift', async ({ runtimeRoot, replaceRuntimeArtifact }) => {
      const filename = path.join(runtimeRoot, 'qualification', 'pf10-libauth-evidence.json');
      const evidence = JSON.parse(await readFile(filename));
      evidence.identity.runtimeMaterialSha256 = '00'.repeat(32);
      await replaceRuntimeArtifact('pf10-libauth-evidence', Buffer.from(canonicalizeJcs(evidence)));
    }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, async (t) => {
      const subject = await fixture(t, mutate);
      await assert.rejects(api.prepareV2InstancePackage(prepareInput(subject)));
      await assertMissing(subject.preparedDirectory);
    });
  }
});

test('finalize revalidates staged bytes and rejects untrusted, malformed, duplicate, or replayed signatures without final residue', async (t) => {
  const api = await packageApi();
  const subject = await fixture(t);
  await api.prepareV2InstancePackage(prepareInput(subject));
  const request = JSON.parse(await readFile(path.join(subject.preparedDirectory, 'signing-request.json')));
  const signature = signEd25519(null, Buffer.from(request.messageBase64, 'base64'), subject.signerPair.privateKey);
  const cases = [
    ['bad signature', Buffer.alloc(64), [subject.signer], undefined],
    ['untrusted signer', signature, [{ ...subject.signer, signerId: 'other-signer' }], undefined],
    ['duplicate trusted ID', signature, [subject.signer, subject.signer], undefined],
    ['prepared manifest drift', signature, [subject.signer], async () => {
      await writeFile(path.join(subject.preparedDirectory, 'manifest.json'), '{}');
    }],
  ];
  for (const [label, candidate, trustedSigners, mutate] of cases) {
    await t.test(label, async () => {
      if (mutate !== undefined) await mutate();
      await assert.rejects(api.finalizeV2InstancePackage({
        preparedDirectory: subject.preparedDirectory, signature: candidate,
        outputDirectory: subject.outputDirectory, trustedSigners,
      }));
      await assertMissing(subject.outputDirectory);
      assert.equal((await lstat(subject.preparedDirectory)).isDirectory(), true);
    });
  }
});

test('finalize rejects signed genesis-package-binding drift even after trusted re-signing', async (t) => {
  const api = await packageApi();
  const subject = await fixture(t);
  await api.prepareV2InstancePackage(prepareInput(subject));
  const [manifestBytes, unsignedBytes, requestBytes, bindingBytes] = await Promise.all([
    readFile(path.join(subject.preparedDirectory, 'manifest.json')),
    readFile(path.join(subject.preparedDirectory, 'instance.unsigned.json')),
    readFile(path.join(subject.preparedDirectory, 'signing-request.json')),
    readFile(path.join(subject.preparedDirectory, 'genesis', 'binding.json')),
  ]);
  const manifest = JSON.parse(manifestBytes);
  const unsigned = JSON.parse(unsignedBytes);
  const request = JSON.parse(requestBytes);
  const binding = JSON.parse(bindingBytes);
  binding.runtimeMaterialSha256 = '00'.repeat(32);
  const replacementBindingBytes = Buffer.from(canonicalizeJcs(binding));
  const bindingArtifact = manifest.artifacts.find(
    (artifact) => artifact.id === 'genesis-package-binding',
  );
  assert.notEqual(bindingArtifact, undefined);
  bindingArtifact.sha256 = sha256(replacementBindingBytes);
  const replacementManifestBytes = Buffer.from(canonicalizeJcs(manifest));
  unsigned.manifest.sha256 = sha256(replacementManifestBytes);
  const replacementUnsignedBytes = Buffer.from(canonicalizeJcs(unsigned));
  const message = descriptorAttestationBytes({
    descriptor: unsigned,
    canonicalManifestBytes: replacementManifestBytes,
    signature: subject.signer,
  });
  request.descriptorSha256 = sha256(replacementUnsignedBytes);
  request.manifestSha256 = sha256(replacementManifestBytes);
  request.messageBase64 = message.toString('base64');
  request.messageSha256 = sha256(message);
  await Promise.all([
    writeFile(path.join(subject.preparedDirectory, 'manifest.json'), replacementManifestBytes),
    writeFile(path.join(subject.preparedDirectory, 'genesis', 'binding.json'), replacementBindingBytes),
    writeFile(path.join(subject.preparedDirectory, 'instance.unsigned.json'), replacementUnsignedBytes),
    writeCanonical(path.join(subject.preparedDirectory, 'signing-request.json'), request),
  ]);
  const signature = signEd25519(null, message, subject.signerPair.privateKey);
  await assert.rejects(api.finalizeV2InstancePackage({
    preparedDirectory: subject.preparedDirectory,
    signature,
    outputDirectory: subject.outputDirectory,
    trustedSigners: [subject.signer],
  }));
  await assertMissing(subject.outputDirectory);
});

test('prepare and final publication are non-overwriting', async (t) => {
  const api = await packageApi();
  const subject = await fixture(t);
  await mkdir(subject.preparedDirectory, { mode: 0o700 });
  await assert.rejects(api.prepareV2InstancePackage(prepareInput(subject)));
  await rm(subject.preparedDirectory, { recursive: true, force: true });
  await api.prepareV2InstancePackage(prepareInput(subject));
  const request = JSON.parse(await readFile(path.join(subject.preparedDirectory, 'signing-request.json')));
  const signature = signEd25519(null, Buffer.from(request.messageBase64, 'base64'), subject.signerPair.privateKey);
  await mkdir(subject.outputDirectory, { mode: 0o700 });
  const foreign = path.join(subject.outputDirectory, 'foreign-user-file');
  await writeFile(foreign, 'preserve-me', { mode: 0o600 });
  await assert.rejects(api.finalizeV2InstancePackage({
    preparedDirectory: subject.preparedDirectory, signature,
    outputDirectory: subject.outputDirectory, trustedSigners: [subject.signer],
  }));
  assert.equal((await lstat(subject.outputDirectory)).isDirectory(), true);
  assert.equal(await readFile(foreign, 'utf8'), 'preserve-me');
});
