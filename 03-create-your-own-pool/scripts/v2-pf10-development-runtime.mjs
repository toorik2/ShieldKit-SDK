#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  rename,
  realpath,
  rm,
  stat,
} from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  buildDirectV2Pf10DevelopmentRuntime,
} from '../packages/unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  verifyV2DevelopmentProfilePackage,
} from '../packages/profile/v2/development-profile.mjs';
import {
  ARTIFACT_MANIFEST_SCHEMA,
  PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
  PF10_RUNTIME_ARTIFACT_SCHEMA,
  PF10_RUNTIME_MANIFEST_ARTIFACT_ID,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../packages/action/v2/topology.mjs';

export const V2_PF10_DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA =
  'shieldkit-v2-direct-pf10-development-runtime-bundle-v2';
export const V2_PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA =
  PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA;

const OPTIONS = Object.freeze({
  '--instance-id': Object.freeze({ name: 'instanceId', path: false }),
  '--output': Object.freeze({ name: 'outputDirectory', path: true }),
  '--profile-core': Object.freeze({ name: 'profileCorePath', path: true }),
  '--profile-package': Object.freeze({
    name: 'profilePackagePath',
    path: true,
  }),
  '--qualification-evidence': Object.freeze({
    name: 'qualificationEvidencePath',
    path: true,
  }),
  '--libauth-evidence': Object.freeze({
    name: 'libauthEvidencePath',
    path: true,
  }),
  '--temporary-root': Object.freeze({ name: 'temporaryRoot', path: true }),
});
const HASH = /^[0-9a-f]{64}$/;

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

function fail(message) {
  throw new Error(message);
}

export function parseV2Pf10DevelopmentRuntimeArguments(
  argv,
  cwd = process.cwd(),
) {
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const definition = OPTIONS[option];
    if (definition === undefined) {
      fail(`unknown or positional CLI argument: ${String(option)}`);
    }
    if (Object.hasOwn(parsed, definition.name)) {
      fail(`duplicate CLI option: ${option}`);
    }
    const value = argv[index + 1];
    if (
      typeof value !== 'string'
      || value.length === 0
      || value.startsWith('--')
    ) {
      fail(`missing value for ${option}`);
    }
    parsed[definition.name] = definition.path
      ? path.resolve(cwd, value)
      : value;
  }
  for (const [option, definition] of Object.entries(OPTIONS)) {
    if (!Object.hasOwn(parsed, definition.name)) {
      fail(`missing required CLI option: ${option}`);
    }
  }
  if (!HASH.test(parsed.instanceId)) {
    fail('--instance-id must be 32 lowercase hexadecimal bytes');
  }
  return Object.freeze(parsed);
}

function repositoryRelative(repositoryRoot, filename, label = 'path') {
  const relative = path.relative(repositoryRoot, filename);
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail(`${label} must be repository-local`);
  }
  return relative.split(path.sep).join('/');
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function stableFileBytes(repositoryRoot, value, label) {
  const filename = path.resolve(value);
  repositoryRelative(repositoryRoot, filename, label);
  let initial;
  let canonical;
  try {
    initial = await lstat(filename, { bigint: true });
    canonical = await realpath(filename);
  } catch (error) {
    fail(`${label} is not readable: ${error.message}`);
  }
  if (
    !initial.isFile()
    || initial.isSymbolicLink()
    || initial.nlink !== 1n
    || initial.size === 0n
    || canonical !== filename
    || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail(`${label} must be one nonempty canonical regular file`);
  }
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || !sameIdentity(initial, before)
      || before.size !== initial.size
    ) {
      fail(`${label} changed before it could be read safely`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(filename, { bigint: true });
    const canonicalAfter = await realpath(filename);
    if (
      !sameIdentity(initial, after)
      || !sameIdentity(initial, pathAfter)
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || bytes.length !== Number(before.size)
      || canonicalAfter !== filename
    ) {
      fail(`${label} changed while it was read`);
    }
    return Object.freeze({
      filename,
      repositoryPath: repositoryRelative(repositoryRoot, filename, label),
      bytes,
      sha256: sha256(bytes),
    });
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function canonicalJson(repositoryRoot, filename, label) {
  const record = await stableFileBytes(repositoryRoot, filename, label);
  const { bytes } = record;
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return Object.freeze({ ...record, value });
}

async function safeOutputParent(repositoryRoot, value) {
  if (value === repositoryRoot) {
    if ((await stat(repositoryRoot)).mode & 0o022) {
      fail('repository root must not be writable by group or other users');
    }
    return;
  }
  const relative = repositoryRelative(repositoryRoot, value, 'output parent');
  let current = repositoryRoot;
  for (const component of relative.split('/')) {
    current = path.join(current, component);
    let metadata;
    let created = false;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await mkdir(current, { mode: 0o700 });
      metadata = await lstat(current);
      created = true;
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail('output parent must contain only non-symlink directories');
    }
    if (await realpath(current) !== current) {
      fail('output parent must be canonical');
    }
    if (created) await chmod(current, 0o700);
    if ((await stat(current)).mode & 0o022) {
      fail('output parent must not be writable by group or other users');
    }
  }
}

async function privateOutputStage(repositoryRoot, value) {
  const output = path.resolve(value);
  repositoryRelative(repositoryRoot, output, 'output directory');
  try {
    await lstat(output);
    fail('output directory must not already exist');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const parent = path.dirname(output);
  await safeOutputParent(repositoryRoot, parent);
  const parentMetadata = await lstat(parent);
  if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()) {
    fail('output parent must be a non-symlink directory');
  }
  const stage = await mkdtemp(path.join(parent, '.pf10-runtime-stage-'));
  // mkdtemp created this path; nevertheless inspect it before changing mode.
  const stageMetadata = await lstat(stage);
  if (!stageMetadata.isDirectory() || stageMetadata.isSymbolicLink()) {
    fail('runtime staging directory is unsafe');
  }
  await chmod(stage, 0o700);
  return Object.freeze({ output, parent, stage });
}

async function syncDirectory(directory) {
  const handle = await open(directory, fsConstants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function publishStage(stage, output, parent) {
  await syncDirectory(stage);
  try {
    await lstat(output);
    fail('output directory appeared during bundle creation');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await rename(stage, output);
  await syncDirectory(parent);
}

async function writeExactFile(filename, data) {
  let handle;
  try {
    handle = await open(filename, 'wx', 0o600);
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset);
    if (bytesWritten === 0) fail('file write made no progress');
    offset += bytesWritten;
  }
}

async function writeArtifact(output, artifacts, id, relative, bytes) {
  const data = Buffer.from(bytes);
  if (data.length === 0) fail(`artifact ${id} must be nonempty`);
  const filename = path.join(output, relative);
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await writeExactFile(filename, data);
  const entry = Object.freeze({
    id,
    path: relative.split(path.sep).join('/'),
    sha256: sha256(data),
    bytes: data.length,
  });
  artifacts.push(entry);
  return entry;
}

function descriptorEntry(entry) {
  return Object.freeze({
    id: entry.id,
    path: entry.path,
    sha256: entry.sha256,
  });
}

function proofRecord(repositoryRoot, value, expectedHash, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || typeof value.path !== 'string'
    || typeof value.sha256 !== 'string'
    || value.sha256 !== expectedHash
    || !HASH.test(value.sha256)
  ) {
    fail(`${label} is not bound to the profile core`);
  }
  const filename = path.resolve(repositoryRoot, value.path);
  repositoryRelative(repositoryRoot, filename, label);
  return Object.freeze({ path: filename, sha256: value.sha256 });
}

async function copyPinnedArtifact(
  repositoryRoot,
  output,
  artifacts,
  id,
  relative,
  value,
  label,
) {
  const filename = path.resolve(value.path);
  repositoryRelative(repositoryRoot, filename, label);
  const initial = await lstat(filename, { bigint: true });
  if (
    !initial.isFile()
    || initial.isSymbolicLink()
    || initial.nlink !== 1n
    || initial.size === 0n
    || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
    || await realpath(filename) !== filename
  ) {
    fail(`${label} must be one nonempty canonical regular file`);
  }
  const destination = path.join(output, relative);
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  let input;
  let destinationHandle;
  try {
    input = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await input.stat({ bigint: true });
    if (!sameIdentity(initial, before) || before.size !== initial.size) {
      fail(`${label} changed before it could be copied safely`);
    }
    destinationHandle = await open(destination, 'wx', 0o600);
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (position < Number(before.size)) {
      const { bytesRead } = await input.read(
        buffer,
        0,
        Math.min(buffer.length, Number(before.size) - position),
        position,
      );
      if (bytesRead === 0) fail(`${label} ended while being copied`);
      const chunk = buffer.subarray(0, bytesRead);
      digest.update(chunk);
      await writeAll(destinationHandle, chunk);
      position += bytesRead;
    }
    await destinationHandle.sync();
    const after = await input.stat({ bigint: true });
    const pathAfter = await lstat(filename, { bigint: true });
    if (
      !sameIdentity(initial, after)
      || !sameIdentity(initial, pathAfter)
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || await realpath(filename) !== filename
    ) {
      fail(`${label} changed while it was copied`);
    }
    const digestValue = digest.digest('hex');
    if (digestValue !== value.sha256) {
      fail(`${label} SHA-256 differs from the profile pin`);
    }
    const entry = Object.freeze({
      id,
      path: relative.split(path.sep).join('/'),
      sha256: digestValue,
      bytes: position,
    });
    artifacts.push(entry);
    return entry;
  } finally {
    if (destinationHandle !== undefined) await destinationHandle.close();
    if (input !== undefined) await input.close();
  }
}

async function pinnedPackageArtifact(
  repositoryRoot,
  packageFile,
  profilePackage,
  name,
  label,
) {
  const expected = profilePackage.generatedArtifacts[name];
  const filename = path.resolve(path.dirname(packageFile.filename), expected.path);
  const record = await canonicalJson(repositoryRoot, filename, label);
  if (record.bytes.length !== expected.bytes || record.sha256 !== expected.sha256) {
    fail(`${label} differs from the profile package pin`);
  }
  return record;
}

async function qualificationEvidence(
  repositoryRoot,
  filename,
  profileId,
  instanceId,
  profilePackage,
) {
  const source = await stableFileBytes(
    repositoryRoot,
    filename,
    'qualification evidence',
  );
  const { bytes } = source;
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`qualification evidence is not JSON: ${error.message}`);
  }
  if (
    value?.schema
      !== 'shieldkit-v2-direct-development-groth16-qualification-v4'
    || value.evidenceClass
      !== 'deterministic-development-key-proof-test-evidence'
    || value.claims?.developmentKey !== true
    || value.claims?.finalKey !== false
    || value.claims?.bchVm !== false
    || value.claims?.production !== false
    || value.identity?.profileId !== profileId
    || value.identity?.instanceId !== instanceId
    || value.identity?.maximumLiveNotes !== '32'
    || value.identity?.denominationSats !== '10000000'
    || value.sourceArtifacts?.r1cs?.sha256
      !== profilePackage.proofArtifacts.r1cs.sha256
    || value.sourceArtifacts?.wasm?.sha256
      !== profilePackage.proofArtifacts.witnessWasm.sha256
    || value.sourceArtifacts?.verificationKey?.sha256
      !== profilePackage.proofArtifacts.verificationKey.sha256
    || value.sourceArtifacts?.developmentZkey?.sha256
      !== profilePackage.proofArtifacts.provingKey.sha256
  ) {
    fail('qualification evidence is not bound to this profile and instance');
  }
  for (const name of ['deposit', 'transfer', 'withdrawal']) {
    const adapter = value.actions?.[name]?.files?.v2DirectGroth16Adapter;
    if (
      value.actions?.[name]?.witnessValid !== true
      || value.actions?.[name]?.proofVerified !== true
      || adapter === null
      || typeof adapter !== 'object'
      || !Number.isSafeInteger(adapter.bytes)
      || adapter.bytes <= 0
      || typeof adapter.path !== 'string'
      || adapter.path.length === 0
      || !HASH.test(adapter.sha256)
    ) {
      fail(`qualification evidence does not verify ${name} with a pinned V2 Direct Groth16 adapter`);
    }
  }
  const record = Object.freeze({
    schema: V2_PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
    qualificationSchema: value.schema,
    evidenceClass: value.evidenceClass,
    identity: Object.freeze({
      profileId: value.identity.profileId,
      instanceId: value.identity.instanceId,
      maximumLiveNotes: value.identity.maximumLiveNotes,
      denominationSats: value.identity.denominationSats,
    }),
    claims: Object.freeze({
      developmentKey: value.claims.developmentKey,
      finalKey: value.claims.finalKey,
      bchVm: value.claims.bchVm,
      production: value.claims.production,
    }),
    sourceArtifacts: Object.freeze({
      r1csSha256: value.sourceArtifacts.r1cs.sha256,
      witnessWasmSha256: value.sourceArtifacts.wasm.sha256,
      verificationKeySha256: value.sourceArtifacts.verificationKey.sha256,
      developmentZkeySha256: value.sourceArtifacts.developmentZkey.sha256,
    }),
    rawEvidenceSha256: source.sha256,
    actions: Object.freeze(Object.fromEntries(
      ['deposit', 'transfer', 'withdrawal'].map((name) => [
        name,
        Object.freeze({ witnessValid: true, proofVerified: true }),
      ]),
    )),
  });
  const recordBytes = canonicalBytes(record);
  return Object.freeze({
    record,
    recordBytes,
    rawTelemetryBytes: bytes,
    rawTelemetrySha256: source.sha256,
  });
}

export async function runV2Pf10DevelopmentRuntime(
  argv,
  {
    cwd = process.cwd(),
    repositoryRoot = path.resolve(import.meta.dirname, '../..'),
  } = {},
) {
  const options = parseV2Pf10DevelopmentRuntimeArguments(argv, cwd);
  const canonicalRepositoryRoot = await realpath(repositoryRoot);
  if (canonicalRepositoryRoot !== repositoryRoot) {
    fail('repository root must be canonical');
  }
  const profile = await canonicalJson(
    canonicalRepositoryRoot,
    options.profileCorePath,
    'profile core',
  );
  validateProfileCore(profile.value);
  const profileId = deriveProfileId(profile.value);
  const packageFile = await canonicalJson(
    canonicalRepositoryRoot,
    options.profilePackagePath,
    'development profile package',
  );
  const profilePackage = await verifyV2DevelopmentProfilePackage(
    packageFile.value,
    {
      directory: path.dirname(packageFile.filename),
      repositoryRoot: canonicalRepositoryRoot,
    },
  );
  if (
    profilePackage.profileId !== profileId
    || profilePackage.profileCoreSha256 !== profile.sha256
    || profilePackage.proofArtifacts.r1cs.sha256
      !== profile.value.proof.r1csSha256
    || profilePackage.proofArtifacts.verificationKey.sha256
      !== profile.value.proof.verificationKeySha256
    || profilePackage.proofArtifacts.witnessWasm.sha256
      !== profile.value.proof.witnessWasmSha256
  ) {
    fail('profile package differs from the supplied profile core');
  }
  const evidence = await qualificationEvidence(
    canonicalRepositoryRoot,
    options.qualificationEvidencePath,
    profileId,
    options.instanceId,
    profilePackage,
  );
  const libauthEvidence = await canonicalJson(
    canonicalRepositoryRoot,
    options.libauthEvidencePath,
    'per-instance PF10 Libauth evidence',
  );
  const profileProofArtifacts = Object.freeze({
    circuitSymbols: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.circuitSymbols,
      profilePackage.proofArtifacts.circuitSymbols.sha256,
      'circuit symbol table',
    ),
    initialProvingKey: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.initialProvingKey,
      profilePackage.proofArtifacts.initialProvingKey.sha256,
      'development initial proving key',
    ),
    powersOfTau: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.powersOfTau,
      profilePackage.proofArtifacts.powersOfTau.sha256,
      'development Powers of Tau',
    ),
    provingKey: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.provingKey,
      profilePackage.proofArtifacts.provingKey.sha256,
      'development proving key',
    ),
    r1cs: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.r1cs,
      profile.value.proof.r1csSha256,
      'R1CS',
    ),
    verificationKey: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.verificationKey,
      profile.value.proof.verificationKeySha256,
      'verification key',
    ),
    witnessWasm: proofRecord(
      canonicalRepositoryRoot,
      profilePackage.proofArtifacts.witnessWasm,
      profile.value.proof.witnessWasmSha256,
      'witness WASM',
    ),
  });
  const proofArtifacts = Object.freeze({
    provingKey: profileProofArtifacts.provingKey,
    r1cs: profileProofArtifacts.r1cs,
    verificationKey: profileProofArtifacts.verificationKey,
    wasm: profileProofArtifacts.witnessWasm,
  });
  const prerequisites = Object.freeze({
    baseVerifierManifest: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'baseVerifierManifest',
      'base verifier source manifest',
    ),
    circuitBuildAttestation: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'circuitBuildAttestation',
      'circuit build attestation',
    ),
    developmentSetupAttestation: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'developmentSetupAttestation',
      'development setup attestation',
    ),
    toolchainManifest: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'toolchainManifest',
      'toolchain manifest',
    ),
    relationManifest: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'relationManifest',
      'relation source manifest',
    ),
    topologySpec: await pinnedPackageArtifact(
      canonicalRepositoryRoot,
      packageFile,
      profilePackage,
      'topologySpec',
      'PF10 topology specification',
    ),
  });
  const build = await buildDirectV2Pf10DevelopmentRuntime({
    repositoryRoot: canonicalRepositoryRoot,
    temporaryRoot: options.temporaryRoot,
    profileId,
    instanceId: options.instanceId,
    proofArtifacts,
    libauthEvidence: {
      path: libauthEvidence.filename,
      sha256: libauthEvidence.sha256,
    },
  });
  if (build.libauthEvidence === undefined) {
    fail('PF10 Libauth evidence is required for a development runtime bundle');
  }
  const outputStage = await privateOutputStage(
    canonicalRepositoryRoot,
    options.outputDirectory,
  );
  const { output, parent, stage } = outputStage;
  try {
  const artifacts = [];
  const runtimeIds = Object.freeze({
    proof: Object.freeze({
      provingKey: 'proof-proving-key',
      r1cs: 'proof-r1cs',
      verificationKey: 'proof-verification-key',
      wasm: 'proof-witness-wasm',
    }),
    executorBody: 'pf10-executor-body',
    exactMsmRedeems: Object.freeze([
      'pf10-exact-msm-redeem-0',
      'pf10-exact-msm-redeem-1',
      'pf10-exact-msm-redeem-2',
    ]),
    fixedCarrierPads: Object.freeze([
      'pf10-fixed-carrier-pad-0',
      'pf10-fixed-carrier-pad-1',
      'pf10-fixed-carrier-pad-2',
    ]),
    fusedRedeem: 'pf10-fused-redeem',
    terminalRedeem: 'pf10-terminal-redeem',
    qualificationEvidence: 'pf10-qualification-evidence',
    rawQualificationEvidence: 'pf10-qualification-raw-evidence',
    libauthEvidence: 'pf10-libauth-evidence',
    profileCore: 'profile-core',
    profilePackage: 'development-profile-package',
    baseVerifierManifest: 'pf10-base-verifier-sources',
    circuitBuildAttestation: 'circuit-build-attestation',
    developmentSetupAttestation: 'development-setup-attestation',
    relationManifest: 'relation-source-manifest',
    topologySpec: 'pf10-topology-spec',
    toolchainManifest: 'toolchain-manifest',
    circuitSymbols: 'proof-circuit-symbols',
    initialProvingKey: 'proof-initial-proving-key',
    powersOfTau: 'proof-powers-of-tau',
  });
  const profileProofIds = Object.freeze({
    circuitSymbols: runtimeIds.circuitSymbols,
    initialProvingKey: runtimeIds.initialProvingKey,
    powersOfTau: runtimeIds.powersOfTau,
    provingKey: runtimeIds.proof.provingKey,
    r1cs: runtimeIds.proof.r1cs,
    verificationKey: runtimeIds.proof.verificationKey,
    witnessWasm: runtimeIds.proof.wasm,
  });
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.profileCore,
    'profile/profile-core.json',
    profile.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.profilePackage,
    'profile/profile-package.json',
    packageFile.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.baseVerifierManifest,
    'reproducibility/prerequisites/base-verifier-manifest.json',
    prerequisites.baseVerifierManifest.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.circuitBuildAttestation,
    'reproducibility/prerequisites/circuit-build-attestation.json',
    prerequisites.circuitBuildAttestation.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.developmentSetupAttestation,
    'reproducibility/prerequisites/development-setup-attestation.json',
    prerequisites.developmentSetupAttestation.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.relationManifest,
    'reproducibility/prerequisites/relation-manifest.json',
    prerequisites.relationManifest.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.topologySpec,
    'reproducibility/prerequisites/pf10-topology-spec.json',
    prerequisites.topologySpec.bytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.toolchainManifest,
    'reproducibility/prerequisites/toolchain-manifest.json',
    prerequisites.toolchainManifest.bytes,
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.circuitSymbols,
    'proof/main-chipnet.sym',
    profileProofArtifacts.circuitSymbols,
    'circuit symbol table',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.initialProvingKey,
    'proof/initial.zkey',
    profileProofArtifacts.initialProvingKey,
    'development initial proving key',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.powersOfTau,
    'proof/powers-of-tau.ptau',
    profileProofArtifacts.powersOfTau,
    'development Powers of Tau',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.proof.provingKey,
    'proof/development.zkey',
    proofArtifacts.provingKey,
    'development proving key',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.proof.r1cs,
    'proof/main-chipnet.r1cs',
    proofArtifacts.r1cs,
    'R1CS',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.proof.verificationKey,
    'proof/verification_key.json',
    proofArtifacts.verificationKey,
    'verification key',
  );
  await copyPinnedArtifact(
    canonicalRepositoryRoot,
    stage,
    artifacts,
    runtimeIds.proof.wasm,
    'proof/main-chipnet.wasm',
    proofArtifacts.wasm,
    'witness WASM',
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.executorBody,
    'runtime/executor-body.bin',
    build.runtimeMaterialInput.executorBody,
  );
  for (let index = 0; index < 3; index += 1) {
    await writeArtifact(
      stage,
      artifacts,
      runtimeIds.exactMsmRedeems[index],
      `runtime/exact-msm-redeem-${index}.bin`,
      build.runtimeMaterialInput.exactMsmRedeems[index],
    );
    await writeArtifact(
      stage,
      artifacts,
      runtimeIds.fixedCarrierPads[index],
      `runtime/fixed-carrier-pad-${index}.bin`,
      build.runtimeMaterialInput.fixedCarrierPads[index],
    );
  }
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.fusedRedeem,
    'runtime/fused-redeem.bin',
    build.runtimeMaterialInput.fusedRedeem,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.terminalRedeem,
    'runtime/terminal-redeem.bin',
    build.runtimeMaterialInput.terminalRedeem,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.qualificationEvidence,
    'qualification/development-proof-evidence.json',
    evidence.recordBytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.rawQualificationEvidence,
    'qualification/raw-development-proof-evidence.json',
    evidence.rawTelemetryBytes,
  );
  await writeArtifact(
    stage,
    artifacts,
    runtimeIds.libauthEvidence,
    'qualification/pf10-libauth-evidence.json',
    build.libauthEvidence.data,
  );

  const structuralIds = {
    bindingLock: 'binding-lock',
    bindingRedeem: 'binding-redeem',
    stateHelper: 'state-helper',
    stateUnlock: 'state-helper-unlock',
    stateLock: 'state-lock',
    verifierLocks: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.map(
      (_, index) => `verifier-lock-${index}`,
    ),
  };
  for (const [id, relative, bytes] of [
    [
      structuralIds.bindingLock,
      'structural/binding-lock.bin',
      build.structural.bindingLock,
    ],
    [
      structuralIds.bindingRedeem,
      'structural/binding-redeem.bin',
      build.structural.bindingRedeem,
    ],
    [
      structuralIds.stateHelper,
      'structural/state-helper.bin',
      build.structural.stateHelper,
    ],
    [
      structuralIds.stateUnlock,
      'structural/state-helper-unlock.bin',
      build.structural.stateUnlock,
    ],
    [
      structuralIds.stateLock,
      'structural/state-lock.bin',
      build.structural.stateLock,
    ],
  ]) {
    await writeArtifact(stage, artifacts, id, relative, bytes);
  }
  for (let index = 0; index < build.structural.verifierLocks.length; index += 1) {
    await writeArtifact(
      stage,
      artifacts,
      structuralIds.verifierLocks[index],
      `structural/verifier-lock-${index}.bin`,
      build.structural.verifierLocks[index],
    );
  }

  for (const [name, program] of Object.entries({
    executor: build.programs.executor,
    exactFinal: build.programs.exactFinal,
    miller: build.programs.miller,
    terminal: build.programs.terminal,
  })) {
    await writeArtifact(
      stage,
      artifacts,
      `repro-${name.toLowerCase()}-source`,
      `reproducibility/${name}.cash`,
      Buffer.from(program.source, 'utf8'),
    );
    await writeArtifact(
      stage,
      artifacts,
      `repro-${name.toLowerCase()}-raw`,
      `reproducibility/${name}.raw.bin`,
      program.raw,
    );
  }
  for (let index = 0; index < build.programs.exactMsm.length; index += 1) {
    const program = build.programs.exactMsm[index];
    await writeArtifact(
      stage,
      artifacts,
      `repro-exact-msm-${index}-source`,
      `reproducibility/exact-msm-${index}.cash`,
      Buffer.from(program.source, 'utf8'),
    );
    await writeArtifact(
      stage,
      artifacts,
      `repro-exact-msm-${index}-raw`,
      `reproducibility/exact-msm-${index}.raw.bin`,
      program.raw,
    );
  }

  const runtimeArtifact = Object.freeze({
    schema: PF10_RUNTIME_ARTIFACT_SCHEMA,
    eligibility: 'development-only',
    profileId,
    instanceId: options.instanceId,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    profileArtifacts: Object.freeze({
      profileCoreArtifactId: runtimeIds.profileCore,
      profilePackageArtifactId: runtimeIds.profilePackage,
      baseVerifierManifestArtifactId: runtimeIds.baseVerifierManifest,
      topologySpecArtifactId: runtimeIds.topologySpec,
      toolchainManifestArtifactId: runtimeIds.toolchainManifest,
    }),
    attestationArtifacts: Object.freeze({
      circuitBuildAttestationArtifactId:
        runtimeIds.circuitBuildAttestation,
      developmentSetupAttestationArtifactId:
        runtimeIds.developmentSetupAttestation,
      relationManifestArtifactId: runtimeIds.relationManifest,
    }),
    setupArtifacts: Object.freeze({
      circuitSymbolsArtifactId: runtimeIds.circuitSymbols,
      initialProvingKeyArtifactId: runtimeIds.initialProvingKey,
      powersOfTauArtifactId: runtimeIds.powersOfTau,
    }),
    proofArtifacts: Object.freeze({
      provingKeyArtifactId: runtimeIds.proof.provingKey,
      r1csArtifactId: runtimeIds.proof.r1cs,
      verificationKeyArtifactId: runtimeIds.proof.verificationKey,
      witnessWasmArtifactId: runtimeIds.proof.wasm,
    }),
    unlockArtifacts: Object.freeze({
      executorBodyArtifactId: runtimeIds.executorBody,
      exactMsmRedeemArtifactIds: runtimeIds.exactMsmRedeems,
      fixedCarrierPadArtifactIds: runtimeIds.fixedCarrierPads,
      fusedRedeemArtifactId: runtimeIds.fusedRedeem,
      terminalRedeemArtifactId: runtimeIds.terminalRedeem,
    }),
    qualificationEvidenceArtifactId: runtimeIds.qualificationEvidence,
    rawQualificationEvidenceArtifactId: runtimeIds.rawQualificationEvidence,
    libauthEvidenceArtifactId: runtimeIds.libauthEvidence,
  });
  await writeArtifact(
    stage,
    artifacts,
    PF10_RUNTIME_MANIFEST_ARTIFACT_ID,
    'runtime/pf10-runtime-material.json',
    canonicalBytes(runtimeArtifact),
  );

  artifacts.sort((left, right) => left.id.localeCompare(right.id));
  const artifactById = new Map(artifacts.map((entry) => [entry.id, entry]));
  const bundleArtifactRecord = (id) => {
    const entry = artifactById.get(id);
    if (entry === undefined) fail(`missing emitted artifact: ${id}`);
    return Object.freeze({
      id: entry.id,
      path: entry.path,
      bytes: entry.bytes,
      sha256: entry.sha256,
    });
  };
  const buildManifest = Object.freeze({
    schema: V2_PF10_DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA,
    eligibility: 'development-only',
    profileId,
    instanceId: options.instanceId,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    proofArtifacts: Object.freeze(Object.fromEntries(
      Object.keys(profileProofArtifacts).map((name) => [
        name,
        bundleArtifactRecord(profileProofIds[name]),
      ]),
    )),
    profileCore: bundleArtifactRecord(runtimeIds.profileCore),
    profilePackage: bundleArtifactRecord(runtimeIds.profilePackage),
    prerequisites: Object.freeze({
      circuitBuildAttestation: bundleArtifactRecord(
        runtimeIds.circuitBuildAttestation,
      ),
      developmentSetupAttestation: bundleArtifactRecord(
        runtimeIds.developmentSetupAttestation,
      ),
      relationSourceManifest: bundleArtifactRecord(
        runtimeIds.relationManifest,
      ),
      baseVerifierSourceManifest: bundleArtifactRecord(
        runtimeIds.baseVerifierManifest,
      ),
      topologySpec: bundleArtifactRecord(runtimeIds.topologySpec),
      toolchainManifest: bundleArtifactRecord(runtimeIds.toolchainManifest),
      semantics: 'The copied canonical profile, build/setup attestations, relation graph, full development setup artifacts, and verifier/toolchain manifests are content-bound by this artifact manifest.',
    }),
    determinism: Object.freeze({
      runtimeMaterial: Object.freeze({
        deterministic: true,
        scope: 'Pinned profile core, copied proof artifacts, copied prerequisite manifests, and the locked builder toolchain.',
      }),
      qualificationTelemetry: Object.freeze({
        deterministic: false,
        signedArtifacts: 'canonical qualification record and exact raw v4 campaign telemetry',
        rawTelemetryIncluded: true,
        reason: 'Fresh qualification campaigns can vary in timings and campaign-local paths, so the whole signed bundle is not claimed byte-deterministic.',
      }),
    }),
    artifactManifestTemplate: Object.freeze({
      schema: ARTIFACT_MANIFEST_SCHEMA,
      profileId,
      instanceId: options.instanceId,
      artifacts: Object.freeze(artifacts.map(descriptorEntry)),
    }),
    finalLocks: Object.freeze({
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifiers: Object.freeze(
        DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.map((role, index) =>
          Object.freeze({
            role,
            lockingArtifactId: structuralIds.verifierLocks[index],
            baseSats: build.baseValues.verifierSats[index],
          })),
      ),
      binding: Object.freeze({
        lockingArtifactId: structuralIds.bindingLock,
        redeemArtifactId: structuralIds.bindingRedeem,
        baseSats: build.baseValues.bindingSats,
      }),
      state: Object.freeze({
        lockingArtifactId: structuralIds.stateLock,
        helperArtifactId: structuralIds.stateHelper,
        helperUnlockArtifactId: structuralIds.stateUnlock,
        baseSats: build.baseValues.stateSats,
      }),
    }),
    qualification: Object.freeze({
      canonicalRecord: bundleArtifactRecord(runtimeIds.qualificationEvidence),
      canonicalRecordSchema: V2_PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
      rawEvidence: bundleArtifactRecord(runtimeIds.rawQualificationEvidence),
      rawTelemetryIncluded: true,
    }),
    libauthEvidence: Object.freeze({
      artifact: bundleArtifactRecord(runtimeIds.libauthEvidence),
      schema: build.libauthEvidence.schema,
      semantics: 'Canonical development-only local Libauth BCH-2026 evidence. It does not establish final artifacts, production, live-chain, BCHN, or LeanBCH qualification.',
    }),
    build: Object.freeze({
      fixedTables: build.fixedTables,
      layout: build.layout,
      programs: Object.freeze(Object.fromEntries(
        Object.entries(build.programs).map(([name, program]) => [
          name,
          Array.isArray(program)
            ? program.map((entry) => entry.hashes)
            : program.hashes,
        ]),
      )),
      toolchain: build.toolchain,
    }),
  });
  const buildManifestBytes = canonicalBytes(buildManifest);
  await writeExactFile(
    path.join(stage, 'runtime-build-manifest.json'),
    buildManifestBytes,
  );
  await publishStage(stage, output, parent);
  return Object.freeze({
    outputDirectory: output,
    profileId,
    instanceId: options.instanceId,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    buildManifestPath: path.join(output, 'runtime-build-manifest.json'),
    buildManifestSha256: sha256(buildManifestBytes),
    artifactCount: artifacts.length,
  });
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2Pf10DevelopmentRuntime(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  }
}
