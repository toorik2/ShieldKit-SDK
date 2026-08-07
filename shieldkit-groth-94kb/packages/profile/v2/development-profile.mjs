import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  realpath,
  rm,
  rmdir,
} from 'node:fs/promises';
import path from 'node:path';

import {
  DIRECT_V2_PF10_BQ_SHARD_BYTES,
  DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
  DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
  DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES,
  DIRECT_V2_PF10_MAX_UNLOCK_BYTES,
  DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES,
  DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
  DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
  DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  directV2VerifierTopologyById,
} from '../../action/v2/topology.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  PROFILE_CORE_SCHEMA,
  validateProfileCore,
  V2_PROFILE_DOMAINS,
} from './profile-core.mjs';
import {
  collectNpmBuildClosure,
  NPM_BUILD_CLOSURE_SCHEMA,
  NpmBuildClosureError,
  verifyNpmBuildClosure,
} from './npm-closure.mjs';
import {
  verifyDevelopmentSetupAttestationPair,
} from './build-attestation.mjs';
import {
  collectV2RelationSourceManifest,
  parseV2RelationSourceManifest,
  V2_RELATION_SOURCE_MANIFEST_SCHEMA,
  verifyV2RelationSourceManifest,
} from './relation-source-manifest.mjs';
import {
  verifyDevelopmentGroth16Artifacts,
} from '../setup/development.mjs';

export const V2_DEVELOPMENT_PROFILE_PACKAGE_SCHEMA =
  'shieldkit-v2-direct-development-profile-package-v1';
export { V2_RELATION_SOURCE_MANIFEST_SCHEMA };
export const V2_BASE_VERIFIER_SOURCE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-base-verifier-source-manifest-v1';
export const V2_TOOLCHAIN_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-toolchain-manifest-v2';
export const V2_PF10_TOPOLOGY_SPEC_SCHEMA =
  'shieldkit-v2-direct-pf10-topology-spec-v1';

const HASH = /^[0-9a-f]{64}$/;
const PRODUCTION_V2_MODULES = Object.freeze([
  'exact-msm-cashscript.mjs',
  'exact-msm.mjs',
  'identity-aware-miller-cashscript.mjs',
  'identity-aware-miller.mjs',
  'pf10-action-witness.mjs',
  'pf10-fused-q-genesis.mjs',
  'structural-covenants.mjs',
  'total-pairfold-cashscript.mjs',
  'total-pairfold.mjs',
]);
const BASE_VERIFIER_FILES = Object.freeze([
  'shieldkit-groth-94kb/packages/action/v2/binding-unlock.mjs',
  'shieldkit-groth-94kb/packages/action/v2/topology.mjs',
  ...PRODUCTION_V2_MODULES.map((name) =>
    `shieldkit-groth-94kb/packages/unlock-builder/v2/${name}`),
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/chunked/pairing/_millermath.mjs',
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/src/c7/v2-direct-groth16-adapter-input.mjs',
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/src/c7/shield-adapter-input.mjs',
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
]);
const BASE_VERIFIER_DIRECTORIES = Object.freeze([
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/tools/singleton-artifact',
  'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist',
]);
const NPM_TOOLCHAINS = Object.freeze([
  Object.freeze({
    lockPath: 'node_modules/@bitauth/libauth',
    name: 'libauth',
  }),
  Object.freeze({
    lockPath: 'node_modules/circom2',
    name: 'circom2',
  }),
  Object.freeze({
    lockPath: 'node_modules/circomlib',
    name: 'circomlib',
  }),
  Object.freeze({
    lockPath: 'node_modules/snarkjs',
    name: 'snarkjs',
  }),
]);
const NPM_CLOSURE_ROOTS = Object.freeze(
  NPM_TOOLCHAINS.map((definition) => definition.lockPath).sort(),
);
const NPM_SUMMARY_KIND = 'npm-lock-entry-summary-not-complete-closure';
const DEFAULT_REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../..');

export class V2DevelopmentProfileError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2DevelopmentProfileError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2DevelopmentProfileError(code, message, cause);
};

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

function canonicalBytes(value) {
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

function relativePortable(root, filename) {
  const relative = path.relative(root, filename);
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail(
      'PROFILE_PATH_OUTSIDE_ROOT',
      `profile input is outside the repository root: ${filename}`,
    );
  }
  return relative.split(path.sep).join('/');
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function privateOwner(statValue, label, { privateMode = false } = {}) {
  const expectedUid = process.getuid === undefined
    ? undefined
    : typeof statValue.uid === 'bigint'
      ? BigInt(process.getuid())
      : process.getuid();
  if (
    !statValue.isDirectory()
    || statValue.isSymbolicLink()
    || (expectedUid !== undefined && statValue.uid !== expectedUid)
    || (statValue.mode & (privateMode ? 0o077n : 0o022n)) !== 0n
  ) {
    fail(
      'PROFILE_OUTPUT_UNSAFE',
      privateMode
        ? `${label} must be a 0700 owner-private directory`
        : `${label} must be an owner-controlled directory not writable by group or other users`,
    );
  }
  return statValue;
}

async function canonicalRoot(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    fail('PROFILE_PATH_INVALID', 'repositoryRoot must be an absolute path');
  }
  const resolved = path.resolve(value);
  let metadata;
  let canonical;
  try {
    metadata = await lstat(resolved, { bigint: true });
    canonical = await realpath(resolved);
  } catch (error) {
    fail('PROFILE_PATH_INVALID', 'repositoryRoot is not readable', error);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || canonical !== resolved) {
    fail(
      'PROFILE_PATH_INVALID',
      'repositoryRoot must be a canonical path without symlink traversal',
    );
  }
  return canonical;
}

async function inputFileIdentity(root, value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    fail('PROFILE_PATH_INVALID', `${label} must be an absolute path`);
  }
  const resolved = path.resolve(value);
  relativePortable(root, resolved);
  let metadata;
  let canonical;
  try {
    metadata = await lstat(resolved, { bigint: true });
    canonical = await realpath(resolved);
  } catch (error) {
    fail('PROFILE_PATH_INVALID', `${label} is not readable`, error);
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || metadata.size === 0n
    || canonical !== resolved
  ) {
    fail(
      'PROFILE_PATH_INVALID',
      `${label} must be one nonempty canonical regular file`,
    );
  }
  return Object.freeze({ filename: resolved, metadata });
}

async function stableFileEvidence(root, value, label, includeData = false) {
  const expected = await inputFileIdentity(root, value, label);
  const filename = expected.filename;
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || !sameIdentity(expected.metadata, before)
      || before.size !== expected.metadata.size
      || before.mtimeNs !== expected.metadata.mtimeNs
      || before.ctimeNs !== expected.metadata.ctimeNs
    ) {
      fail('PROFILE_FILE_CHANGED', `${label} changed before it could be opened safely`);
    }
    const hash = createHash('sha256');
    const chunks = [];
    let bytes = 0n;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
      bytes += BigInt(chunk.length);
      if (includeData) chunks.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    let pathAfter;
    let canonicalAfter;
    try {
      pathAfter = await lstat(filename, { bigint: true });
      canonicalAfter = await realpath(filename);
    } catch (error) {
      fail('PROFILE_FILE_CHANGED', `${label} changed while it was hashed`, error);
    }
    if (
      !sameIdentity(before, after)
      || !sameIdentity(expected.metadata, after)
      || !sameIdentity(expected.metadata, pathAfter)
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || bytes !== before.size
      || canonicalAfter !== filename
    ) {
      fail('PROFILE_FILE_CHANGED', `${label} changed while it was hashed`);
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('PROFILE_FILE_TOO_LARGE', `${label} exceeds safe evidence size`);
    }
    return Object.freeze({
      path: relativePortable(root, filename),
      bytes: Number(before.size),
      sha256: hash.digest('hex'),
      data: includeData ? Buffer.concat(chunks) : undefined,
    });
  } catch (error) {
    if (error instanceof V2DevelopmentProfileError) throw error;
    fail('PROFILE_FILE_READ_FAILED', `${label} could not be hashed`, error);
  } finally {
    await handle?.close();
  }
}

function publicEvidence(value) {
  return Object.freeze({
    path: value.path,
    bytes: value.bytes,
    sha256: value.sha256,
  });
}

async function directorySources(repositoryRoot, relativeDirectory, label) {
  const directory = path.join(repositoryRoot, relativeDirectory);
  const canonical = await realpath(directory);
  if (canonical !== directory) {
    fail(
      'PROFILE_PATH_INVALID',
      `${label} must be a canonical directory without symlink traversal`,
    );
  }
  const pending = [directory];
  const files = [];
  while (pending.length > 0) {
    const current = pending.pop();
    const entries = await readdir(current, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const target = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        fail(
          'PROFILE_PATH_INVALID',
          `${label} contains a symlink: ${relativePortable(repositoryRoot, target)}`,
        );
      }
      if (entry.isDirectory()) {
        pending.push(target);
      } else if (entry.isFile()) {
        files.push(publicEvidence(await stableFileEvidence(
          repositoryRoot,
          target,
          label,
        )));
      } else {
        fail(
          'PROFILE_PATH_INVALID',
          `${label} contains a non-file entry: ${relativePortable(repositoryRoot, target)}`,
        );
      }
    }
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return Object.freeze(files);
}

async function baseVerifierSources(repositoryRoot) {
  const entries = new Map();
  for (const relative of BASE_VERIFIER_FILES) {
    const evidence = publicEvidence(await stableFileEvidence(
      repositoryRoot,
      path.join(repositoryRoot, relative),
      `base verifier source ${relative}`,
    ));
    entries.set(evidence.path, evidence);
  }
  for (const relative of BASE_VERIFIER_DIRECTORIES) {
    for (const evidence of await directorySources(
      repositoryRoot,
      relative,
      `base verifier source tree ${relative}`,
    )) {
      entries.set(evidence.path, evidence);
    }
  }
  return Object.freeze(
    [...entries.values()].sort((left, right) =>
      left.path.localeCompare(right.path)),
  );
}

async function toolchainManifest(repositoryRoot) {
  let npmBuildClosure;
  try {
    npmBuildClosure = await collectNpmBuildClosure({
      repositoryRoot,
      roots: NPM_CLOSURE_ROOTS,
    });
  } catch (error) {
    fail('TOOLCHAIN_CLOSURE_INVALID', 'complete npm build closure cannot be collected', error);
  }
  const closureByPath = new Map(
    npmBuildClosure.packages.map((entry) => [entry.packagePath, entry]),
  );
  const entries = [];
  for (const definition of NPM_TOOLCHAINS) {
    const closureEntry = closureByPath.get(definition.lockPath);
    if (closureEntry === undefined) {
      fail('TOOLCHAIN_CLOSURE_INVALID', `npm closure omits direct toolchain: ${definition.lockPath}`);
    }
    const locked = closureEntry.lock;
    entries.push(Object.freeze({
      name: definition.name,
      version: locked.version,
      sha256: sha256(canonicalBytes({
        integrity: locked.integrity,
        resolved: locked.resolved,
        version: locked.version,
      })),
      source: Object.freeze({
        kind: NPM_SUMMARY_KIND,
        lockfile: npmBuildClosure.lockfile.path,
        packagePath: definition.lockPath,
      }),
    }));
  }
  const cashcPackage = await stableFileEvidence(
    repositoryRoot,
    path.join(
      repositoryRoot,
      'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/package.json',
    ),
    'vendored CashC package',
    true,
  );
  let cashc;
  try {
    cashc = JSON.parse(cashcPackage.data.toString('utf8'));
  } catch (error) {
    fail('TOOLCHAIN_LOCK_INVALID', 'vendored CashC package is not JSON', error);
  }
  if (cashc?.name !== 'cashc' || typeof cashc.version !== 'string') {
    fail('TOOLCHAIN_LOCK_INVALID', 'vendored CashC package identity is invalid');
  }
  const cashcDist = await directorySources(
    repositoryRoot,
    'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist',
    'vendored CashC compiler',
  );
  entries.push(Object.freeze({
    name: 'cashc-resched',
    version: cashc.version,
    sha256: sha256(canonicalBytes({
      files: cashcDist,
      package: publicEvidence(cashcPackage),
    })),
    source: Object.freeze({
      kind: 'vendored-compiler',
      packagePath: cashcPackage.path,
    }),
  }));
  const optimizerFiles = await directorySources(
    repositoryRoot,
    'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/tools/singleton-artifact',
    'singleton optimizer source',
  );
  entries.push(Object.freeze({
    name: 'singleton-optimizer',
    version: 'shieldkit-content-addressed-v1',
    sha256: sha256(canonicalBytes(optimizerFiles)),
    source: Object.freeze({
      kind: 'vendored-source-set',
      files: optimizerFiles,
    }),
  }));
  entries.sort((left, right) => left.name.localeCompare(right.name));
  return Object.freeze({
    schema: V2_TOOLCHAIN_MANIFEST_SCHEMA,
    lockfile: npmBuildClosure.lockfile,
    npmBuildClosure,
    entries: Object.freeze(entries),
  });
}

function topologySpec() {
  const topology = directV2VerifierTopologyById(
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  );
  return Object.freeze({
    schema: V2_PF10_TOPOLOGY_SPEC_SCHEMA,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    qualificationClass: topology.qualificationClass,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    indexes: Object.freeze({
      binding: topology.bindingInputIndex,
      state: topology.stateInputIndex,
      funding: topology.fundingInputIndex,
      inputCount: topology.inputCount,
      digestCarrier: topology.digestCarrierIndex,
      digestPayloadOffset: topology.digestPayloadOffset,
    }),
    layout: Object.freeze({
      bqShardBytes: DIRECT_V2_PF10_BQ_SHARD_BYTES,
      exactMsmZeroPaddingBytes:
        DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES,
      nonFinalMsmPaddingBytes:
        DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
      millerZeroPaddingBytes:
        DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES,
      executorDensityPadBytes:
        DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
      executorFunctionId: DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
      verifierUnlockBytes: DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
      stateUnlockBytes: DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
    }),
    policyCeilings: Object.freeze({
      maximumTransactionBytes: 100_000,
      maximumUnlockBytes: DIRECT_V2_PF10_MAX_UNLOCK_BYTES,
      maximumVmResourcePercent: 100,
    }),
  });
}

async function safeDirectory(directory, label, options = undefined) {
  let metadata;
  let canonical;
  try {
    metadata = await lstat(directory, { bigint: true });
    canonical = await realpath(directory);
  } catch (error) {
    fail('PROFILE_OUTPUT_UNSAFE', `${label} is unavailable`, error);
  }
  if (canonical !== directory) {
    fail('PROFILE_OUTPUT_UNSAFE', `${label} must not resolve through a symlink`);
  }
  return privateOwner(metadata, label, options);
}

async function ensureOutputParent(repositoryRoot, outputDirectory) {
  const parent = path.dirname(outputDirectory);
  const relative = path.relative(repositoryRoot, parent);
  if (
    relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail('PROFILE_PATH_OUTSIDE_ROOT', 'output parent is outside the repository root');
  }
  let current = repositoryRoot;
  await safeDirectory(current, 'repository root');
  for (const segment of relative.length === 0 ? [] : relative.split(path.sep)) {
    current = path.join(current, segment);
    try {
      await mkdir(current, { mode: 0o700 });
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        fail('PROFILE_OUTPUT_UNSAFE', 'output parent directory cannot be created', error);
      }
    }
    await safeDirectory(current, 'output parent directory');
  }
  return parent;
}

async function inspectEmptyOutputDirectory(repositoryRoot, outputDirectory) {
  if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory)) {
    fail('PROFILE_PATH_INVALID', 'outputDirectory must be an absolute path');
  }
  const resolved = path.resolve(outputDirectory);
  relativePortable(repositoryRoot, resolved);
  const parent = await ensureOutputParent(repositoryRoot, resolved);
  let existing;
  try {
    existing = await lstat(resolved, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return Object.freeze({ output: resolved, parent, existingIdentity: null });
    }
    fail('PROFILE_OUTPUT_UNSAFE', 'outputDirectory cannot be inspected safely', error);
  }
  try {
    const metadata = await safeDirectory(
      resolved,
      'outputDirectory',
      { privateMode: true },
    );
    if ((await readdir(resolved)).length !== 0) {
      fail(
        'PROFILE_OUTPUT_NOT_EMPTY',
        'outputDirectory must be an empty owner-private directory',
      );
    }
    if (!sameIdentity(existing, metadata)) {
      fail('PROFILE_OUTPUT_UNSAFE', 'outputDirectory changed while its identity was checked');
    }
    return Object.freeze({
      output: resolved,
      parent,
      existingIdentity: Object.freeze({ dev: metadata.dev, ino: metadata.ino }),
    });
  } catch (error) {
    if (error instanceof V2DevelopmentProfileError) throw error;
    fail('PROFILE_OUTPUT_UNSAFE', 'outputDirectory cannot be inspected safely', error);
  }
}

async function createStagingDirectory(parent) {
  let staging;
  try {
    staging = await mkdtemp(path.join(parent, '.shieldkit-v2-development-profile-'));
    await chmod(staging, 0o700);
  } catch (error) {
    fail('PROFILE_OUTPUT_UNSAFE', 'private profile staging directory cannot be created', error);
  }
  const metadata = await safeDirectory(
    staging,
    'profile staging directory',
    { privateMode: true },
  );
  return Object.freeze({
    directory: staging,
    identity: Object.freeze({ dev: metadata.dev, ino: metadata.ino }),
  });
}

async function syncDirectory(directory, label) {
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    await handle.sync();
  } catch (error) {
    fail('PROFILE_OUTPUT_UNSAFE', `${label} cannot be synchronized`, error);
  } finally {
    await handle?.close();
  }
}

async function cleanupStaging(staging) {
  if (staging === undefined) return;
  try {
    const metadata = await lstat(staging.directory, { bigint: true });
    if (
      metadata.isDirectory()
      && !metadata.isSymbolicLink()
      && sameIdentity(metadata, staging.identity)
    ) {
      await rm(staging.directory, { recursive: true, force: false, maxRetries: 0 });
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      fail('PROFILE_STAGING_CLEANUP_FAILED', 'exact profile staging directory could not be removed', error);
    }
  }
}

function outputFileName(name) {
  if (typeof name !== 'string' || !/^[a-z0-9-]+\.json$/.test(name)) {
    fail('PROFILE_OUTPUT_UNSAFE', 'profile output filename is invalid');
  }
  return name;
}

async function writeCanonical(directory, name, value) {
  const bytes = canonicalBytes(value);
  const filename = path.join(directory, outputFileName(name));
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    fail('PROFILE_OUTPUT_UNSAFE', `profile output ${name} cannot be written safely`, error);
  } finally {
    await handle?.close();
  }
  return Object.freeze({
    path: name,
    bytes: bytes.length,
    sha256: sha256(bytes),
  });
}

async function publishStaging(outputPlan, staging) {
  if (outputPlan.existingIdentity !== null) {
    const metadata = await safeDirectory(
      outputPlan.output,
      'outputDirectory',
      { privateMode: true },
    );
    if (
      !sameIdentity(metadata, outputPlan.existingIdentity)
      || (await readdir(outputPlan.output)).length !== 0
    ) {
      fail('PROFILE_OUTPUT_NOT_EMPTY', 'outputDirectory changed before atomic publication');
    }
    try {
      await rmdir(outputPlan.output);
    } catch (error) {
      fail('PROFILE_OUTPUT_UNSAFE', 'empty outputDirectory cannot be replaced atomically', error);
    }
  } else {
    try {
      await lstat(outputPlan.output);
      fail('PROFILE_OUTPUT_NOT_EMPTY', 'outputDirectory appeared before atomic publication');
    } catch (error) {
      if (error instanceof V2DevelopmentProfileError) throw error;
      if (error?.code !== 'ENOENT') {
        fail('PROFILE_OUTPUT_UNSAFE', 'outputDirectory cannot be checked before publication', error);
      }
    }
  }
  await syncDirectory(staging.directory, 'profile staging directory');
  try {
    await rename(staging.directory, outputPlan.output);
  } catch (error) {
    fail('PROFILE_OUTPUT_UNSAFE', 'profile staging directory cannot be atomically published', error);
  }
  await syncDirectory(outputPlan.parent, 'profile output parent directory');
}

const PACKAGE_KEYS = Object.freeze([
  'eligibility',
  'generatedArtifacts',
  'profileCoreSha256',
  'profileId',
  'proofArtifacts',
  'schema',
]);
const PROOF_ARTIFACT_NAMES = Object.freeze([
  'circuitSymbols',
  'initialProvingKey',
  'powersOfTau',
  'provingKey',
  'r1cs',
  'verificationKey',
  'witnessWasm',
]);
const GENERATED_ARTIFACT_PATHS = Object.freeze({
  circuitBuildAttestation: 'circuit-build-attestation.json',
  developmentSetupAttestation: 'development-setup-attestation.json',
  relationManifest: 'relation-manifest.json',
  baseVerifierManifest: 'base-verifier-manifest.json',
  topologySpec: 'pf10-topology-spec.json',
  toolchainManifest: 'toolchain-manifest.json',
  profileCore: 'profile-core.json',
});

function exactObject(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
  ) {
    fail('PROFILE_PACKAGE_INVALID', `${label} must be a plain JSON object`);
  }
  try {
    canonicalizeJcs(value);
  } catch (error) {
    fail('PROFILE_PACKAGE_INVALID', `${label} is not canonical JSON data`, error);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('PROFILE_PACKAGE_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function portableArtifactPath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\0')
    || path.isAbsolute(value)
    || path.posix.normalize(value) !== value
    || value === '..'
    || value.startsWith('../')
  ) {
    fail('PROFILE_PACKAGE_INVALID', `${label} must be a normalized relative path`);
  }
  return value;
}

function artifactRecord(value, label, expectedPath = undefined) {
  exactObject(value, ['bytes', 'path', 'sha256'], label);
  const artifactPath = portableArtifactPath(value.path, `${label}.path`);
  if (
    (expectedPath !== undefined && artifactPath !== expectedPath)
    || !Number.isSafeInteger(value.bytes)
    || value.bytes <= 0
    || typeof value.sha256 !== 'string'
    || !HASH.test(value.sha256)
  ) {
    fail('PROFILE_PACKAGE_INVALID', `${label} has invalid artifact evidence`);
  }
  return Object.freeze({
    path: artifactPath,
    bytes: value.bytes,
    sha256: value.sha256,
  });
}

function sameArtifactBytes(record, evidence) {
  return (
    record.bytes === evidence.bytes
    && record.sha256 === evidence.sha256
  );
}

function inspectedPackage(value) {
  exactObject(value, PACKAGE_KEYS, 'development profile package');
  if (
    value.schema !== V2_DEVELOPMENT_PROFILE_PACKAGE_SCHEMA
    || value.eligibility !== 'development-only'
    || typeof value.profileId !== 'string'
    || !HASH.test(value.profileId)
    || typeof value.profileCoreSha256 !== 'string'
    || !HASH.test(value.profileCoreSha256)
  ) {
    fail('PROFILE_PACKAGE_INVALID', 'development profile package identity is invalid');
  }
  exactObject(value.proofArtifacts, PROOF_ARTIFACT_NAMES, 'proofArtifacts');
  exactObject(
    value.generatedArtifacts,
    Object.keys(GENERATED_ARTIFACT_PATHS),
    'generatedArtifacts',
  );
  const proofArtifacts = Object.freeze(Object.fromEntries(
    PROOF_ARTIFACT_NAMES.map((name) => [
      name,
      artifactRecord(value.proofArtifacts[name], `proofArtifacts.${name}`),
    ]),
  ));
  const generatedArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(GENERATED_ARTIFACT_PATHS).map(([name, expectedPath]) => [
      name,
      artifactRecord(
        value.generatedArtifacts[name],
        `generatedArtifacts.${name}`,
        expectedPath,
      ),
    ]),
  ));
  if (generatedArtifacts.profileCore.sha256 !== value.profileCoreSha256) {
    fail('PROFILE_PACKAGE_INVALID', 'profileCoreSha256 does not match generatedArtifacts.profileCore');
  }
  return Object.freeze({
    schema: value.schema,
    eligibility: value.eligibility,
    profileId: value.profileId,
    profileCoreSha256: value.profileCoreSha256,
    proofArtifacts,
    generatedArtifacts,
  });
}

async function verifiedGeneratedFile(directory, record, label) {
  const evidence = await stableFileEvidence(
    directory,
    path.join(directory, record.path),
    label,
    true,
  );
  if (evidence.bytes !== record.bytes || evidence.sha256 !== record.sha256) {
    fail('PROFILE_PACKAGE_INVALID', `${label} differs from its emitted artifact record`);
  }
  return evidence;
}

function toolchainEntriesForProfileCore(entries) {
  if (!Array.isArray(entries)) {
    fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest entries must be an array');
  }
  const profileEntries = entries.map((entry) => {
    exactObject(entry, ['name', 'sha256', 'source', 'version'], 'toolchain manifest entry');
    if (
      typeof entry.name !== 'string'
      || typeof entry.version !== 'string'
      || !HASH.test(entry.sha256)
    ) {
      fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest entry is malformed');
    }
    return Object.freeze({ name: entry.name, sha256: entry.sha256, version: entry.version });
  });
  profileEntries.sort((left, right) => left.name.localeCompare(right.name));
  if (profileEntries.some((entry, index) => index > 0 && entry.name === profileEntries[index - 1].name)) {
    fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest entries are not unique');
  }
  return Object.freeze(profileEntries);
}

async function verifyToolchainManifest(value, repositoryRoot) {
  exactObject(value, ['entries', 'lockfile', 'npmBuildClosure', 'schema'], 'toolchain manifest');
  if (value.schema !== V2_TOOLCHAIN_MANIFEST_SCHEMA) {
    fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest schema is unsupported');
  }
  let npmBuildClosure;
  try {
    npmBuildClosure = await verifyNpmBuildClosure(value.npmBuildClosure, {
      repositoryRoot,
    });
  } catch (error) {
    if (error instanceof NpmBuildClosureError) {
      fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest npm build closure drifted or is invalid', error);
    }
    throw error;
  }
  if (
    value.npmBuildClosure.schema !== NPM_BUILD_CLOSURE_SCHEMA
    || canonicalizeJcs(value.lockfile) !== canonicalizeJcs(npmBuildClosure.lockfile)
    || canonicalizeJcs(value.npmBuildClosure.roots) !== canonicalizeJcs(NPM_CLOSURE_ROOTS)
  ) {
    fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest npm closure roots or lockfile differ from the required closure');
  }
  const closureByPath = new Map(
    npmBuildClosure.packages.map((entry) => [entry.packagePath, entry]),
  );
  const profileEntries = toolchainEntriesForProfileCore(value.entries);
  for (const definition of NPM_TOOLCHAINS) {
    const summary = value.entries.find((entry) => entry.name === definition.name);
    const closureEntry = closureByPath.get(definition.lockPath);
    if (
      summary === undefined
      || closureEntry === undefined
      || summary.version !== closureEntry.lock.version
      || summary.sha256 !== closureEntry.lock.sha256
      || canonicalizeJcs(summary.source) !== canonicalizeJcs({
        kind: NPM_SUMMARY_KIND,
        lockfile: npmBuildClosure.lockfile.path,
        packagePath: definition.lockPath,
      })
    ) {
      fail('PROFILE_PACKAGE_INVALID', `toolchain manifest direct summary is not bound to its complete closure: ${definition.name}`);
    }
  }
  return Object.freeze({ npmBuildClosure, profileEntries });
}

/**
 * Validate a complete package envelope. With `directory`, additionally verify
 * all emitted JSON bytes and recompute the profile ID from profile-core.json.
 */
export async function verifyV2DevelopmentProfilePackage(
  value,
  {
    directory = undefined,
    repositoryRoot = DEFAULT_REPOSITORY_ROOT,
  } = {},
) {
  const inspected = inspectedPackage(value);
  if (directory === undefined) return inspected;
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    fail('PROFILE_PACKAGE_INVALID', 'package directory must be an absolute path');
  }
  const resolved = path.resolve(directory);
  const root = await canonicalRoot(repositoryRoot);
  await safeDirectory(resolved, 'development profile package directory', {
    privateMode: true,
  });
  const packageFile = await verifiedGeneratedFile(
    resolved,
    Object.freeze({
      path: 'profile-package.json',
      bytes: Buffer.byteLength(canonicalizeJcs(value), 'utf8'),
      sha256: sha256(canonicalBytes(value)),
    }),
    'profile package record',
  );
  let parsedPackage;
  try {
    parsedPackage = JSON.parse(packageFile.data.toString('utf8'));
  } catch (error) {
    fail('PROFILE_PACKAGE_INVALID', 'profile package record is not JSON', error);
  }
  if (!packageFile.data.equals(canonicalBytes(parsedPackage)) || canonicalizeJcs(parsedPackage) !== canonicalizeJcs(value)) {
    fail('PROFILE_PACKAGE_INVALID', 'profile package record is not exact canonical package bytes');
  }
  const emitted = {};
  for (const [name, record] of Object.entries(inspected.generatedArtifacts)) {
    emitted[name] = await verifiedGeneratedFile(
      resolved,
      record,
      `generated artifact ${name}`,
    );
  }
  for (const [name, record] of Object.entries(inspected.proofArtifacts)) {
    const evidence = await stableFileEvidence(
      root,
      path.join(root, ...record.path.split('/')),
      `proof artifact ${name}`,
    );
    if (!sameArtifactBytes(record, evidence)) {
      fail(
        'PROFILE_PACKAGE_INVALID',
        `proof artifact ${name} differs from its package record`,
      );
    }
  }
  let profileCore;
  try {
    profileCore = JSON.parse(emitted.profileCore.data.toString('utf8'));
    validateProfileCore(profileCore);
  } catch (error) {
    if (error instanceof V2DevelopmentProfileError) throw error;
    fail('PROFILE_PACKAGE_INVALID', 'emitted profile core is invalid', error);
  }
  if (
    !emitted.profileCore.data.equals(canonicalBytes(profileCore))
    || deriveProfileId(profileCore) !== inspected.profileId
    || emitted.profileCore.sha256 !== inspected.profileCoreSha256
  ) {
    fail('PROFILE_PACKAGE_INVALID', 'emitted profile core does not bind the package identity');
  }
  let attestationPair;
  try {
    attestationPair = await verifyDevelopmentSetupAttestationPair(
      emitted.developmentSetupAttestation.data,
      {
        buildAttestationBytes: emitted.circuitBuildAttestation.data,
        repositoryRoot: root,
        sourceManifestBytes: emitted.relationManifest.data,
      },
    );
  } catch (error) {
    fail(
      'PROFILE_PACKAGE_INVALID',
      'emitted build/setup attestations are invalid or unlinked',
      error,
    );
  }
  if (
    !sameArtifactBytes(
      attestationPair.build.artifacts.r1cs,
      inspected.proofArtifacts.r1cs,
    )
    || !sameArtifactBytes(
      attestationPair.build.artifacts.wasm,
      inspected.proofArtifacts.witnessWasm,
    )
    || !sameArtifactBytes(
      attestationPair.build.artifacts.sym,
      inspected.proofArtifacts.circuitSymbols,
    )
    || !sameArtifactBytes(
      attestationPair.setup.zkeyChain.initial,
      inspected.proofArtifacts.initialProvingKey,
    )
    || !sameArtifactBytes(
      attestationPair.setup.zkeyChain.contributions[0].output,
      inspected.proofArtifacts.provingKey,
    )
    || !sameArtifactBytes(
      attestationPair.setup.ptau.artifact,
      inspected.proofArtifacts.powersOfTau,
    )
    || !sameArtifactBytes(
      attestationPair.setup.finalEvidence.verificationKey,
      inspected.proofArtifacts.verificationKey,
    )
  ) {
    fail(
      'PROFILE_PACKAGE_INVALID',
      'emitted attestations differ from package proof artifacts',
    );
  }
  try {
    const relationManifest = parseV2RelationSourceManifest(
      emitted.relationManifest.data,
    );
    await verifyV2RelationSourceManifest(relationManifest, {
      repositoryRoot: root,
    });
    if (
      profileCore.proof.relationSha256
        !== emitted.relationManifest.sha256
      || attestationPair.build.sourceManifest.bytes
        !== emitted.relationManifest.bytes
      || attestationPair.build.sourceManifest.sha256
        !== emitted.relationManifest.sha256
    ) {
      fail(
        'PROFILE_PACKAGE_INVALID',
        'profile core relation hash differs from the verified source manifest',
      );
    }
  } catch (error) {
    if (error instanceof V2DevelopmentProfileError) throw error;
    fail(
      'PROFILE_PACKAGE_INVALID',
      'emitted relation source manifest is invalid or drifted',
      error,
    );
  }
  let toolchain;
  try {
    const toolchainValue = JSON.parse(emitted.toolchainManifest.data.toString('utf8'));
    if (!emitted.toolchainManifest.data.equals(canonicalBytes(toolchainValue))) {
      fail('PROFILE_PACKAGE_INVALID', 'toolchain manifest is not exact canonical JSON bytes');
    }
    toolchain = await verifyToolchainManifest(toolchainValue, root);
  } catch (error) {
    if (error instanceof V2DevelopmentProfileError) throw error;
    fail('PROFILE_PACKAGE_INVALID', 'emitted toolchain manifest is invalid', error);
  }
  if (canonicalizeJcs(profileCore.toolchain) !== canonicalizeJcs(toolchain.profileEntries)) {
    fail('PROFILE_PACKAGE_INVALID', 'profile core toolchain summaries differ from the emitted toolchain manifest');
  }
  try {
    await verifyDevelopmentGroth16Artifacts({
      repositoryRoot: root,
      buildAttestationBytes: emitted.circuitBuildAttestation.data,
      sourceManifestBytes: emitted.relationManifest.data,
      setupAttestationBytes: emitted.developmentSetupAttestation.data,
      initialZkeyPath: path.join(
        root,
        ...inspected.proofArtifacts.initialProvingKey.path.split('/'),
      ),
      provingKeyPath: path.join(
        root,
        ...inspected.proofArtifacts.provingKey.path.split('/'),
      ),
      ptauPath: path.join(
        root,
        ...inspected.proofArtifacts.powersOfTau.path.split('/'),
      ),
      r1csPath: path.join(
        root,
        ...inspected.proofArtifacts.r1cs.path.split('/'),
      ),
      verificationKeyPath: path.join(
        root,
        ...inspected.proofArtifacts.verificationKey.path.split('/'),
      ),
    });
  } catch (error) {
    fail(
      'PROFILE_PACKAGE_INVALID',
      'independent Groth16 setup verification failed',
      error,
    );
  }
  return inspected;
}

/**
 * Build a content-addressed development profile from real local artifacts.
 * This does not create a proving key, instance, descriptor, or release claim.
 */
export async function buildV2DevelopmentProfilePackage({
  repositoryRoot,
  circuitBuildAttestationPath,
  circuitSymbolPath,
  developmentSetupAttestationPath,
  initialProvingKeyPath,
  ptauPath,
  r1csPath,
  witnessWasmPath,
  verificationKeyPath,
  provingKeyPath,
  outputDirectory,
} = {}) {
  const root = await canonicalRoot(repositoryRoot);
  const outputPlan = await inspectEmptyOutputDirectory(root, outputDirectory);
  let staging;
  try {
    staging = await createStagingDirectory(outputPlan.parent);
    const output = staging.directory;
    const proofArtifacts = Object.freeze({
    circuitSymbols: publicEvidence(await stableFileEvidence(
      root,
      circuitSymbolPath,
      'circuit symbol table',
    )),
    initialProvingKey: publicEvidence(await stableFileEvidence(
      root,
      initialProvingKeyPath,
      'development initial proving key',
    )),
    powersOfTau: publicEvidence(await stableFileEvidence(
      root,
      ptauPath,
      'development Powers of Tau',
    )),
    provingKey: publicEvidence(await stableFileEvidence(
      root,
      provingKeyPath,
      'development proving key',
    )),
    r1cs: publicEvidence(await stableFileEvidence(
      root,
      r1csPath,
      'R1CS',
    )),
    verificationKey: publicEvidence(await stableFileEvidence(
      root,
      verificationKeyPath,
      'verification key',
    )),
    witnessWasm: publicEvidence(await stableFileEvidence(
      root,
      witnessWasmPath,
      'witness WASM',
    )),
  });
    const circuitBuildAttestation = await stableFileEvidence(
      root,
      circuitBuildAttestationPath,
      'circuit build attestation',
      true,
    );
    const developmentSetupAttestation = await stableFileEvidence(
      root,
      developmentSetupAttestationPath,
      'development setup attestation',
      true,
    );
    const relationManifest = await collectV2RelationSourceManifest({
      repositoryRoot: root,
    });
    const relationBytes = canonicalBytes(relationManifest);
    let attestationPair;
    try {
      attestationPair = await verifyDevelopmentSetupAttestationPair(
        developmentSetupAttestation.data,
        {
          buildAttestationBytes: circuitBuildAttestation.data,
          repositoryRoot: root,
          sourceManifestBytes: relationBytes,
        },
      );
    } catch (error) {
      fail(
        'PROFILE_ATTESTATION_INVALID',
        'build/setup attestation linkage or npm closure is invalid',
        error,
      );
    }
    if (
      !sameArtifactBytes(
        attestationPair.build.artifacts.r1cs,
        proofArtifacts.r1cs,
      )
      || !sameArtifactBytes(
        attestationPair.build.artifacts.wasm,
        proofArtifacts.witnessWasm,
      )
      || !sameArtifactBytes(
        attestationPair.build.artifacts.sym,
        proofArtifacts.circuitSymbols,
      )
      || !sameArtifactBytes(
        attestationPair.setup.zkeyChain.initial,
        proofArtifacts.initialProvingKey,
      )
      || !sameArtifactBytes(
        attestationPair.setup.zkeyChain.contributions[0].output,
        proofArtifacts.provingKey,
      )
      || !sameArtifactBytes(
        attestationPair.setup.ptau.artifact,
        proofArtifacts.powersOfTau,
      )
      || !sameArtifactBytes(
        attestationPair.setup.finalEvidence.verificationKey,
        proofArtifacts.verificationKey,
      )
    ) {
      fail(
        'PROFILE_ATTESTATION_INVALID',
        'proof artifacts differ from the build/setup attestations',
      );
    }
    const baseVerifierManifest = Object.freeze({
    schema: V2_BASE_VERIFIER_SOURCE_MANIFEST_SCHEMA,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    sources: await baseVerifierSources(root),
  });
    const topology = topologySpec();
    const toolchains = await toolchainManifest(root);
    if (
      attestationPair.build.sourceManifest.bytes
        !== relationBytes.byteLength
      || attestationPair.build.sourceManifest.sha256
        !== sha256(relationBytes)
    ) {
      fail(
        'PROFILE_ATTESTATION_INVALID',
        'build attestation source manifest differs from the current relation',
      );
    }
    const baseVerifierBytes = canonicalBytes(baseVerifierManifest);
    const topologyBytes = canonicalBytes(topology);
    const profileCore = Object.freeze({
    schema: PROFILE_CORE_SCHEMA,
    network: Object.freeze({ id: 2, name: 'chipnet' }),
    denominationSats: '10000000',
    proof: Object.freeze({
      system: 'groth16',
      curve: 'bn254',
      relationId: 'shieldkit-pool-action-v2-direct',
      relationSha256: sha256(relationBytes),
      r1csSha256: proofArtifacts.r1cs.sha256,
      verificationKeySha256: proofArtifacts.verificationKey.sha256,
      witnessWasmSha256: proofArtifacts.witnessWasm.sha256,
    }),
    trees: Object.freeze({
      note: Object.freeze({
        id: 'shieldkit-note-tree-v2-depth32',
        depth: 32,
        leafSchemaId: 'shieldkit-note-leaf-v2',
      }),
      nullifier: Object.freeze({
        id: 'shieldkit-indexed-nullifier-tree-v2-depth32',
        depth: 32,
        leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2',
      }),
    }),
    crypto: Object.freeze({
      babyJubCurveId: 'circomlib-babyjub-base8',
      poseidonId: 'circomlib-poseidon-bn254',
      domains: Object.freeze({ ...V2_PROFILE_DOMAINS }),
    }),
    encodings: Object.freeze({
      state: 'shieldkit-pool-state-sks2-native128',
      packet: 'shieldkit-direct-action-sda2-552',
      address: 'shieldkit-address-v2-direct',
      record: 'shieldkit-note-record-v2-direct-128',
      unlock: 'shieldkit-rolling-bundle-unlock-v2-direct',
    }),
    publicInputAbi: Object.freeze({
      id: 'shieldkit-sda2-sha256-be-u128x2',
      count: 2,
      limbBits: 128,
      digest: 'sha256',
    }),
    baseVerifierArtifacts: Object.freeze([
      Object.freeze({
        id: 'pf10-base-verifier-sources',
        sha256: sha256(baseVerifierBytes),
      }),
      Object.freeze({
        id: 'pf10-topology-spec',
        sha256: sha256(topologyBytes),
      }),
    ]),
    toolchain: Object.freeze(toolchains.entries.map((entry) =>
      Object.freeze({
        name: entry.name,
        version: entry.version,
        sha256: entry.sha256,
      }))),
  });
    validateProfileCore(profileCore);
    const profileId = deriveProfileId(profileCore);
    const emitted = {};
    emitted.circuitBuildAttestation = await writeCanonical(
    output,
    'circuit-build-attestation.json',
    attestationPair.build,
  );
    emitted.developmentSetupAttestation = await writeCanonical(
    output,
    'development-setup-attestation.json',
    attestationPair.setup,
  );
    if (
      emitted.circuitBuildAttestation.sha256
        !== circuitBuildAttestation.sha256
      || emitted.circuitBuildAttestation.bytes
        !== circuitBuildAttestation.bytes
      || emitted.developmentSetupAttestation.sha256
        !== developmentSetupAttestation.sha256
      || emitted.developmentSetupAttestation.bytes
        !== developmentSetupAttestation.bytes
    ) {
      fail(
        'PROFILE_ATTESTATION_INVALID',
        'canonical attestation copies differ from their input bytes',
      );
    }
    emitted.relationManifest = await writeCanonical(
    output,
    'relation-manifest.json',
    relationManifest,
  );
    emitted.baseVerifierManifest = await writeCanonical(
    output,
    'base-verifier-manifest.json',
    baseVerifierManifest,
  );
    emitted.topologySpec = await writeCanonical(
    output,
    'pf10-topology-spec.json',
    topology,
  );
    emitted.toolchainManifest = await writeCanonical(
    output,
    'toolchain-manifest.json',
    toolchains,
  );
    emitted.profileCore = await writeCanonical(
    output,
    'profile-core.json',
    profileCore,
  );
    const packageRecord = Object.freeze({
    schema: V2_DEVELOPMENT_PROFILE_PACKAGE_SCHEMA,
    eligibility: 'development-only',
    profileId,
    profileCoreSha256: emitted.profileCore.sha256,
    proofArtifacts,
    generatedArtifacts: Object.freeze({ ...emitted }),
  });
    emitted.packageRecord = await writeCanonical(
    output,
    'profile-package.json',
    packageRecord,
  );
    await verifyV2DevelopmentProfilePackage(packageRecord, {
      directory: output,
      repositoryRoot: root,
    });
    await publishStaging(outputPlan, staging);
    staging = undefined;
    return Object.freeze({
      outputDirectory: outputPlan.output,
      profileId,
      profileCore,
      profileCorePath: path.join(outputPlan.output, 'profile-core.json'),
      proofArtifacts,
      emitted: Object.freeze(emitted),
    });
  } finally {
    await cleanupStaging(staging);
  }
}

export function inspectV2DevelopmentProfilePackage(value) {
  return inspectedPackage(value);
}
