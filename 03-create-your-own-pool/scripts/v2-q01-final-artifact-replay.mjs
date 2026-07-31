#!/usr/bin/env node
/*
 * Q-01 final-artifact replay.
 *
 * This is an offline, fail-closed verifier. It resolves only a release root
 * compiled into this ShieldKit build, revalidates the signed final
 * descriptor/runtime and D-01 result, independently checks the frozen relation
 * source manifest against the live checkout, and invokes the authoritative
 * Q-01-pre verifier. That verifier reruns all four implementation lanes and
 * compares their canonical outputs with the sealed pre-ceremony bundle.
 *
 * The TEST-ONLY entrypoint below accepts injected validators solely to exercise
 * this orchestration before authentic final signed artifacts exist. Its schema
 * and claims are permanently nonqualifying.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  parseV2RelationSourceManifest,
  verifyV2RelationSourceManifest,
} from '../packages/profile/v2/relation-source-manifest.mjs';
import {
  V2_D01_POST_CEREMONY_BINDING_SCHEMA,
  V2_D01_RESULT_SCHEMA,
  validateV2D01PostCeremonyBinding,
  verifyV2D01FinalCeremonyEvidence,
} from './v2-final-ceremony-qualification.mjs';
import {
  V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA,
  verifyV2Q01CommitBoundBundle,
} from './v2-q01-commit-bound-evidence.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const HASH = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ROOT_ID = /^[a-z][a-z0-9-]*$/u;
const IMPLEMENTATIONS = Object.freeze([
  'typescript',
  'rust',
  'circuit',
  'covenant',
]);
const REFERENCE_ID = 'javascript-reference-orchestrator';
const Q01_FILES = Object.freeze([
  'execution.json',
  'manifest.json',
  'qualification.json',
  'source-set.json',
]);
const PUBLIC_Q01_STATUS =
  'verified-local-pre-ceremony-four-implementation-conformance';
const TEST_Q01_STATUS = 'verified-test-only-local-nonqualifying';
const PUBLIC_STATUS =
  'q01-final-artifact-replay-qualified-not-production-or-release';
const TEST_STATUS =
  'test-only-final-artifact-replay-validated-nonqualifying';
const PUBLIC_FILENAME = 'q01-final-artifact-replay.json';
const TEST_FILENAME = 'q01-final-artifact-replay-test-only.json';

export const V2_Q01_FINAL_REPLAY_SCHEMA =
  'shieldkit-v2-direct-q01-final-artifact-replay-v1';
export const V2_Q01_FINAL_REPLAY_TEST_SCHEMA =
  'shieldkit-v2-direct-q01-final-artifact-replay-test-only-v1';

export class V2Q01FinalArtifactReplayError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q01FinalArtifactReplayError';
  }
}

const fail = (message) => {
  throw new V2Q01FinalArtifactReplayError(message);
};
const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');
const canonical = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const same = (left, right) =>
  canonicalizeJcs(left) === canonicalizeJcs(right);

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function gitObject(value, label) {
  if (typeof value !== 'string' || !SHA1.test(value)) {
    fail(`${label} must be one lowercase SHA-1 Git object id`);
  }
  return value;
}

function absolute(value, label) {
  if (
    typeof value !== 'string'
    || !isAbsolute(value)
    || resolve(value) !== value
  ) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function identityEqual(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function directDirectory(path, label, { mode = undefined } = {}) {
  absolute(path, label);
  const entry = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (
    entry === undefined
    || !entry.isDirectory()
    || entry.isSymbolicLink()
    || realpathSync(path) !== path
    || (
      typeof process.getuid === 'function'
      && entry.uid !== BigInt(process.getuid())
    )
    || (mode !== undefined && Number(entry.mode & 0o7777n) !== mode)
  ) {
    fail(`${label} must be a direct canonical user-owned${
      mode === undefined ? '' : ` mode-${mode.toString(8)}`
    } directory`);
  }
  return entry;
}

function directFile(path, label, { mode = 0o600 } = {}) {
  absolute(path, label);
  const entry = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (
    entry === undefined
    || !entry.isFile()
    || entry.isSymbolicLink()
    || entry.nlink !== 1n
    || realpathSync(path) !== path
    || (
      typeof process.getuid === 'function'
      && entry.uid !== BigInt(process.getuid())
    )
    || Number(entry.mode & 0o7777n) !== mode
  ) {
    fail(
      `${label} must be one direct canonical user-owned mode-${
        mode.toString(8)
      } single-link file`,
    );
  }
  return entry;
}

function stableBytes(path, label, options = undefined) {
  const beforePath = directFile(path, label, options);
  const fd = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const before = fstatSync(fd, { bigint: true });
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    if (
      !identityEqual(beforePath, before)
      || !identityEqual(before, after)
      || !identityEqual(after, afterPath)
      || BigInt(bytes.length) !== after.size
    ) {
      fail(`${label} changed while it was read`);
    }
    return Buffer.from(bytes);
  } finally {
    closeSync(fd);
  }
}

function jcsFile(path, label, options = undefined) {
  const bytes = stableBytes(path, label, options);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(canonical(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return Object.freeze({
    bytes,
    path,
    sha256: sha256(bytes),
    value,
  });
}

function assertSafeRuntime() {
  if (process.execArgv.length !== 0) {
    fail('Q-01 final replay refuses process.execArgv loader or preload controls');
  }
  const contaminated = Object.keys(process.env).filter((key) =>
    key === 'NODE_OPTIONS'
      || key === 'NODE_PATH'
      || key === 'NODE_V8_COVERAGE'
      || key.startsWith('LD_')
      || key.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(
      `Q-01 final replay refuses ambient loader, preload, or dynamic-linker controls: ${
        contaminated.sort().join(',')
      }`,
    );
  }
}

function snapshotQ01Bundle(root) {
  directDirectory(root, 'Q-01-pre bundle', { mode: 0o700 });
  const actual = readdirSync(root).sort();
  if (!same(actual, [...Q01_FILES])) {
    fail('Q-01-pre bundle has missing or unreferenced files');
  }
  const files = Object.freeze(Object.fromEntries(Q01_FILES.map((name) => {
    const file = jcsFile(join(root, name), `Q-01-pre ${name}`);
    return [name, Object.freeze({
      bytes: file.bytes.length,
      sha256: file.sha256,
      value: file.value,
    })];
  })));
  return Object.freeze({
    files,
    inventorySha256: sha256(canonical(Q01_FILES.map((name) => ({
      bytes: files[name].bytes,
      path: name,
      sha256: files[name].sha256,
    })))),
  });
}

function validateQ01Replay(replay, snapshot, {
  expectedBundle,
  expectedCommit,
  expectedTree,
  testOnly,
}) {
  exact(replay, [
    'boundaries',
    'bundlePath',
    'chainAuthenticated',
    'executed',
    'finalArtifacts',
    'finalQualification',
    'gitCommit',
    'gitTree',
    'implementations',
    'localOnly',
    'preCeremony',
    'qualification',
    'reference',
    'schema',
    'signed',
    'sourceSetSha256',
    'status',
  ], 'Q-01-pre replay result');
  if (
    replay.schema
      !== `${V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA}/verification`
    || replay.status !== (testOnly ? TEST_Q01_STATUS : PUBLIC_Q01_STATUS)
    || replay.localOnly !== true
    || replay.preCeremony !== true
    || replay.chainAuthenticated !== false
    || replay.signed !== false
    || replay.finalArtifacts !== false
    || replay.finalQualification !== false
    || replay.reference !== REFERENCE_ID
    || !same(replay.implementations, IMPLEMENTATIONS)
    || replay.executed !== !testOnly
    || replay.gitCommit !== expectedCommit
    || replay.gitTree !== expectedTree
    || replay.bundlePath !== expectedBundle
    || resolve(replay.bundlePath) !== replay.bundlePath
  ) {
    fail('Q-01-pre replay claim, source, or four-lane boundary is invalid');
  }
  hash(replay.sourceSetSha256, 'Q-01-pre sourceSetSha256');
  if (!Array.isArray(replay.boundaries) || replay.boundaries.length === 0) {
    fail('Q-01-pre boundary vector inventory is invalid');
  }
  const source = snapshot.files['source-set.json'].value;
  const qualification = snapshot.files['qualification.json'].value;
  if (
    source.gitCommit !== replay.gitCommit
    || source.gitTree !== replay.gitTree
    || source.sourceSetSha256 !== replay.sourceSetSha256
    || qualification.sourceSetSha256 !== replay.sourceSetSha256
    || qualification.testOnly !== testOnly
    || !Array.isArray(qualification.implementations)
    || qualification.implementations.length !== IMPLEMENTATIONS.length
    || qualification.reference?.id !== REFERENCE_ID
  ) {
    fail('Q-01-pre sealed source, qualification, or replay identity differs');
  }
  const outputPins = qualification.implementations.map((entry, index) => {
    if (
      entry.id !== IMPLEMENTATIONS[index]
      || entry.role !== 'implementation'
    ) {
      fail('Q-01-pre sealed implementation order or role differs');
    }
    return Object.freeze({
      id: entry.id,
      outputSha256: hash(
        entry.outputSha256,
        `Q-01-pre ${entry.id} outputSha256`,
      ),
    });
  });
  hash(
    qualification.reference.outputSha256,
    'Q-01-pre JavaScript reference outputSha256',
  );
  const counters = {
    stateMutations: qualification.agreement?.stateMutations,
    packetMutations: qualification.agreement?.packetMutations,
    publicInputVectors: qualification.agreement?.publicInputVectors,
  };
  if (
    Object.values(counters).some(
      (value) => !Number.isSafeInteger(value) || value <= 0,
    )
  ) {
    fail('Q-01-pre semantic vector counters are invalid');
  }
  return Object.freeze({
    counters: Object.freeze(counters),
    outputPins: Object.freeze(outputPins),
    referenceOutputSha256: qualification.reference.outputSha256,
    semanticFreezeSha256: sha256(canonical({
      agreement: qualification.agreement,
      implementations: qualification.implementations.map((entry) => ({
        id: entry.id,
        output: entry.output,
        outputSha256: entry.outputSha256,
      })),
      reference: qualification.reference,
    })),
    sourceSetSha256: replay.sourceSetSha256,
  });
}

function finalRuntime(runtime, {
  expectedCommit,
  expectedTree,
}) {
  plain(runtime, 'final runtime');
  exact(runtime.claims, [
    'ceremonyQualified',
    'developmentKey',
    'finalKey',
    'production',
    'releaseQualified',
  ], 'final runtime claims');
  if (
    runtime.eligibility !== 'final-qualified'
    || runtime.claims.ceremonyQualified !== true
    || runtime.claims.developmentKey !== false
    || runtime.claims.finalKey !== true
    || runtime.claims.production !== false
    || runtime.claims.releaseQualified !== false
  ) {
    fail(
      'Q-01 final replay requires final-key, ceremony-qualified, non-development, non-production, non-release runtime material',
    );
  }
  const relationSourceManifestSha256 = hash(
    runtime.finalBuildEvidence?.relationSourceManifestSha256,
    'final relation source manifest SHA-256',
  );
  const relationSourceManifestArtifactId = runtime.finalBuildEvidence
    ?.relationSourceManifestArtifactId;
  if (
    typeof relationSourceManifestArtifactId !== 'string'
    || relationSourceManifestArtifactId.length === 0
  ) {
    fail('final runtime relation source manifest artifact identity is invalid');
  }
  const r1csSha256 = hash(
    runtime.proofArtifacts?.r1cs?.sha256,
    'final R1CS SHA-256',
  );
  const witnessWasmSha256 = hash(
    runtime.proofArtifacts?.wasm?.sha256,
    'final witness WASM SHA-256',
  );
  const verificationKeySha256 = hash(
    runtime.proofArtifacts?.verificationKey?.sha256,
    'final verification key SHA-256',
  );
  const finalZkeySha256 = hash(
    runtime.proofArtifacts?.provingKey?.sha256,
    'final proving key SHA-256',
  );
  const runtimeMaterialSha256 = hash(
    runtime.runtimeMaterial?.materialSha256,
    'final runtime material SHA-256',
  );
  const runtimeArtifactSha256 = hash(
    runtime.runtimeArtifactSha256,
    'final runtime artifact SHA-256',
  );
  const snarkjsToolchainSha256 = hash(
    runtime.finalEvidence?.snarkjsToolchainSha256,
    'final SnarkJS toolchain SHA-256',
  );
  const finalZkeyToolchainManifestSha256 = hash(
    runtime.finalZkeyEvidence?.snarkjsToolchainManifestSha256,
    'final zkey toolchain manifest SHA-256',
  );
  if (
    runtime.finalZkeyEvidence.r1csSha256 !== r1csSha256
    || runtime.finalZkeyEvidence.finalZkeySha256 !== finalZkeySha256
    || runtime.finalZkeyEvidence.verificationKeySha256
      !== verificationKeySha256
    || runtime.finalEvidence.sourceCommit !== expectedCommit
    || runtime.finalEvidence.sourceTree !== expectedTree
  ) {
    fail('final runtime proof pins or reproduced source identity differ');
  }
  return Object.freeze({
    finalZkeySha256,
    finalZkeyToolchainManifestSha256,
    r1csSha256,
    relationSourceManifestSha256,
    relationSourceManifestArtifactId,
    runtimeArtifactSha256,
    runtimeMaterialSha256,
    snarkjsToolchainSha256,
    verificationKeySha256,
    witnessWasmSha256,
  });
}

function d01ExpectedBinding({
  descriptor,
  expectedCommit,
  expectedTree,
  releaseRootId,
  runtime,
  runtimePins,
}) {
  return Object.freeze({
    profileId: descriptor.profileId,
    instanceId: descriptor.instanceId,
    topologyId: descriptor.finalLocks.topology.id,
    descriptorSha256: descriptor.descriptor.sha256,
    manifestSha256: descriptor.manifest.sha256,
    releaseRootId,
    sourceCommit: expectedCommit,
    sourceTree: expectedTree,
    r1csSha256: runtimePins.r1csSha256,
    ptauSha256: runtime.finalZkeyEvidence.powersOfTauSha256,
    finalZkeySha256: runtimePins.finalZkeySha256,
    verificationKeySha256: runtimePins.verificationKeySha256,
    snarkjsToolchainSha256: runtimePins.snarkjsToolchainSha256,
    contributorCount: runtime.finalEvidence.contributorCount,
    transcriptSha256: runtime.finalEvidence.transcriptSha256,
    beaconSha256: runtime.finalEvidence.beaconSha256,
    transcriptVerificationSha256s:
      runtime.finalEvidence.transcriptVerificationSha256s,
    reproductionSha256s: runtime.finalEvidence.reproductionSha256s,
  });
}

function validateD01(value, {
  descriptor,
  expectedCommit,
  expectedTree,
  release,
  runtime,
  runtimePins,
}) {
  const bindingKeys = [
    'beaconSha256',
    'contributorCount',
    'descriptorSha256',
    'finalZkeySha256',
    'instanceId',
    'manifestSha256',
    'profileId',
    'ptauSha256',
    'r1csSha256',
    'releaseRootId',
    'reproductionSha256s',
    'snarkjsToolchainSha256',
    'sourceCommit',
    'sourceTree',
    'topologyId',
    'transcriptSha256',
    'transcriptVerificationSha256s',
    'verificationKeySha256',
  ];
  exact(value, [
    ...bindingKeys,
    'ceremonyInventorySha256',
    'd01Qualified',
    'postCeremonyBindingSha256',
    'production',
    'releaseBootstrapSha256',
    'releaseQualified',
    'schema',
    'status',
  ], 'D-01 result');
  if (
    value.schema !== V2_D01_RESULT_SCHEMA
    || value.status
      !== 'd01-qualified-final-key-not-production-or-release'
    || value.d01Qualified !== true
    || value.production !== false
    || value.releaseQualified !== false
    || value.releaseBootstrapSha256 !== release.releaseBootstrapSha256
  ) {
    fail('D-01 result qualification or release-root boundary is invalid');
  }
  const expected = d01ExpectedBinding({
    descriptor,
    expectedCommit,
    expectedTree,
    releaseRootId: release.releaseRootId,
    runtime,
    runtimePins,
  });
  validateV2D01PostCeremonyBinding({
    schema: V2_D01_POST_CEREMONY_BINDING_SCHEMA,
    ...Object.fromEntries(bindingKeys.map((key) => [key, value[key]])),
  }, expected);
  hash(value.ceremonyInventorySha256, 'D-01 ceremony inventory SHA-256');
  hash(
    value.postCeremonyBindingSha256,
    'D-01 post-ceremony binding SHA-256',
  );
  return expected;
}

function relationArtifact(descriptor, {
  expectedArtifactId,
  expectedSha256,
}) {
  if (!(descriptor.artifacts instanceof Map)) {
    fail('validated descriptor artifact map is unavailable');
  }
  const artifactId = expectedArtifactId;
  const artifact = descriptor.artifacts.get(artifactId);
  if (
    typeof artifactId !== 'string'
    || artifactId.length === 0
    || typeof artifact?.filename !== 'string'
    || artifact.sha256 !== expectedSha256
  ) {
    fail('final relation source manifest artifact identity or hash is invalid');
  }
  return Object.freeze({
    artifactId,
    filename: absolute(
      artifact.filename,
      'final relation source manifest artifact',
    ),
  });
}

function createOutput(directory) {
  if (existsSync(directory)) return false;
  directDirectory(dirname(directory), 'Q-01 final replay output parent');
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  directDirectory(
    directory,
    'Q-01 final replay output directory',
    { mode: 0o700 },
  );
  return true;
}

function writeDirect(directory, filename, value) {
  const bytes = canonical(value);
  const path = join(directory, filename);
  const temporary = join(
    directory,
    `.${filename}.${process.pid}.${Date.now()}.tmp`,
  );
  const fd = openSync(
    temporary,
    constants.O_WRONLY
      | constants.O_CREAT
      | constants.O_EXCL
      | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(fd, bytes, offset, bytes.length - offset);
      if (written <= 0) fail('Q-01 final replay atomic write made no progress');
      offset += written;
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  directFile(path, `Q-01 final replay ${filename}`);
  const directoryFd = openSync(
    directory,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0),
  );
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
  return Object.freeze({ path, sha256: sha256(bytes) });
}

function outputOutsideCheckout(directory) {
  return directory !== workspaceRoot
    && !directory.startsWith(`${workspaceRoot}/`);
}

function failure(options, error, { outputCreated, testOnly }) {
  try {
    if (
      options === null
      || typeof options !== 'object'
      || typeof options.outputDirectory !== 'string'
      || !isAbsolute(options.outputDirectory)
      || resolve(options.outputDirectory) !== options.outputDirectory
      || !outputOutsideCheckout(options.outputDirectory)
    ) {
      return;
    }
    if (outputCreated) {
      directDirectory(
        options.outputDirectory,
        'Q-01 final replay failed output directory',
        { mode: 0o700 },
      );
      for (const name of readdirSync(options.outputDirectory)) {
        if (
          name === PUBLIC_FILENAME
          || name === TEST_FILENAME
          || name === 'failure.json'
          || name.startsWith(`.${PUBLIC_FILENAME}.`)
          || name.startsWith(`.${TEST_FILENAME}.`)
        ) {
          const path = join(options.outputDirectory, name);
          const entry = lstatSync(path, { throwIfNoEntry: false });
          if (entry?.isFile() && !entry.isSymbolicLink()) unlinkSync(path);
        }
      }
      if (readdirSync(options.outputDirectory).length !== 0) return;
    } else if (!createOutput(options.outputDirectory)) {
      return;
    }
    const reason = (
      error instanceof Error ? error.message : String(error)
    ).slice(0, 2048);
    writeDirect(options.outputDirectory, 'failure.json', {
      schema: testOnly
        ? V2_Q01_FINAL_REPLAY_TEST_SCHEMA
        : V2_Q01_FINAL_REPLAY_SCHEMA,
      status: testOnly
        ? 'test-only-q01-final-replay-not-validated'
        : 'q01-final-artifact-replay-not-qualified',
      q01FinalReplayQualified: false,
      production: false,
      releaseQualified: false,
      reason,
    });
  } catch {
    // Preserve the primary failure and never overwrite an existing directory.
  }
}

function claims() {
  return Object.freeze({
    ceremonyQualified: true,
    developmentKey: false,
    finalKey: true,
    production: false,
    releaseQualified: false,
  });
}

function validateResult(value, { testOnly }) {
  exact(value, [
    'claims',
    'd01',
    'finalRelation',
    'identity',
    'production',
    'q01FinalReplayQualified',
    'q01Pre',
    'releaseQualified',
    'replay',
    'schema',
    'status',
    'testOnly',
  ], 'Q-01 final replay result');
  if (
    value.schema !== (
      testOnly
        ? V2_Q01_FINAL_REPLAY_TEST_SCHEMA
        : V2_Q01_FINAL_REPLAY_SCHEMA
    )
    || value.status !== (testOnly ? TEST_STATUS : PUBLIC_STATUS)
    || value.q01FinalReplayQualified !== !testOnly
    || value.testOnly !== testOnly
    || value.production !== false
    || value.releaseQualified !== false
    || !same(value.claims, claims())
  ) {
    fail('Q-01 final replay result claim boundary is invalid');
  }
  exact(value.identity, [
    'descriptorSha256',
    'instanceId',
    'manifestSha256',
    'profileCoreSha256',
    'profileId',
    'releaseBootstrapSha256',
    'releaseRootId',
    'sourceCommit',
    'sourceTree',
    'topologyId',
  ], 'Q-01 final replay identity');
  for (const key of [
    'descriptorSha256',
    'instanceId',
    'manifestSha256',
    'profileCoreSha256',
    'profileId',
    'releaseBootstrapSha256',
  ]) hash(value.identity[key], `Q-01 final replay identity.${key}`);
  gitObject(value.identity.sourceCommit, 'Q-01 final replay source commit');
  gitObject(value.identity.sourceTree, 'Q-01 final replay source tree');
  if (
    !ROOT_ID.test(value.identity.releaseRootId)
    || typeof value.identity.topologyId !== 'string'
    || value.identity.topologyId.length === 0
  ) {
    fail('Q-01 final replay release root or topology identity is invalid');
  }
  exact(value.finalRelation, [
    'finalZkeySha256',
    'finalZkeyToolchainManifestSha256',
    'r1csSha256',
    'relationSourceManifestArtifactId',
    'relationSourceManifestSha256',
    'runtimeArtifactSha256',
    'runtimeMaterialSha256',
    'snarkjsToolchainSha256',
    'verificationKeySha256',
    'witnessWasmSha256',
  ], 'Q-01 final replay relation pins');
  for (const [key, entry] of Object.entries(value.finalRelation)) {
    if (key === 'relationSourceManifestArtifactId') {
      if (typeof entry !== 'string' || entry.length === 0) {
        fail('Q-01 final replay relation artifact id is invalid');
      }
    } else {
      hash(entry, `Q-01 final replay relation pins.${key}`);
    }
  }
  exact(value.d01, [
    'artifactSha256',
    'beaconSha256',
    'ceremonyInventorySha256',
    'contributorCount',
    'postCeremonyBindingSha256',
    'reproductionSha256s',
    'transcriptSha256',
    'transcriptVerificationSha256s',
  ], 'Q-01 final replay D-01 binding');
  for (const key of [
    'artifactSha256',
    'beaconSha256',
    'ceremonyInventorySha256',
    'postCeremonyBindingSha256',
    'transcriptSha256',
  ]) hash(value.d01[key], `Q-01 final replay d01.${key}`);
  if (
    !Number.isSafeInteger(value.d01.contributorCount)
    || value.d01.contributorCount < 5
    || !Array.isArray(value.d01.transcriptVerificationSha256s)
    || value.d01.transcriptVerificationSha256s.length !== 2
    || !Array.isArray(value.d01.reproductionSha256s)
    || value.d01.reproductionSha256s.length !== 2
  ) {
    fail('Q-01 final replay D-01 threshold summary is invalid');
  }
  for (const entry of [
    ...value.d01.transcriptVerificationSha256s,
    ...value.d01.reproductionSha256s,
  ]) hash(entry, 'Q-01 final replay D-01 evidence hash');
  exact(value.q01Pre, [
    'bundleInventorySha256',
    'bundleManifestSha256',
    'counters',
    'executionArtifactSha256',
    'implementationOutputs',
    'qualificationArtifactSha256',
    'referenceOutputSha256',
    'semanticFreezeSha256',
    'sourceSetArtifactSha256',
    'sourceSetSha256',
  ], 'Q-01 final replay pre-ceremony binding');
  for (const key of [
    'bundleInventorySha256',
    'bundleManifestSha256',
    'executionArtifactSha256',
    'qualificationArtifactSha256',
    'referenceOutputSha256',
    'semanticFreezeSha256',
    'sourceSetArtifactSha256',
    'sourceSetSha256',
  ]) hash(value.q01Pre[key], `Q-01 final replay q01Pre.${key}`);
  if (
    !same(
      value.q01Pre.implementationOutputs.map((entry) => entry.id),
      IMPLEMENTATIONS,
    )
  ) {
    fail('Q-01 final replay implementation output set is invalid');
  }
  for (const entry of value.q01Pre.implementationOutputs) {
    exact(entry, ['id', 'outputSha256'], 'Q-01 implementation output');
    hash(entry.outputSha256, `Q-01 ${entry.id} output SHA-256`);
  }
  exact(value.q01Pre.counters, [
    'packetMutations',
    'publicInputVectors',
    'stateMutations',
  ], 'Q-01 final replay vector counters');
  if (
    Object.values(value.q01Pre.counters).some(
      (entry) => !Number.isSafeInteger(entry) || entry <= 0,
    )
  ) {
    fail('Q-01 final replay vector counters are invalid');
  }
  exact(value.replay, [
    'canonicalSemanticAgreement',
    'exactFourImplementationReplay',
    'implementationIds',
    'q01BundleStableDuringReplay',
    'referenceId',
    'relationSourceManifestVerifiedAgainstLiveCheckout',
  ], 'Q-01 final replay assertions');
  if (
    value.replay.canonicalSemanticAgreement !== true
    || value.replay.exactFourImplementationReplay !== true
    || value.replay.q01BundleStableDuringReplay !== true
    || value.replay.relationSourceManifestVerifiedAgainstLiveCheckout !== true
    || value.replay.referenceId !== REFERENCE_ID
    || !same(value.replay.implementationIds, IMPLEMENTATIONS)
  ) {
    fail('Q-01 final replay assertions are incomplete');
  }
  return Object.freeze(value);
}

export function revalidateV2Q01FinalArtifactReplayResult(value) {
  return validateResult(value, { testOnly: false });
}

/** TEST-ONLY: validates only the visibly nonqualifying result schema. */
export function revalidateV2Q01FinalArtifactReplayTestResultForTestOnly(value) {
  return validateResult(value, { testOnly: true });
}

const publicDependencies = Object.freeze({
  deriveRuntime: deriveV2Pf10RuntimeFromValidatedDescriptor,
  loadDescriptor: loadV2InstanceDescriptor,
  resolveReleaseRoot: resolveV2FinalReleaseRoot,
  verifyProfileCore: verifyV2FinalReleaseProfileCore,
  verifyD01Evidence: verifyV2D01FinalCeremonyEvidence,
  verifyQ01Bundle: verifyV2Q01CommitBoundBundle,
  verifyRelationManifest: (value) =>
    verifyV2RelationSourceManifest(value, { repositoryRoot: workspaceRoot }),
});

function validateDependencies(value) {
  exact(value, [
    'deriveRuntime',
    'loadDescriptor',
    'resolveReleaseRoot',
    'verifyProfileCore',
    'verifyD01Evidence',
    'verifyQ01Bundle',
    'verifyRelationManifest',
  ], 'Q-01 final replay TEST-ONLY dependencies');
  for (const [name, dependency] of Object.entries(value)) {
    if (typeof dependency !== 'function') {
      fail(`Q-01 final replay TEST-ONLY dependency ${name} is not a function`);
    }
  }
  return value;
}

async function execute(options, dependencies, { testOnly }) {
  exact(options, [
    'd01ResultPath',
    'ceremonyDirectory',
    'descriptorPath',
    'expectedCommit',
    'expectedTree',
    'finalManifestPath',
    'outputDirectory',
    'profileCorePath',
    'q01PreBundle',
    'releaseRootId',
  ], 'Q-01 final replay options');
  let outputCreated = false;
  try {
    assertSafeRuntime();
    if (
      !ROOT_ID.test(options.releaseRootId)
      || !SHA1.test(options.expectedCommit)
      || !SHA1.test(options.expectedTree)
    ) {
      fail('Q-01 final replay release root or expected Git pins are malformed');
    }
    absolute(options.outputDirectory, 'Q-01 final replay output directory');
    if (!outputOutsideCheckout(options.outputDirectory)) {
      fail('Q-01 final replay output directory must be outside the source checkout');
    }
    absolute(options.q01PreBundle, 'Q-01 final replay Q-01-pre bundle');
    if (
      options.outputDirectory === options.q01PreBundle
      || options.outputDirectory.startsWith(`${options.q01PreBundle}/`)
    ) {
      fail('Q-01 final replay output directory must not modify its Q-01-pre bundle');
    }

    // Trust order: compiled authority precedes all caller-selected evidence.
    const releaseRoot = dependencies.resolveReleaseRoot(
      options.releaseRootId,
    );

    const profile = jcsFile(
      options.profileCorePath,
      'Q-01 final replay profile core',
    );
    const descriptorFile = jcsFile(
      options.descriptorPath,
      'Q-01 final replay descriptor',
    );
    const manifest = jcsFile(
      options.finalManifestPath,
      'Q-01 final replay final manifest',
    );
    const d01 = jcsFile(
      options.d01ResultPath,
      'Q-01 final replay D-01 result',
    );
    const before = snapshotQ01Bundle(options.q01PreBundle);

    const release = dependencies.verifyProfileCore(
      releaseRoot,
      profile.bytes,
      profile.value,
    );
    if (
      release.releaseRootId !== options.releaseRootId
      || release.profileId !== releaseRoot.profileId
    ) {
      fail('selected final release root metadata differs from verified profile metadata');
    }
    const descriptor = await dependencies.loadDescriptor({
      descriptorPath: options.descriptorPath,
      profileCore: profile.value,
      trustedSigners: release.descriptorSigners,
    });
    if (
      descriptor.profileId !== release.profileId
      || descriptor.descriptor.sha256 !== descriptorFile.sha256
      || descriptor.manifest.filename !== options.finalManifestPath
      || descriptor.manifest.sha256 !== manifest.sha256
      || descriptor.finalLocks?.topology?.id !== releaseRoot.topology?.id
    ) {
      fail(
        'final profile, descriptor, manifest, signature, or topology identity differs',
      );
    }
    const runtime = await dependencies.deriveRuntime(descriptor);
    const runtimePins = finalRuntime(runtime, {
      expectedCommit: options.expectedCommit,
      expectedTree: options.expectedTree,
    });
    const verifiedD01 = await dependencies.verifyD01Evidence({
      ceremonyDirectory: options.ceremonyDirectory,
      descriptorPath: options.descriptorPath,
      expectedCommit: options.expectedCommit,
      expectedTree: options.expectedTree,
      finalManifestPath: options.finalManifestPath,
      profileCorePath: options.profileCorePath,
      releaseRootId: options.releaseRootId,
    });
    if (!same(d01.value, verifiedD01)) {
      fail('caller-supplied D-01 result differs from independently revalidated ceremony evidence');
    }
    validateD01(verifiedD01, {
      descriptor,
      expectedCommit: options.expectedCommit,
      expectedTree: options.expectedTree,
      release,
      runtime,
      runtimePins,
    });

    const relationReference = relationArtifact(
      descriptor,
      {
        expectedArtifactId: runtimePins.relationSourceManifestArtifactId,
        expectedSha256: runtimePins.relationSourceManifestSha256,
      },
    );
    const relation = jcsFile(
      relationReference.filename,
      'Q-01 final replay relation source manifest',
    );
    if (relation.sha256 !== runtimePins.relationSourceManifestSha256) {
      fail('final relation source manifest hash differs from the final runtime');
    }
    const parsedRelation = parseV2RelationSourceManifest(relation.bytes);
    await dependencies.verifyRelationManifest(parsedRelation);

    const q01Replay = await dependencies.verifyQ01Bundle(
      options.q01PreBundle,
    );
    const after = snapshotQ01Bundle(options.q01PreBundle);
    if (!same(before, after)) {
      fail('Q-01-pre bundle changed during final-artifact replay');
    }
    const q01 = validateQ01Replay(q01Replay, after, {
      expectedBundle: options.q01PreBundle,
      expectedCommit: options.expectedCommit,
      expectedTree: options.expectedTree,
      testOnly,
    });

    const result = Object.freeze({
      schema: testOnly
        ? V2_Q01_FINAL_REPLAY_TEST_SCHEMA
        : V2_Q01_FINAL_REPLAY_SCHEMA,
      status: testOnly ? TEST_STATUS : PUBLIC_STATUS,
      q01FinalReplayQualified: !testOnly,
      testOnly,
      production: false,
      releaseQualified: false,
      claims: claims(),
      identity: Object.freeze({
        profileId: descriptor.profileId,
        instanceId: descriptor.instanceId,
        topologyId: descriptor.finalLocks.topology.id,
        profileCoreSha256: profile.sha256,
        descriptorSha256: descriptor.descriptor.sha256,
        manifestSha256: descriptor.manifest.sha256,
        releaseRootId: release.releaseRootId,
        releaseBootstrapSha256: release.releaseBootstrapSha256,
        sourceCommit: options.expectedCommit,
        sourceTree: options.expectedTree,
      }),
      finalRelation: Object.freeze({
        ...runtimePins,
        relationSourceManifestArtifactId: relationReference.artifactId,
      }),
      d01: Object.freeze({
        artifactSha256: d01.sha256,
        ceremonyInventorySha256: d01.value.ceremonyInventorySha256,
        postCeremonyBindingSha256:
          d01.value.postCeremonyBindingSha256,
        contributorCount: d01.value.contributorCount,
        transcriptSha256: d01.value.transcriptSha256,
        beaconSha256: d01.value.beaconSha256,
        transcriptVerificationSha256s:
          d01.value.transcriptVerificationSha256s,
        reproductionSha256s: d01.value.reproductionSha256s,
      }),
      q01Pre: Object.freeze({
        bundleManifestSha256: after.files['manifest.json'].sha256,
        bundleInventorySha256: after.inventorySha256,
        sourceSetArtifactSha256: after.files['source-set.json'].sha256,
        qualificationArtifactSha256:
          after.files['qualification.json'].sha256,
        executionArtifactSha256: after.files['execution.json'].sha256,
        sourceSetSha256: q01.sourceSetSha256,
        semanticFreezeSha256: q01.semanticFreezeSha256,
        referenceOutputSha256: q01.referenceOutputSha256,
        implementationOutputs: q01.outputPins,
        counters: q01.counters,
      }),
      replay: Object.freeze({
        referenceId: REFERENCE_ID,
        implementationIds: IMPLEMENTATIONS,
        exactFourImplementationReplay: true,
        canonicalSemanticAgreement: true,
        q01BundleStableDuringReplay: true,
        relationSourceManifestVerifiedAgainstLiveCheckout: true,
      }),
    });
    validateResult(result, { testOnly });
    outputCreated = createOutput(options.outputDirectory);
    if (!outputCreated) {
      fail('Q-01 final replay refuses a preexisting output directory');
    }
    const artifact = writeDirect(
      options.outputDirectory,
      testOnly ? TEST_FILENAME : PUBLIC_FILENAME,
      result,
    );
    if (
      readdirSync(options.outputDirectory).length !== 1
      || !readdirSync(options.outputDirectory).includes(
        testOnly ? TEST_FILENAME : PUBLIC_FILENAME,
      )
    ) {
      fail('Q-01 final replay output directory is not an exact one-file result');
    }
    return Object.freeze({
      ...result,
      artifactPath: artifact.path,
      artifactSha256: artifact.sha256,
    });
  } catch (error) {
    failure(options, error, { outputCreated, testOnly });
    if (error instanceof V2Q01FinalArtifactReplayError) throw error;
    fail(
      `Q-01 final artifact replay dependency failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export async function runV2Q01FinalArtifactReplay(
  options,
  dependencies = undefined,
) {
  if (dependencies !== undefined) {
    fail(
      'Q-01 final replay public verifier refuses injected dependencies, fixtures, or test doubles',
    );
  }
  return execute(options, publicDependencies, { testOnly: false });
}

/**
 * TEST-ONLY: exercises orchestration with injected final-looking records.
 * It always emits q01FinalReplayQualified:false and cannot use the public
 * result schema or filename.
 */
export async function runV2Q01FinalArtifactReplayForTest(
  options,
  dependencies,
) {
  return execute(
    options,
    validateDependencies(dependencies),
    { testOnly: true },
  );
}

export function parseV2Q01FinalArtifactReplayArguments(argv) {
  const names = new Set([
    '--profile-core',
    '--descriptor',
    '--final-manifest',
    '--release-root',
    '--d01-result',
    '--ceremony-dir',
    '--q01-pre-bundle',
    '--expected-commit',
    '--expected-tree',
    '--output-dir',
  ]);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) {
    fail('usage: v2-q01-final-artifact-replay.mjs --profile-core <absolute-file> --descriptor <absolute-file> --final-manifest <absolute-file> --release-root <compiled-root-id> --d01-result <absolute-file> --ceremony-dir <absolute-directory> --q01-pre-bundle <absolute-directory> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-directory>');
  }
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      !names.has(name)
      || fields.has(name)
      || typeof value !== 'string'
      || value.length === 0
    ) {
      fail('Q-01 final replay arguments are malformed, duplicated, or unknown');
    }
    fields.set(name, value);
  }
  for (const name of names) {
    if (!fields.has(name)) fail(`Q-01 final replay requires ${name}`);
  }
  if (
    !ROOT_ID.test(fields.get('--release-root'))
    || !SHA1.test(fields.get('--expected-commit'))
    || !SHA1.test(fields.get('--expected-tree'))
  ) {
    fail('Q-01 final replay release root or expected Git pins are malformed');
  }
  return Object.freeze({
    profileCorePath: absolute(
      fields.get('--profile-core'),
      'Q-01 final replay profile core',
    ),
    descriptorPath: absolute(
      fields.get('--descriptor'),
      'Q-01 final replay descriptor',
    ),
    finalManifestPath: absolute(
      fields.get('--final-manifest'),
      'Q-01 final replay final manifest',
    ),
    releaseRootId: fields.get('--release-root'),
    d01ResultPath: absolute(
      fields.get('--d01-result'),
      'Q-01 final replay D-01 result',
    ),
    ceremonyDirectory: absolute(
      fields.get('--ceremony-dir'),
      'Q-01 final replay ceremony directory',
    ),
    q01PreBundle: absolute(
      fields.get('--q01-pre-bundle'),
      'Q-01 final replay Q-01-pre bundle',
    ),
    expectedCommit: fields.get('--expected-commit'),
    expectedTree: fields.get('--expected-tree'),
    outputDirectory: absolute(
      fields.get('--output-dir'),
      'Q-01 final replay output directory',
    ),
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2Q01FinalArtifactReplay(
      parseV2Q01FinalArtifactReplayArguments(process.argv.slice(2)),
    );
    process.stdout.write(`${canonicalizeJcs(result)}\n`);
  } catch (error) {
    process.stderr.write(
      `Q-01 final artifact replay failed: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    process.exitCode = 1;
  }
}
