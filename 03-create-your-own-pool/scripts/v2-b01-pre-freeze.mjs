#!/usr/bin/env node
/*
 * B-01-pre records a local, development-key candidate for independent review.
 * It deliberately does not create a ceremony, authorization, final-key, or
 * release claim. The runtime is copied by reference: the sealed manifest
 * authenticates every byte in the supplied, preserved runtime directory.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { ACTION_PACKET_BYTES, ACTION_PACKET_OFFSETS } from '../packages/action/v2/packet.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../packages/action/v2/topology.mjs';
import { canonicalizeJcs, deriveProfileId, validateProfileCore } from '../packages/profile/v2/profile-core.mjs';
import { assertLocalVerifierRuntimeCoherence } from './run-domain-tests.mjs';
import { verifyV2Q01CommitBoundBundle } from './v2-q01-commit-bound-evidence.mjs';

export const V2_B01_PRE_FREEZE_SCHEMA = 'shieldkit-v2-direct-b01-pre-freeze-v1';
const RUNTIME_SCHEMA = 'shieldkit-v2-direct-pf10-development-runtime-bundle-v2';
const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PROJECT = resolve(ROOT, '03-create-your-own-pool');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const bytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

export class V2B01PreFreezeError extends Error {
  constructor(message) { super(message); this.name = 'V2B01PreFreezeError'; }
}
const fail = (message) => { throw new V2B01PreFreezeError(message); };
function assertSafeRuntime() {
  if (process.execArgv.length !== 0) {
    fail('B-01-pre refuses Node loader, preload, or exec-argument controls');
  }
  const contaminated = Object.keys(process.env).filter((key) =>
    key === 'NODE_OPTIONS'
      || key === 'NODE_PATH'
      || key === 'NODE_V8_COVERAGE'
      || key.startsWith('LD_')
      || key.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(
      `B-01-pre refuses ambient loader, preload, or dynamic-linker controls: ${
        contaminated.sort().join(',')
      }`,
    );
  }
}
function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) fail(`${label} has missing or unknown properties`);
  return value;
}
function canonicalJson(filename, label) {
  const data = ownedFile(filename, label); let value;
  try { value = JSON.parse(data.toString('utf8')); } catch { fail(`${label} is not JSON`); }
  if (!data.equals(bytes(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
  return Object.freeze({ bytes: data, value });
}
function ownerPrivate(stat, label, directory = false) {
  const isBigInt = typeof stat.mode === 'bigint';
  const privateMode = isBigInt
    ? Number(stat.mode & 0o7777n)
    : stat.mode & 0o7777;
  const expectedMode = directory ? 0o700 : 0o600;
  const owner = typeof process.getuid !== 'function'
    || stat.uid === (isBigInt ? BigInt(process.getuid()) : process.getuid());
  const singleLink = directory
    || stat.nlink === (isBigInt ? 1n : 1);
  if (
    (directory && !stat.isDirectory())
    || (!directory && !stat.isFile())
    || stat.isSymbolicLink()
    || !singleLink
    || !owner
    || privateMode !== expectedMode
  ) {
    fail(
      `${label} must be a direct user-owned mode-${
        expectedMode.toString(8)
      } ${directory ? 'directory' : 'single-link file'}`,
    );
  }
}
function directDirectory(value, label) {
  if (!isAbsolute(value)) fail(`${label} must be absolute`);
  const filename = resolve(value); let stat;
  try { stat = lstatSync(filename, { bigint: true }); } catch { fail(`${label} is missing`); }
  ownerPrivate(stat, label, true);
  if (realpathSync(filename) !== filename) fail(`${label} must be canonical without symlink traversal`);
  return filename;
}
function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}
function ownedFile(filename, label) {
  let pathBefore;
  try { pathBefore = lstatSync(filename, { bigint: true }); } catch { fail(`${label} is missing`); }
  ownerPrivate(pathBefore, label);
  if (realpathSync(filename) !== filename) fail(`${label} traverses a symlink`);
  let fd;
  try {
    fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(fd, { bigint: true });
    ownerPrivate(before, label);
    if (!sameIdentity(pathBefore, before)) fail(`${label} changed before it was read`);
    const data = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(filename, { bigint: true });
    ownerPrivate(pathAfter, label);
    if (
      !sameIdentity(before, after)
      || !sameIdentity(after, pathAfter)
      || BigInt(data.length) !== after.size
      || realpathSync(filename) !== filename
    ) fail(`${label} changed while read`);
    return data;
  } finally { if (fd !== undefined) closeSync(fd); }
}
function safeRelative(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || value.startsWith('/') || value === '..' || value.startsWith('../') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) fail(`${label} must be a normalized relative POSIX path`);
  return value;
}
function child(root, value, label) {
  const relativePath = safeRelative(value, label); const filename = resolve(root, ...relativePath.split('/'));
  const pathRelative = relative(root, filename);
  if (pathRelative === '' || pathRelative === '..' || pathRelative.startsWith(`..${sep}`)) fail(`${label} escapes its root`);
  return filename;
}
function inventory(root) {
  const files = [];
  const rootBefore = lstatSync(root, { bigint: true });
  ownerPrivate(rootBefore, 'runtime bundle', true);
  const walk = (directory, prefix = '') => {
    const stat = lstatSync(directory, { bigint: true }); ownerPrivate(stat, `directory ${prefix || '.'}`, true);
    if (realpathSync(directory) !== directory) fail(`directory ${prefix || '.'} traverses a symlink`);
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const filename = child(root, name, 'runtime inventory path');
      if (entry.isDirectory()) walk(filename, name);
      else if (entry.isFile()) { const data = ownedFile(filename, `runtime artifact ${name}`); files.push(Object.freeze({ path: name, bytes: data.length, sha256: sha256(data) })); }
      else fail(`runtime inventory contains unsupported entry: ${name}`);
    }
  };
  walk(root);
  const rootAfter = lstatSync(root, { bigint: true });
  if (!sameIdentity(rootBefore, rootAfter) || realpathSync(root) !== root) {
    fail('runtime bundle changed while inventoried');
  }
  return Object.freeze(files);
}
function artifact(value, label, { requireBytes = true } = {}) {
  exact(value, requireBytes ? ['bytes', 'id', 'path', 'sha256'] : ['id', 'path', 'sha256'], label);
  if (typeof value.id !== 'string' || !/^[a-z][a-z0-9-]*$/u.test(value.id) || (requireBytes && (!Number.isSafeInteger(value.bytes) || value.bytes <= 0)) || !HASH.test(value.sha256)) fail(`${label} is malformed`);
  safeRelative(value.path, `${label}.path`); return Object.freeze({ ...value });
}
function validateRuntimeSnapshot(runtimeRoot) {
  const source = canonicalJson(child(runtimeRoot, 'runtime-build-manifest.json', 'runtime manifest'), 'runtime manifest');
  const manifest = exact(source.value, ['artifactManifestTemplate', 'build', 'determinism', 'eligibility', 'finalLocks', 'instanceId', 'libauthEvidence', 'prerequisites', 'profileCore', 'profileId', 'profilePackage', 'proofArtifacts', 'qualification', 'runtimeMaterialSha256', 'schema', 'topologyId', 'verifierRoles'], 'runtime manifest');
  if (manifest.schema !== RUNTIME_SCHEMA || manifest.eligibility !== 'development-only' || !HASH.test(manifest.profileId) || !HASH.test(manifest.instanceId) || !HASH.test(manifest.runtimeMaterialSha256) || manifest.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID || !Array.isArray(manifest.verifierRoles) || manifest.verifierRoles.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length || manifest.verifierRoles.some((role, index) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index])) fail('runtime manifest development identity/topology is invalid');
  exact(manifest.artifactManifestTemplate, ['artifacts', 'instanceId', 'profileId', 'schema'], 'runtime artifact manifest');
  if (manifest.artifactManifestTemplate.schema !== 'shieldkit-artifact-manifest-v2-direct' || manifest.artifactManifestTemplate.profileId !== manifest.profileId || manifest.artifactManifestTemplate.instanceId !== manifest.instanceId || !Array.isArray(manifest.artifactManifestTemplate.artifacts)) fail('runtime artifact manifest identity is invalid');
  const listed = manifest.artifactManifestTemplate.artifacts.map((entry, index) => artifact(entry, `runtime artifact ${index}`, { requireBytes: false }));
  const ids = new Set(); const paths = new Set();
  for (const entry of listed) {
    if (ids.has(entry.id) || paths.has(entry.path)) fail('runtime artifact manifest is ambiguous'); ids.add(entry.id); paths.add(entry.path);
    const data = ownedFile(child(runtimeRoot, entry.path, `runtime artifact ${entry.id}`), `runtime artifact ${entry.id}`);
    if (sha256(data) !== entry.sha256) fail(`runtime artifact ${entry.id} hash differs`);
  }
  const inventoryRecords = inventory(runtimeRoot);
  const actual = inventoryRecords.map((entry) => entry.path).sort();
  const expected = ['runtime-build-manifest.json', ...paths].sort();
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) fail('runtime artifact inventory is not exhaustive');
  const profileRef = artifact(manifest.profileCore, 'runtime profile core reference');
  const profileBytes = ownedFile(child(runtimeRoot, profileRef.path, 'runtime profile core'), 'runtime profile core');
  if (profileBytes.length !== profileRef.bytes || sha256(profileBytes) !== profileRef.sha256) fail('runtime profile core reference differs');
  const profile = JSON.parse(profileBytes.toString('utf8')); if (!profileBytes.equals(bytes(profile))) fail('runtime profile core is not canonical JCS');
  try { validateProfileCore(profile); } catch (error) { fail(`runtime profile core is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (deriveProfileId(profile) !== manifest.profileId || profileRef.sha256 !== sha256(profileBytes)) fail('runtime profile core does not bind runtime identity');
  const material = canonicalJson(child(runtimeRoot, 'runtime/pf10-runtime-material.json', 'runtime material'), 'runtime material');
  const materialEntry = listed.find((entry) => entry.id === 'pf10-runtime-material');
  if (materialEntry === undefined || materialEntry.path !== 'runtime/pf10-runtime-material.json' || materialEntry.sha256 !== sha256(material.bytes)) fail('runtime material artifact is not manifest-bound');
  exact(material.value, ['attestationArtifacts', 'eligibility', 'instanceId', 'libauthEvidenceArtifactId', 'profileArtifacts', 'profileId', 'proofArtifacts', 'qualificationEvidenceArtifactId', 'rawQualificationEvidenceArtifactId', 'schema', 'setupArtifacts', 'topologyId', 'unlockArtifacts', 'verifierRoles'], 'runtime material');
  if (material.value.schema !== 'shieldkit-v2-direct-pf10-runtime-artifact-v3' || material.value.eligibility !== 'development-only' || material.value.profileId !== manifest.profileId || material.value.instanceId !== manifest.instanceId || material.value.topologyId !== manifest.topologyId || canonicalizeJcs(material.value.verifierRoles) !== canonicalizeJcs(manifest.verifierRoles)) fail('runtime material development identity is invalid');
  return Object.freeze({
    manifest,
    manifestSha256: sha256(source.bytes),
    profile,
    profileCoreSha256: sha256(profileBytes),
    artifactCount: listed.length,
    inventorySha256: sha256(bytes(inventoryRecords)),
  });
}
function git(command) {
  let gitPath;
  for (const candidate of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(candidate, { throwIfNoEntry: false });
    if (
      entry?.isFile()
      && !entry.isSymbolicLink()
      && entry.nlink === 1
      && entry.uid === 0
      && (entry.mode & 0o022) === 0
      && realpathSync(candidate) === candidate
    ) {
      gitPath = candidate;
      break;
    }
  }
  if (gitPath === undefined) {
    fail('B-01-pre requires a root-owned non-writable direct git executable');
  }
  const result = spawnSync(gitPath, [
    '--no-replace-objects',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    '-c', 'include.path=/dev/null',
    '-C', ROOT,
    ...command,
  ], {
    encoding: 'utf8',
    env: {
      HOME: '/nonexistent',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
      GIT_CONFIG_COUNT: '0',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
    },
  });
  if (result.status !== 0) fail(`git ${command.join(' ')} failed`); return result.stdout.trim();
}

function assertCleanSource(expectedCommit, expectedTree) {
  if (!GIT.test(expectedCommit) || !GIT.test(expectedTree)) fail('expected commit and tree must be lowercase SHA-1 objects');
  if (git(['rev-parse', 'HEAD^{commit}']) !== expectedCommit || git(['rev-parse', 'HEAD^{tree}']) !== expectedTree) fail('source commit or tree differs from expected freeze identity');
  if (git(['status', '--porcelain=v1', '--untracked-files=all']) !== '') fail('source checkout must be clean');
}
function q01Manifest(q01Root, expectedCommit, expectedTree) {
  const result = verifyV2Q01CommitBoundBundle(q01Root);
  if (result.gitCommit !== expectedCommit || result.gitTree !== expectedTree || result.localOnly !== true || result.preCeremony !== true || result.signed !== false || result.finalArtifacts !== false || result.finalQualification !== false) fail('Q-01-pre evidence does not bind this local pre-ceremony source identity');
  const manifest = canonicalJson(child(q01Root, 'manifest.json', 'Q-01 manifest'), 'Q-01 manifest');
  return Object.freeze({ path: q01Root, manifestSha256: sha256(manifest.bytes), sourceSetSha256: result.sourceSetSha256, qualification: result.qualification, implementations: result.implementations });
}
async function validateAuthoritativeRuntime(runtimeRoot) {
  const artifactRoot = dirname(runtimeRoot);
  const libauthRoot = directDirectory(
    join(artifactRoot, 'v2-pf10-libauth-qualification'),
    'PF10 Libauth qualification bundle',
  );
  const profileRoot = directDirectory(
    join(artifactRoot, 'v2-development-profile'),
    'V2 development profile bundle',
  );
  let coherence;
  try {
    coherence = await assertLocalVerifierRuntimeCoherence({
      projectRoot: PROJECT,
      runtimeRoot,
      libauthRoot,
      profileRoot,
    });
  } catch (error) {
    fail(
      `authoritative PF10 development runtime verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const snapshot = validateRuntimeSnapshot(runtimeRoot);
  if (
    coherence.profileId !== snapshot.manifest.profileId
    || coherence.instanceId !== snapshot.manifest.instanceId
    || coherence.runtimeArtifactCount !== snapshot.artifactCount
    || coherence.runtimeMaterialSha256
      !== snapshot.manifest.runtimeMaterialSha256
    || coherence.proofArtifacts.r1cs
      !== snapshot.profile.proof.r1csSha256
    || coherence.proofArtifacts.witnessWasm
      !== snapshot.profile.proof.witnessWasmSha256
    || coherence.proofArtifacts.verificationKey
      !== snapshot.profile.proof.verificationKeySha256
  ) {
    fail('authoritative PF10 runtime result differs from its sealed bundle');
  }
  return Object.freeze({
    ...snapshot,
    coherence,
    libauthRoot,
    profileRoot,
  });
}
async function makeManifest({ runtimeRoot, q01Root, expectedCommit, expectedTree }) {
  assertCleanSource(expectedCommit, expectedTree);
  const runtime = await validateAuthoritativeRuntime(runtimeRoot);
  const q01 = q01Manifest(q01Root, expectedCommit, expectedTree);
  const after = validateRuntimeSnapshot(runtimeRoot);
  if (
    after.manifestSha256 !== runtime.manifestSha256
    || after.inventorySha256 !== runtime.inventorySha256
  ) {
    fail('PF10 development runtime changed during B-01-pre validation');
  }
  assertCleanSource(expectedCommit, expectedTree);
  return Object.freeze({
    schema: V2_B01_PRE_FREEZE_SCHEMA,
    status: 'b01-pre-freeze-candidate-awaiting-independent-review',
    b01PreFreezeCandidate: true,
    reviewed: false,
    ceremonyAuthorized: false,
    production: false,
    releaseQualified: false,
    localOnly: true,
    preCeremony: true,
    claims: Object.freeze({ developmentKey: true, finalKey: false, bchVm: false, production: false, releaseQualified: false }),
    source: Object.freeze({ repositoryRoot: ROOT, gitCommit: expectedCommit, gitTree: expectedTree }),
    packetAbi: Object.freeze({ encoding: 'shieldkit-direct-action-sda2-552', bytes: ACTION_PACKET_BYTES, offsets: ACTION_PACKET_OFFSETS, digest: 'sha256', publicInputs: Object.freeze({ count: 2, limbBits: 128, endianness: 'unsigned-be-u128' }) }),
    profile: Object.freeze({ profileId: runtime.manifest.profileId, profileCoreSha256: runtime.profileCoreSha256, relationSha256: runtime.profile.proof.relationSha256, r1csSha256: runtime.profile.proof.r1csSha256, witnessWasmSha256: runtime.profile.proof.witnessWasmSha256, verificationKeySha256: runtime.profile.proof.verificationKeySha256 }),
    topology: Object.freeze({ topologyId: runtime.manifest.topologyId, verifierRoles: runtime.manifest.verifierRoles }),
    runtime: Object.freeze({
      path: runtimeRoot,
      manifestSha256: runtime.manifestSha256,
      inventorySha256: runtime.inventorySha256,
      runtimeMaterialSha256: runtime.manifest.runtimeMaterialSha256,
      artifactCount: runtime.artifactCount,
      artifactManifest: runtime.manifest.artifactManifestTemplate,
      libauthEvidenceSha256: runtime.coherence.libauthEvidenceSha256,
      qualificationEvidenceSha256:
        runtime.coherence.qualificationEvidenceSha256,
      rawQualificationEvidenceSha256:
        runtime.coherence.rawQualificationEvidenceSha256,
      proofArtifacts: runtime.coherence.proofArtifacts,
      support: Object.freeze({
        libauthBundlePath: runtime.libauthRoot,
        profileBundlePath: runtime.profileRoot,
      }),
    }),
    q01Pre: q01,
    boundaries: Object.freeze(['This is a local development-key pre-ceremony candidate, not a reviewed freeze.', 'No final key, ceremony authorization, BCHN/LeanBCH result, production or release qualification is asserted.', 'The retained runtime directory is content-bound by hashes but remains external custody material.']),
  });
}
function writeNewBundle(outputDirectory, manifest) {
  if (!isAbsolute(outputDirectory)) fail('output directory must be absolute');
  const output = resolve(outputDirectory); if (existsSync(output)) fail('output directory must not already exist');
  if (output === ROOT || output.startsWith(`${ROOT}${sep}`)) {
    fail('output directory must be outside the source checkout');
  }
  directDirectory(dirname(output), 'output parent');
  mkdirSync(output, { mode: 0o700 });
  chmodSync(output, 0o700);
  const parentFd = openSync(dirname(output), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
  const filename = `${output}/manifest.json`;
  const temporary = `${output}/.manifest.json.${process.pid}.${Date.now()}.tmp`;
  const body = bytes(manifest);
  try {
    const manifestFd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try {
      let offset = 0;
      while (offset < body.length) {
        const written = writeSync(
          manifestFd,
          body,
          offset,
          body.length - offset,
        );
        if (written <= 0) fail('B-01-pre atomic write made no progress');
        offset += written;
      }
      fsyncSync(manifestFd);
    } finally { closeSync(manifestFd); }
    chmodSync(temporary, 0o600);
    renameSync(temporary, filename);
    ownedFile(filename, 'B-01-pre manifest');
    const directoryFd = openSync(output, constants.O_RDONLY);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    return Object.freeze({ bundlePath: output, manifestSha256: sha256(body), status: manifest.status });
  } catch (error) {
    // Preserve the direct private failed output for diagnosis. Never recursively
    // remove a pathname that another process could have replaced.
    throw error;
  }
}
async function validateFreezeManifest(root) {
  const record = canonicalJson(child(root, 'manifest.json', 'freeze manifest'), 'freeze manifest');
  const value = exact(record.value, ['b01PreFreezeCandidate', 'boundaries', 'ceremonyAuthorized', 'claims', 'localOnly', 'packetAbi', 'preCeremony', 'production', 'profile', 'q01Pre', 'releaseQualified', 'reviewed', 'runtime', 'schema', 'source', 'status', 'topology'], 'freeze manifest');
  if (value.schema !== V2_B01_PRE_FREEZE_SCHEMA || value.status !== 'b01-pre-freeze-candidate-awaiting-independent-review' || value.b01PreFreezeCandidate !== true || value.reviewed !== false || value.ceremonyAuthorized !== false || value.production !== false || value.releaseQualified !== false || value.localOnly !== true || value.preCeremony !== true || canonicalizeJcs(value.claims) !== canonicalizeJcs({ developmentKey: true, finalKey: false, bchVm: false, production: false, releaseQualified: false })) fail('freeze manifest claim boundary is invalid');
  exact(value.source, ['gitCommit', 'gitTree', 'repositoryRoot'], 'freeze source');
  if (value.source.repositoryRoot !== ROOT || !GIT.test(value.source.gitCommit) || !GIT.test(value.source.gitTree)) fail('freeze source identity is invalid');
  const expected = await makeManifest({ runtimeRoot: directDirectory(value.runtime.path, 'bound runtime bundle'), q01Root: directDirectory(value.q01Pre.path, 'bound Q-01-pre bundle'), expectedCommit: value.source.gitCommit, expectedTree: value.source.gitTree });
  if (!Buffer.from(canonicalizeJcs(expected)).equals(record.bytes)) fail('freeze manifest content no longer matches bound artifacts/source');
  const files = readdirSync(root).sort(); if (canonicalizeJcs(files) !== canonicalizeJcs(['manifest.json'])) fail('freeze bundle has extra or missing files');
  return Object.freeze({ schema: `${V2_B01_PRE_FREEZE_SCHEMA}/verification`, bundlePath: root, manifestSha256: sha256(record.bytes), status: 'verified-b01-pre-freeze-candidate-awaiting-independent-review', b01PreFreezeCandidate: true, reviewed: false, ceremonyAuthorized: false, production: false, releaseQualified: false });
}
export function parseV2B01PreFreezeArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  if (
    argv.length === 2
    && argv[0] === '--verify'
    && typeof argv[1] === 'string'
    && isAbsolute(argv[1])
    && resolve(argv[1]) === argv[1]
  ) {
    return Object.freeze({ mode: 'verify', bundlePath: argv[1] });
  }
  if (argv.length !== 10) fail('usage: v2-b01-pre-freeze.mjs --runtime-bundle <absolute-dir> --q01-pre-bundle <absolute-dir> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir> | --verify <absolute-bundle-dir>');
  const names = new Map([['--runtime-bundle', 'runtimeRoot'], ['--q01-pre-bundle', 'q01Root'], ['--expected-commit', 'expectedCommit'], ['--expected-tree', 'expectedTree'], ['--output-dir', 'outputDirectory']]); const result = {};
  for (let index = 0; index < argv.length; index += 2) { const name = names.get(argv[index]); const value = argv[index + 1]; if (name === undefined || Object.hasOwn(result, name) || typeof value !== 'string' || value.length === 0 || value.startsWith('--') || (['runtimeRoot', 'q01Root', 'outputDirectory'].includes(name) && !isAbsolute(value))) fail('invalid, duplicate, or unknown CLI argument'); result[name] = ['runtimeRoot', 'q01Root', 'outputDirectory'].includes(name) ? resolve(cwd, value) : value; }
  if (!isAbsolute(result.runtimeRoot) || !isAbsolute(result.q01Root) || !isAbsolute(result.outputDirectory) || !GIT.test(result.expectedCommit) || !GIT.test(result.expectedTree)) fail('B-01 paths must be absolute and commit/tree must be SHA-1');
  return Object.freeze({ mode: 'create', ...result });
}
export async function verifyV2B01PreFreezeBundle(bundlePath) {
  assertSafeRuntime();
  return validateFreezeManifest(
    directDirectory(bundlePath, 'freeze bundle'),
  );
}
export async function runV2B01PreFreeze(options) {
  assertSafeRuntime();
  exact(options, ['expectedCommit', 'expectedTree', 'outputDirectory', 'q01Root', 'runtimeRoot'], 'B-01 options');
  return writeNewBundle(options.outputDirectory, await makeManifest({ runtimeRoot: directDirectory(options.runtimeRoot, 'runtime bundle'), q01Root: directDirectory(options.q01Root, 'Q-01-pre bundle'), expectedCommit: options.expectedCommit, expectedTree: options.expectedTree }));
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { const args = parseV2B01PreFreezeArguments(process.argv.slice(2)); const { mode, ...options } = args; const result = mode === 'verify' ? await verifyV2B01PreFreezeBundle(options.bundlePath) : await runV2B01PreFreeze(options); process.stdout.write(`${canonicalizeJcs(result)}\n`); } catch (error) { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exitCode = 1; }
}
