#!/usr/bin/env node
/*
 * D-01 is an offline, read-only qualification verifier. The signed descriptor
 * and final-runtime-evidence verifier are the source of ceremony truth; this
 * script neither invokes setup tooling nor accepts generated test evidence.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const HASH = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const ROOT = /^[a-z][a-z0-9-]*$/;
const INVENTORY_SCHEMA = 'shieldkit-v2-direct-d01-artifact-inventory-v1';
export const V2_D01_RESULT_SCHEMA =
  'shieldkit-v2-direct-d01-final-ceremony-qualification-v1';
export const V2_D01_POST_CEREMONY_BINDING_SCHEMA =
  'shieldkit-v2-direct-d01-post-ceremony-binding-v1';

export class V2D01FinalCeremonyQualificationError extends Error {
  constructor(message) { super(message); this.name = 'V2D01FinalCeremonyQualificationError'; }
}
const fail = (message) => { throw new V2D01FinalCeremonyQualificationError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
}
function absolute(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail(`${label} must be an absolute normalized path`);
  return value;
}
function directFile(path, label) {
  absolute(path, label); const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry === undefined || !entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 || realpathSync(path) !== path) fail(`${label} must be one direct regular non-symlink file`);
  return entry;
}
function directDirectory(path, label) {
  absolute(path, label); const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry === undefined || !entry.isDirectory() || entry.isSymbolicLink() || realpathSync(path) !== path) fail(`${label} must be one direct canonical directory`);
  return entry;
}
function readJcs(path, label) {
  directFile(path, label); const bytes = readFileSync(path); let value;
  try { value = JSON.parse(bytes); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(canonical(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
  return Object.freeze({ bytes, path, sha256: sha256(bytes), value });
}
function listFiles(root) {
  const files = []; const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) fail('D-01 ceremony directory contains a symlink');
      if (entry.isDirectory()) visit(path); else if (entry.isFile()) files.push(relative(root, path));
      else fail('D-01 ceremony directory contains a non-regular artifact');
    }
  }; visit(root); return files.sort();
}
function readInventory(root) {
  const record = readJcs(join(root, 'inventory.json'), 'D-01 inventory');
  exact(record.value, ['artifacts', 'schema'], 'D-01 inventory');
  if (record.value.schema !== INVENTORY_SCHEMA || !Array.isArray(record.value.artifacts)) fail('D-01 inventory schema is unsupported');
  const pins = new Map();
  for (const entry of record.value.artifacts) {
    exact(entry, ['path', 'sha256'], 'D-01 inventory artifact');
    if (typeof entry.path !== 'string' || entry.path.length === 0 || isAbsolute(entry.path)
      || entry.path.split(/[\\/]/u).includes('..') || !HASH.test(entry.sha256) || pins.has(entry.path)) fail('D-01 inventory artifact is malformed or duplicated');
    pins.set(entry.path, entry.sha256);
  }
  const actual = listFiles(root); const expected = [...pins.keys(), 'inventory.json'].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail('D-01 ceremony directory has missing or unreferenced artifacts');
  for (const [path, hash] of pins) {
    const bytes = readFileSync(join(root, path)); if (sha256(bytes) !== hash) fail(`D-01 inventory hash differs for ${path}`);
  }
  return Object.freeze({ pins, record });
}
function parseArguments(argv) {
  const names = new Set(['--profile-core', '--descriptor', '--final-manifest', '--release-root', '--ceremony-dir', '--expected-commit', '--expected-tree', '--output-dir']);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) fail('usage: v2-final-ceremony-qualification.mjs --profile-core <absolute> --descriptor <absolute> --final-manifest <absolute> --release-root <compiled-root-id> --ceremony-dir <absolute> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>');
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!names.has(argv[index]) || fields.has(argv[index]) || typeof argv[index + 1] !== 'string' || argv[index + 1].length === 0) fail('D-01 arguments are malformed or duplicated');
    fields.set(argv[index], argv[index + 1]);
  }
  for (const name of names) if (!fields.has(name)) fail(`D-01 requires ${name}`);
  if (!ROOT.test(fields.get('--release-root')) || !SHA1.test(fields.get('--expected-commit')) || !SHA1.test(fields.get('--expected-tree'))) fail('D-01 expected pins or release root are malformed');
  return Object.freeze({ profileCorePath: absolute(fields.get('--profile-core'), 'D-01 profile core'), descriptorPath: absolute(fields.get('--descriptor'), 'D-01 descriptor'), finalManifestPath: absolute(fields.get('--final-manifest'), 'D-01 final manifest'), releaseRootId: fields.get('--release-root'), ceremonyDirectory: absolute(fields.get('--ceremony-dir'), 'D-01 ceremony directory'), expectedCommit: fields.get('--expected-commit'), expectedTree: fields.get('--expected-tree'), outputDirectory: absolute(fields.get('--output-dir'), 'D-01 output directory') });
}
export const parseV2D01Arguments = parseArguments;
function safeRuntime() {
  const dynamicLoader = Object.keys(process.env).find(
    (key) => key.startsWith('LD_') || key.startsWith('DYLD_'),
  );
  if (
    process.execArgv.length !== 0
    || process.env.NODE_OPTIONS !== undefined
    || process.env.NODE_PATH !== undefined
    || dynamicLoader !== undefined
  ) fail('D-01 refuses Node loaders, preloads, exec arguments, module-path injection, or dynamic-loader controls');
}
function trustedGit() {
  for (const candidate of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(candidate, { throwIfNoEntry: false });
    if (entry?.isFile() && !entry.isSymbolicLink() && entry.nlink === 1 && entry.uid === 0 && (entry.mode & 0o022) === 0 && realpathSync(candidate) === candidate) return candidate;
  }
  fail('D-01 requires a root-owned non-writable direct git executable');
}
async function gitState(git) {
  const run = (args) => new Promise((done, reject) => {
    const child = spawn(git, args, { cwd: workspaceRoot, env: { HOME: '/nonexistent', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', GIT_CONFIG_COUNT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; child.stdout.on('data', (chunk) => { output += chunk; }); child.once('error', reject); child.once('close', (code) => code === 0 ? done(output.trim()) : reject(new Error('sanitized git query failed')));
  });
  const prefix = [
    '--no-replace-objects',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    '-c', 'include.path=/dev/null',
  ];
  const [commit, tree, status] = await Promise.all([run([...prefix, 'rev-parse', 'HEAD^{commit}']), run([...prefix, 'rev-parse', 'HEAD^{tree}']), run([...prefix, 'status', '--porcelain=v1', '--untracked-files=all'])]);
  if (!SHA1.test(commit) || !SHA1.test(tree) || status !== '') fail('D-01 requires an exact clean Git commit and tree');
  return Object.freeze({ commit, tree });
}
function writeDirect(directory, filename, value) {
  const path = join(directory, filename); const bytes = canonical(value); const temporary = join(directory, `.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(temporary, 0o600); renameSync(temporary, path); const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 || entry.uid !== process.getuid() || (entry.mode & 0o7777) !== 0o600) fail(`D-01 ${filename} is not a direct user-owned 0600 single-link file`);
  const directoryFd = openSync(directory, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0)); try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  return Object.freeze({ path, sha256: sha256(bytes) });
}
function createOutput(directory) {
  if (existsSync(directory)) return false;
  directDirectory(dirname(directory), 'D-01 output parent'); mkdirSync(directory, { mode: 0o700 }); chmodSync(directory, 0o700); const entry = lstatSync(directory); if (!entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== process.getuid() || (entry.mode & 0o7777) !== 0o700) fail('D-01 output directory is not direct user-owned mode 0700'); return true;
}
function failure(directory, error) {
  try { if (createOutput(directory)) writeDirect(directory, 'failure.json', { schema: V2_D01_RESULT_SCHEMA, status: 'd01-not-qualified', d01Qualified: false, production: false, releaseQualified: false, reason: error instanceof Error ? error.message : String(error) }); } catch { /* preserve primary failure; never overwrite */ }
}
function expectedBinding(runtime, descriptor, releaseRootId, git) {
  return Object.freeze({ profileId: descriptor.profileId, instanceId: descriptor.instanceId, topologyId: descriptor.finalLocks.topology.id, descriptorSha256: descriptor.descriptor.sha256, manifestSha256: descriptor.manifest.sha256, releaseRootId, sourceCommit: git.commit, sourceTree: git.tree, r1csSha256: runtime.proofArtifacts.r1cs.sha256, ptauSha256: runtime.finalZkeyEvidence.powersOfTauSha256, finalZkeySha256: runtime.proofArtifacts.provingKey.sha256, verificationKeySha256: runtime.proofArtifacts.verificationKey.sha256, snarkjsToolchainSha256: runtime.finalEvidence.snarkjsToolchainSha256, contributorCount: runtime.finalEvidence.contributorCount, transcriptSha256: runtime.finalEvidence.transcriptSha256, beaconSha256: runtime.finalEvidence.beaconSha256, transcriptVerificationSha256s: runtime.finalEvidence.transcriptVerificationSha256s, reproductionSha256s: runtime.finalEvidence.reproductionSha256s });
}
export function validateV2D01PostCeremonyBinding(value, expected) {
  exact(value, ['beaconSha256', 'contributorCount', 'descriptorSha256', 'finalZkeySha256', 'instanceId', 'manifestSha256', 'profileId', 'ptauSha256', 'r1csSha256', 'releaseRootId', 'reproductionSha256s', 'schema', 'snarkjsToolchainSha256', 'sourceCommit', 'sourceTree', 'topologyId', 'transcriptSha256', 'transcriptVerificationSha256s', 'verificationKeySha256'], 'D-01 post-ceremony binding');
  if (value.schema !== V2_D01_POST_CEREMONY_BINDING_SCHEMA) fail('D-01 post-ceremony binding schema is invalid');
  for (const [key, expectedValue] of Object.entries(expected)) if (JSON.stringify(value[key]) !== JSON.stringify(expectedValue)) fail(`D-01 post-ceremony binding differs at ${key}`);
  for (const key of ['descriptorSha256', 'manifestSha256', 'r1csSha256', 'ptauSha256', 'finalZkeySha256', 'verificationKeySha256', 'snarkjsToolchainSha256', 'transcriptSha256', 'beaconSha256']) if (!HASH.test(value[key])) fail(`D-01 post-ceremony binding ${key} is malformed`);
  if (!SHA1.test(value.sourceCommit) || !SHA1.test(value.sourceTree) || !Number.isSafeInteger(value.contributorCount) || value.contributorCount < 5 || !Array.isArray(value.transcriptVerificationSha256s) || value.transcriptVerificationSha256s.length !== 2 || !Array.isArray(value.reproductionSha256s) || value.reproductionSha256s.length !== 2) fail('D-01 post-ceremony binding has invalid final-evidence summary');
  return Object.freeze(value);
}
export async function runV2D01FinalCeremonyQualification(options) {
  exact(options, ['ceremonyDirectory', 'descriptorPath', 'expectedCommit', 'expectedTree', 'finalManifestPath', 'outputDirectory', 'profileCorePath', 'releaseRootId'], 'D-01 options');
  let outputCreated = false;
  try {
    safeRuntime(); const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId); const git = await gitState(trustedGit());
    if (git.commit !== options.expectedCommit || git.tree !== options.expectedTree) fail('D-01 live source differs from expected commit/tree');
    for (const [path, label] of Object.entries({ profileCorePath: 'D-01 profile core', descriptorPath: 'D-01 descriptor', finalManifestPath: 'D-01 final manifest' })) directFile(options[path], label);
    directDirectory(options.ceremonyDirectory, 'D-01 ceremony directory');
    const profile = readJcs(options.profileCorePath, 'D-01 profile core'); const release = verifyV2FinalReleaseProfileCore(releaseRoot, profile.bytes, profile.value);
    const descriptor = await loadV2InstanceDescriptor({ descriptorPath: options.descriptorPath, profileCore: profile.value, trustedSigners: release.descriptorSigners });
    if (descriptor.manifest.filename !== options.finalManifestPath) fail('D-01 final manifest path is not descriptor-pinned');
    const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
    if (runtime.eligibility !== 'final-qualified' || runtime.claims.finalKey !== true || runtime.claims.developmentKey !== false || runtime.claims.ceremonyQualified !== true || runtime.claims.production !== false || runtime.claims.releaseQualified !== false) fail('D-01 requires final-key, ceremony-qualified, non-production, non-release runtime material');
    const inventory = readInventory(options.ceremonyDirectory); const binding = readJcs(join(options.ceremonyDirectory, 'post-ceremony-binding.json'), 'D-01 post-ceremony binding');
    if (inventory.pins.get('post-ceremony-binding.json') !== binding.sha256) fail('D-01 post-ceremony binding is not inventory-pinned');
    const expected = expectedBinding(runtime, descriptor, options.releaseRootId, git); validateV2D01PostCeremonyBinding(binding.value, expected);
    outputCreated = createOutput(options.outputDirectory); if (!outputCreated) fail('D-01 refuses a preexisting output directory');
    const result = Object.freeze({ schema: V2_D01_RESULT_SCHEMA, status: 'd01-qualified-final-key-not-production-or-release', d01Qualified: true, production: false, releaseQualified: false, releaseBootstrapSha256: release.releaseBootstrapSha256, ...expected, postCeremonyBindingSha256: binding.sha256, ceremonyInventorySha256: inventory.record.sha256 });
    const artifact = writeDirect(options.outputDirectory, 'd01-final-ceremony-qualification.json', result); return Object.freeze({ ...result, artifactPath: artifact.path, artifactSha256: artifact.sha256 });
  } catch (error) { if (!outputCreated) failure(options.outputDirectory, error); throw error; }
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) { try { process.stdout.write(`${JSON.stringify(await runV2D01FinalCeremonyQualification(parseArguments(process.argv.slice(2))), null, 2)}\n`); } catch (error) { process.stderr.write(`D-01 final ceremony qualification failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; } }
