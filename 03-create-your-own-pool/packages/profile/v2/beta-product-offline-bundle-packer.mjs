/** Build a local-only, hash-pinned beta release bundle from private custody. */
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, copyFile, lstat, mkdir, mkdtemp, open, readdir, realpath, rename,
  rm,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  V2_BETA_OFFLINE_RELEASE_BUNDLE_SCHEMA,
  V2_BETA_OFFLINE_RELEASE_MANIFEST,
} from './beta-product-offline-bootstrap.mjs';

const SECTIONS = Object.freeze(['runtime', 'ceremony', 'native']);
const RELEASE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const FALSE_CLAIMS = Object.freeze({ productionQualified: false, releaseQualified: false });

export class V2BetaOfflineBundlePackerError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaOfflineBundlePackerError'; this.code = code;
  }
}
const fail = (code, message, options) => { throw new V2BetaOfflineBundlePackerError(code, message, options); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('BETA_OFFLINE_PACK_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('BETA_OFFLINE_PACK_INVALID', `${label} has missing or unknown properties`);
  return value;
};
const absolute = (value, label) => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value || value.includes('\0')) fail('BETA_OFFLINE_PACK_INVALID', `${label} must be a normalized absolute path`);
  return value;
};
const expectedMode = (section, relative) => section === 'native' && relative === 'bin/prover' ? 0o700 : 0o600;

async function privateDirectory(value, label) {
  const directory = absolute(value, label);
  const stat = await lstat(directory, { bigint: true }).catch((error) => fail('BETA_OFFLINE_PACK_UNAVAILABLE', `${label} is unavailable`, { cause: error }));
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777n) !== 0o700n
    || (typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid())) || await realpath(directory) !== directory) fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `${label} must be a private canonical 0700 directory`);
  return directory;
}

async function readStable(filename, label, mode) {
  const named = await lstat(filename, { bigint: true }).catch((error) => fail('BETA_OFFLINE_PACK_UNAVAILABLE', `${label} is unavailable`, { cause: error }));
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
    || (named.mode & 0o777n) !== BigInt(mode) || await realpath(filename) !== filename) fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `${label} must be a private exact-mode single-link file`);
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true }); const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true }); const end = await lstat(filename, { bigint: true });
    if (before.dev !== named.dev || before.ino !== named.ino || after.dev !== named.dev || after.ino !== named.ino || end.dev !== named.dev || end.ino !== named.ino) fail('BETA_OFFLINE_PACK_RACE', `${label} changed while read`);
    return Object.freeze({ bytes, sha256: sha256(bytes) });
  } finally { await handle?.close().catch(() => undefined); }
}

async function files(root, prefix = '') {
  const output = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const filename = path.join(root, entry.name); const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    const stat = await lstat(filename, { bigint: true });
    if (entry.isDirectory()) {
      if (stat.isSymbolicLink() || await realpath(filename) !== filename) fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `source directory ${relative} is unsafe`);
      output.push(...await files(filename, relative));
    } else if (entry.isFile()) {
      if (stat.isSymbolicLink() || stat.nlink !== 1n || await realpath(filename) !== filename) fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `source file ${relative} is unsafe`);
      output.push(relative);
    } else fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `source entry ${relative} is unsafe`);
  }
  return output.sort();
}

async function inventory(section, directory) {
  const entries = [];
  for (const relative of await files(directory)) {
    const mode = expectedMode(section, relative);
    const file = await readStable(path.join(directory, ...relative.split('/')), `${section}/${relative}`, mode);
    entries.push(Object.freeze({ path: relative, bytes: file.bytes.length, sha256: file.sha256, mode }));
  }
  if (entries.length === 0) fail('BETA_OFFLINE_PACK_INVALID', `${section} source must not be empty`);
  return Object.freeze(entries);
}

async function writeCanonical(filename, value) {
  const bytes = Buffer.from(canonicalizeJcs(value), 'utf8'); const temporary = path.join(path.dirname(filename), `.${path.basename(filename)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await rename(temporary, filename); const parent = await open(path.dirname(filename), fsConstants.O_RDONLY); try { await parent.sync(); } finally { await parent.close(); }
  } finally { await handle?.close().catch(() => undefined); await rm(temporary, { force: true }).catch(() => undefined); }
}

async function syncRegularFile(filename, label) {
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) fail('BETA_OFFLINE_PACK_UNSAFE_PATH', `${label} is not a regular file`);
    await handle.sync();
  } finally { await handle?.close().catch(() => undefined); }
}

async function syncDirectoryHierarchy(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) await syncDirectoryHierarchy(path.join(directory, entry.name));
  }
  const handle = await open(
    directory,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
  );
  try { await handle.sync(); } finally { await handle.close(); }
}

async function copyInventory(section, source, destination, entries) {
  await mkdir(destination, { mode: 0o700 }); await chmod(destination, 0o700);
  for (const entry of entries) {
    const from = path.join(source, ...entry.path.split('/')); const to = path.join(destination, ...entry.path.split('/'));
    await mkdir(path.dirname(to), { recursive: true, mode: 0o700 }); await chmod(path.dirname(to), 0o700);
    // Re-read just before copy so a post-manifest source mutation cannot enter the bundle.
    const current = await readStable(from, `${section}/${entry.path}`, entry.mode);
    if (current.bytes.length !== entry.bytes || current.sha256 !== entry.sha256) fail('BETA_OFFLINE_PACK_RACE', `${section}/${entry.path} changed after inventory`);
    await copyFile(from, to, fsConstants.COPYFILE_FICLONE); await chmod(to, entry.mode);
    const copied = await readStable(to, `copied ${section}/${entry.path}`, entry.mode);
    if (copied.bytes.length !== entry.bytes || copied.sha256 !== entry.sha256) fail('BETA_OFFLINE_PACK_RACE', `copied ${section}/${entry.path} differs from source`);
    await syncRegularFile(to, `copied ${section}/${entry.path}`);
  }
}

export async function packV2BetaProductOfflineBundle(value) {
  exact(value, ['ceremonyDirectory', 'nativeProverInstallationDirectory', 'outputDirectory', 'releaseId', 'runtimeDirectory'], 'offline bundle pack options');
  if (typeof value.releaseId !== 'string' || !RELEASE_ID.test(value.releaseId)) fail('BETA_OFFLINE_PACK_INVALID', 'releaseId is invalid');
  const sources = Object.freeze({
    runtime: await privateDirectory(value.runtimeDirectory, 'runtimeDirectory'),
    ceremony: await privateDirectory(value.ceremonyDirectory, 'ceremonyDirectory'),
    native: await privateDirectory(value.nativeProverInstallationDirectory, 'nativeProverInstallationDirectory'),
  });
  const output = absolute(value.outputDirectory, 'outputDirectory'); const parent = await privateDirectory(path.dirname(output), 'outputDirectory parent');
  const artifacts = Object.freeze(Object.fromEntries(await Promise.all(SECTIONS.map(async (section) => [section, await inventory(section, sources[section])]))));
  if (!artifacts.native.some((entry) => entry.path === 'manifest.json') || !artifacts.native.some((entry) => entry.path === 'bin/prover')) fail('BETA_OFFLINE_PACK_INVALID', 'native source lacks manifest.json or bin/prover');
  const manifest = Object.freeze({ schema: V2_BETA_OFFLINE_RELEASE_BUNDLE_SCHEMA, status: 'offline-beta-unqualified', claims: FALSE_CLAIMS, releaseId: value.releaseId, artifacts });
  const manifestBytes = Buffer.from(canonicalizeJcs(manifest), 'utf8');
  try { await mkdir(output, { mode: 0o700 }); await chmod(output, 0o700); }
  catch (error) { if (error?.code === 'EEXIST') fail('BETA_OFFLINE_PACK_EXISTS', 'outputDirectory already exists'); throw error; }
  let stage;
  try {
    stage = await mkdtemp(path.join(parent, '.offline-release-stage-')); await chmod(stage, 0o700);
    await Promise.all(SECTIONS.map((section) => copyInventory(section, sources[section], path.join(stage, section), artifacts[section])));
    await writeCanonical(path.join(stage, V2_BETA_OFFLINE_RELEASE_MANIFEST), manifest);
    await syncDirectoryHierarchy(stage);
    for (const section of SECTIONS) await rename(path.join(stage, section), path.join(output, section));
    await rm(path.join(stage, V2_BETA_OFFLINE_RELEASE_MANIFEST), { force: false });
    await rm(stage, { recursive: true, force: false });
    await syncDirectoryHierarchy(output);
    // The tracked manifest is the commit marker: an interrupted output without
    // it can never be accepted by the bootstrap loader.
    await writeCanonical(path.join(output, V2_BETA_OFFLINE_RELEASE_MANIFEST), manifest);
    await syncDirectoryHierarchy(output);
    const parentHandle = await open(parent, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW); try { await parentHandle.sync(); } finally { await parentHandle.close(); }
    return Object.freeze({ outputDirectory: output, manifestSha256: sha256(manifestBytes), releaseId: value.releaseId, claims: FALSE_CLAIMS });
  } catch (error) {
    if (stage !== undefined) await rm(stage, { recursive: true, force: true }).catch(() => undefined);
    await rm(output, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}
