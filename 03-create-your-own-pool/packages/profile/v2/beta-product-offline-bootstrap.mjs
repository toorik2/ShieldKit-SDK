/**
 * Local-only custody boundary for a beta artifact release bundle.
 *
 * This accepts no URL, signature, or qualification claim. Publication of an
 * authenticated remote release is deliberately outside this module: callers
 * must first obtain a private offline bundle through their own custody path.
 */
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, copyFile, lstat, mkdir, mkdtemp, open, readdir, realpath, rename,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  installV2BetaProductArtifacts,
  loadV2BetaProductArtifactInstallation,
} from './beta-product-artifact-installation.mjs';

export const V2_BETA_OFFLINE_RELEASE_BUNDLE_SCHEMA =
  'shieldkit-v2-beta-offline-release-bundle-v1';
export const V2_BETA_OFFLINE_RELEASE_MANIFEST = 'release-manifest.json';
export const V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA =
  'shieldkit-v2-beta-offline-bootstrap-journal-v1';
export const V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY = '.v2-beta-offline-bootstrap';
export const V2_BETA_PRODUCT_RELEASE_PIN_SCHEMA =
  'shieldkit-v2-beta-product-release-pin-v1';
export const V2_BETA_PRODUCT_RELEASE_PIN_PATH = fileURLToPath(new URL(
  '../../../pins/v2-beta-product-offline-r2.pin.json',
  import.meta.url,
));

const HASH = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const SECTIONS = Object.freeze(['runtime', 'ceremony', 'native']);
const DESTINATION = 'v2-beta-product-artifacts';
const FALSE_CLAIMS = Object.freeze({ productionQualified: false, releaseQualified: false });
const PIN_STATUS = 'pinned-beta-unqualified';

export class V2BetaOfflineBootstrapError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaOfflineBootstrapError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2BetaOfflineBootstrapError(code, message, options);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
};
const absolute = (value, label) => {
  if (typeof value !== 'string' || !path.isAbsolute(value)
    || path.normalize(value) !== value || value.includes('\0')) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `${label} must be a normalized absolute path`);
  }
  return value;
};

async function privateDirectory(value, label, create = false) {
  const directory = absolute(value, label);
  if (create) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
  }
  const stat = await lstat(directory, { bigint: true }).catch((error) => fail(
    'BETA_OFFLINE_BOOTSTRAP_UNAVAILABLE', `${label} is unavailable`, { cause: error },
  ));
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777n) !== 0o700n
    || (typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid()))
    || await realpath(directory) !== directory) {
    fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `${label} must be a private canonical 0700 directory`);
  }
  return directory;
}

function safeRelative(value, label) {
  if (typeof value !== 'string' || value.length === 0 || path.isAbsolute(value)
    || value.includes('\\') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `${label} is not a safe relative path`);
  }
  return value;
}

async function readPrivateFile(filename, label, mode = 0o600) {
  const stat = await lstat(filename, { bigint: true }).catch((error) => fail(
    'BETA_OFFLINE_BOOTSTRAP_UNAVAILABLE', `${label} is unavailable`, { cause: error },
  ));
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
    || (stat.mode & 0o777n) !== BigInt(mode) || await realpath(filename) !== filename) {
    fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `${label} must be a private canonical ${mode.toString(8)} single-link file`);
  }
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const named = await lstat(filename, { bigint: true });
    if (before.dev !== stat.dev || before.ino !== stat.ino || after.dev !== stat.dev
      || after.ino !== stat.ino || named.dev !== stat.dev || named.ino !== stat.ino) {
      fail('BETA_OFFLINE_BOOTSTRAP_RACE', `${label} changed while read`);
    }
    return Object.freeze({ bytes, mode: Number(stat.mode & 0o777n) });
  } finally { await handle?.close().catch(() => undefined); }
}

async function writeCanonical(filename, value) {
  const bytes = Buffer.from(canonicalizeJcs(value), 'utf8');
  const temporary = path.join(path.dirname(filename), `.${path.basename(filename)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await rename(temporary, filename);
    const parent = await open(path.dirname(filename), fsConstants.O_RDONLY);
    try { await parent.sync(); } finally { await parent.close(); }
  } finally {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function syncRegularFile(filename, label) {
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `${label} is not a regular file`);
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

async function readTrackedPublicFile(filename, label) {
  const stat = await lstat(filename, { bigint: true }).catch((error) => fail(
    'BETA_OFFLINE_BOOTSTRAP_UNAVAILABLE', `${label} is unavailable`, { cause: error },
  ));
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
    || (stat.mode & 0o022n) !== 0n || await realpath(filename) !== filename) {
    fail(
      'BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH',
      `${label} must be a canonical single-link file that is not group/world writable`,
    );
  }
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const named = await lstat(filename, { bigint: true });
    if (before.dev !== stat.dev || before.ino !== stat.ino || after.dev !== stat.dev
      || after.ino !== stat.ino || named.dev !== stat.dev || named.ino !== stat.ino
      || after.size !== stat.size || named.size !== stat.size) {
      fail('BETA_OFFLINE_BOOTSTRAP_RACE', `${label} changed while read`);
    }
    return bytes;
  } finally { await handle?.close().catch(() => undefined); }
}

function validateReleasePin(value) {
  exact(
    value,
    ['bundleSchema', 'claims', 'releaseId', 'releaseManifestSha256', 'schema', 'status'],
    'tracked beta release pin',
  );
  if (value.schema !== V2_BETA_PRODUCT_RELEASE_PIN_SCHEMA
    || value.status !== PIN_STATUS
    || value.bundleSchema !== V2_BETA_OFFLINE_RELEASE_BUNDLE_SCHEMA
    || canonicalizeJcs(value.claims) !== canonicalizeJcs(FALSE_CLAIMS)
    || typeof value.releaseId !== 'string' || !RELEASE_ID.test(value.releaseId)
    || typeof value.releaseManifestSha256 !== 'string'
    || !HASH.test(value.releaseManifestSha256)) {
    fail('BETA_OFFLINE_BOOTSTRAP_PIN_INVALID', 'tracked beta release pin is invalid');
  }
  return Object.freeze(JSON.parse(canonicalizeJcs(value)));
}

function parseReleasePinBytes(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
    if (!bytes.equals(Buffer.from(`${canonicalizeJcs(value)}\n`, 'utf8'))) {
      fail('BETA_OFFLINE_BOOTSTRAP_PIN_INVALID', `${label} must be exact JCS plus one final newline`);
    }
  } catch (error) {
    if (error instanceof V2BetaOfflineBootstrapError) throw error;
    fail('BETA_OFFLINE_BOOTSTRAP_PIN_INVALID', `${label} is invalid JSON`, { cause: error });
  }
  return validateReleasePin(value);
}

export async function loadV2BetaProductTrackedReleasePin() {
  return parseReleasePinBytes(
    await readTrackedPublicFile(V2_BETA_PRODUCT_RELEASE_PIN_PATH, 'tracked beta release pin'),
    'tracked beta release pin',
  );
}

function expectedMode(section, relative) {
  return section === 'native' && relative === 'bin/prover' ? 0o700 : 0o600;
}

function validateReleaseManifest(value) {
  exact(value, ['artifacts', 'claims', 'releaseId', 'schema', 'status'], 'offline release manifest');
  if (value.schema !== V2_BETA_OFFLINE_RELEASE_BUNDLE_SCHEMA
    || value.status !== 'offline-beta-unqualified'
    || canonicalizeJcs(value.claims) !== canonicalizeJcs(FALSE_CLAIMS)
    || typeof value.releaseId !== 'string' || !RELEASE_ID.test(value.releaseId)) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline release manifest boundary is invalid');
  }
  exact(value.artifacts, SECTIONS, 'offline release manifest artifacts');
  const seen = new Set();
  for (const section of SECTIONS) {
    if (!Array.isArray(value.artifacts[section]) || value.artifacts[section].length === 0) {
      fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `offline release ${section} allowlist is empty`);
    }
    for (const entry of value.artifacts[section]) {
      exact(entry, ['bytes', 'mode', 'path', 'sha256'], `offline release ${section} entry`);
      const relative = safeRelative(entry.path, `offline release ${section} path`);
      if (!Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || !HASH.test(entry.sha256)
        || entry.mode !== expectedMode(section, relative) || seen.has(`${section}/${relative}`)) {
        fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `offline release ${section} allowlist entry is invalid`);
      }
      seen.add(`${section}/${relative}`);
    }
  }
  if (!seen.has('native/manifest.json') || !seen.has('native/bin/prover')) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline release lacks the exact native prover payload');
  }
  return value;
}

async function collectFiles(root, prefix = '') {
  const output = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const filename = path.join(root, entry.name);
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    const stat = await lstat(filename, { bigint: true });
    if (entry.isDirectory()) {
      if (stat.isSymbolicLink() || await realpath(filename) !== filename) {
        fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `bundle directory ${relative} is unsafe`);
      }
      output.push(...await collectFiles(filename, relative));
    } else if (entry.isFile()) {
      if (stat.isSymbolicLink() || stat.nlink !== 1n || await realpath(filename) !== filename) {
        fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `bundle file ${relative} is unsafe`);
      }
      output.push(relative);
    } else fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', `bundle entry ${relative} is unsafe`);
  }
  return output.sort();
}

async function loadBundle(bundleDirectory, releasePin) {
  const bundle = await privateDirectory(bundleDirectory, 'offline bundle directory');
  const top = (await readdir(bundle)).sort();
  const expectedTop = [V2_BETA_OFFLINE_RELEASE_MANIFEST, ...SECTIONS].sort();
  if (top.length !== expectedTop.length || top.some((entry, index) => entry !== expectedTop[index])) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bundle has unknown top-level entries');
  }
  const manifestFile = await readPrivateFile(path.join(bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST), 'offline release manifest');
  let manifest;
  try {
    manifest = JSON.parse(manifestFile.bytes.toString('utf8'));
    if (!manifestFile.bytes.equals(Buffer.from(canonicalizeJcs(manifest), 'utf8'))) {
      fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline release manifest must use exact JCS');
    }
  } catch (error) {
    if (error instanceof V2BetaOfflineBootstrapError) throw error;
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline release manifest is invalid JSON', { cause: error });
  }
  validateReleaseManifest(manifest);
  const manifestSha256 = sha256(manifestFile.bytes);
  if (manifest.schema !== releasePin.bundleSchema
    || manifest.releaseId !== releasePin.releaseId
    || manifestSha256 !== releasePin.releaseManifestSha256) {
    fail(
      'BETA_OFFLINE_BOOTSTRAP_PIN_MISMATCH',
      'offline release manifest does not match the repository-tracked beta release pin',
    );
  }
  const entries = [];
  for (const section of SECTIONS) {
    const sectionRoot = await privateDirectory(path.join(bundle, section), `offline bundle ${section}`);
    const allowlist = manifest.artifacts[section];
    const actual = await collectFiles(sectionRoot);
    const expected = allowlist.map((entry) => entry.path).sort();
    if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) {
      fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `offline bundle ${section} has missing or extra files`);
    }
    for (const entry of allowlist) {
      const file = await readPrivateFile(path.join(sectionRoot, ...entry.path.split('/')), `offline bundle ${section}/${entry.path}`, entry.mode);
      if (file.bytes.length !== entry.bytes || sha256(file.bytes) !== entry.sha256) {
        fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `offline bundle ${section}/${entry.path} differs from its allowlist`);
      }
      entries.push(Object.freeze({ section, ...entry }));
    }
  }
  return Object.freeze({ bundle, manifest, manifestSha256, entries: Object.freeze(entries) });
}

function journalValue(bundle, stageDirectory, state, receiptSha256 = undefined) {
  return Object.freeze({
    schema: V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA,
    status: state,
    claims: FALSE_CLAIMS,
    releaseId: bundle.manifest.releaseId,
    releaseManifestSha256: bundle.manifestSha256,
    stageDirectory,
    ...(receiptSha256 === undefined ? {} : { receiptSha256 }),
  });
}

function validateJournal(value, bundle, journalRoot) {
  exact(value, ['claims', 'releaseId', 'releaseManifestSha256', 'schema', 'stageDirectory', 'status', ...(Object.hasOwn(value, 'receiptSha256') ? ['receiptSha256'] : [])], 'offline bootstrap journal');
  if (value.schema !== V2_BETA_OFFLINE_BOOTSTRAP_JOURNAL_SCHEMA
    || !['staging', 'staged', 'committed'].includes(value.status)
    || canonicalizeJcs(value.claims) !== canonicalizeJcs(FALSE_CLAIMS)
    || value.releaseId !== bundle.manifest.releaseId || value.releaseManifestSha256 !== bundle.manifestSha256
    || (value.status === 'committed') !== (typeof value.receiptSha256 === 'string')
    || (value.receiptSha256 !== undefined && !HASH.test(value.receiptSha256))) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bootstrap journal boundary is invalid');
  }
  const expectedStage = path.join(journalRoot, `staged-${bundle.manifestSha256}`);
  if (value.stageDirectory !== expectedStage) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bootstrap journal stage path differs');
  return value;
}

async function readJournal(filename, bundle, root) {
  try { await lstat(filename); } catch (error) { if (error?.code === 'ENOENT') return undefined; throw error; }
  const file = await readPrivateFile(filename, 'offline bootstrap journal');
  let value;
  try {
    value = JSON.parse(file.bytes.toString('utf8'));
    if (!file.bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bootstrap journal must use exact JCS');
  } catch (error) {
    if (error instanceof V2BetaOfflineBootstrapError) throw error;
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bootstrap journal is invalid JSON', { cause: error });
  }
  return validateJournal(value, bundle, root);
}

async function stageBundle(bundle, stageDirectory) {
  try {
    await privateDirectory(stageDirectory, 'offline bootstrap stage');
    await validateStagedBundle(bundle, stageDirectory);
    return;
  } catch (error) {
    if (!(error instanceof V2BetaOfflineBootstrapError)
      || error.code === 'BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH') throw error;
  }
  await rm(stageDirectory, { recursive: true, force: true });
  const temporary = await mkdtemp(path.join(path.dirname(stageDirectory), '.stage-'));
  await chmod(temporary, 0o700);
  try {
    for (const section of SECTIONS) await mkdir(path.join(temporary, section), { mode: 0o700 });
    for (const entry of bundle.entries) {
      const source = path.join(bundle.bundle, entry.section, ...entry.path.split('/'));
      const destination = path.join(temporary, entry.section, ...entry.path.split('/'));
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      await chmod(path.dirname(destination), 0o700);
      await copyFile(source, destination, fsConstants.COPYFILE_FICLONE);
      await chmod(destination, entry.mode);
      await syncRegularFile(destination, `staged ${entry.section}/${entry.path}`);
    }
    await validateStagedBundle(bundle, temporary);
    await syncDirectoryHierarchy(temporary);
    await rename(temporary, stageDirectory);
    const parent = await open(
      path.dirname(stageDirectory),
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    try { await parent.sync(); } finally { await parent.close(); }
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

async function validateStagedBundle(bundle, stageDirectory) {
  for (const section of SECTIONS) {
    const root = await privateDirectory(path.join(stageDirectory, section), `staged ${section}`);
    const expected = bundle.entries.filter((entry) => entry.section === section).map((entry) => entry.path).sort();
    const actual = await collectFiles(root);
    if (canonicalizeJcs(actual) !== canonicalizeJcs(expected)) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `staged ${section} has missing or extra files`);
  }
  for (const entry of bundle.entries) {
    const file = await readPrivateFile(path.join(stageDirectory, entry.section, ...entry.path.split('/')), `staged ${entry.section}/${entry.path}`, entry.mode);
    if (file.bytes.length !== entry.bytes || sha256(file.bytes) !== entry.sha256) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `staged ${entry.section}/${entry.path} differs from its allowlist`);
  }
}

async function inspectInstalledReceipt(productDataDirectory, bundle) {
  const destination = path.join(productDataDirectory, DESTINATION);
  try { await lstat(destination); } catch (error) { if (error?.code === 'ENOENT') return undefined; throw error; }
  await privateDirectory(destination, 'published artifact installation');
  const receiptFile = await readPrivateFile(path.join(destination, 'receipt.json'), 'published artifact receipt');
  let receipt;
  try {
    receipt = JSON.parse(receiptFile.bytes.toString('utf8'));
    if (!receiptFile.bytes.equals(Buffer.from(canonicalizeJcs(receipt), 'utf8'))) {
      fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'published artifact receipt must use exact JCS');
    }
  } catch (error) {
    if (error instanceof V2BetaOfflineBootstrapError) throw error;
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'published artifact receipt is invalid JSON', { cause: error });
  }
  if (!Array.isArray(receipt?.inventory) || receipt.inventory.length !== bundle.entries.length) {
    fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'published artifact receipt does not match the offline allowlist');
  }
  const byPath = new Map(receipt.inventory.map((entry) => [entry?.path, entry]));
  if (byPath.size !== receipt.inventory.length) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'published artifact receipt has duplicate paths');
  for (const entry of bundle.entries) {
    const installed = byPath.get(`${entry.section}/${entry.path}`);
    const mode = installed?.identity?.mode;
    if (installed?.bytes !== entry.bytes || installed?.sha256 !== entry.sha256
      || typeof mode !== 'string' || !/^[0-9]+$/u.test(mode)
      || (BigInt(mode) & 0o777n) !== BigInt(entry.mode)) {
      fail('BETA_OFFLINE_BOOTSTRAP_INVALID', `published artifact receipt differs at ${entry.section}/${entry.path}`);
    }
  }
  return sha256(receiptFile.bytes);
}

function productionDependencies() {
  return Object.freeze({
    install: installV2BetaProductArtifacts,
    inspect: inspectInstalledReceipt,
    load: loadV2BetaProductArtifactInstallation,
  });
}

function exactDependencies(value) {
  exact(value, ['install', 'inspect', 'load'], 'offline bootstrap test dependencies');
  if (typeof value.install !== 'function' || typeof value.inspect !== 'function' || typeof value.load !== 'function') fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'offline bootstrap dependencies must be functions');
  return Object.freeze({ ...value });
}

async function acquireLock(root) {
  const filename = path.join(root, 'install-lock.sqlite');
  try {
    const existing = await lstat(filename, { bigint: true });
    if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1n
      || (existing.mode & 0o777n) !== 0o600n || await realpath(filename) !== filename) {
      fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', 'offline bootstrap lock database is unsafe');
    }
  } catch (error) {
    if (error instanceof V2BetaOfflineBootstrapError) throw error;
    if (error?.code !== 'ENOENT') throw error;
  }
  let database;
  try {
    database = new DatabaseSync(filename);
    await chmod(filename, 0o600);
    database.exec(
      'PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; '
      + 'PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=0; '
      + 'CREATE TABLE IF NOT EXISTS lease (singleton INTEGER PRIMARY KEY CHECK (singleton = 1)); '
      + 'BEGIN EXCLUSIVE;',
    );
    const stat = await lstat(filename, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
      || (stat.mode & 0o777n) !== 0o600n || await realpath(filename) !== filename) {
      fail('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH', 'offline bootstrap lock database is unsafe');
    }
    return Object.freeze({ database, filename });
  } catch (error) {
    try { database?.close(); } catch {}
    if (/database is (?:locked|busy)/iu.test(String(error?.message ?? ''))) {
      fail('BETA_OFFLINE_BOOTSTRAP_BUSY', 'another live offline bootstrap owns the installation lock');
    }
    throw error;
  }
}

async function execute(value, dependencies, releasePin) {
  exact(value, ['bundleDirectory', 'productDataDirectory'], 'offline bootstrap options');
  const product = await privateDirectory(value.productDataDirectory, 'productDataDirectory');
  const pin = validateReleasePin(releasePin);
  const bundle = await loadBundle(value.bundleDirectory, pin);
  const root = await privateDirectory(path.join(product, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY), 'offline bootstrap directory', true);
  const lock = await acquireLock(root);
  try {
    const journalFile = path.join(root, 'journal.json');
    let journal = await readJournal(journalFile, bundle, root);
    const stageDirectory = path.join(root, `staged-${bundle.manifestSha256}`);
    if (journal?.status === 'committed') {
      const published = await dependencies.inspect(product, bundle);
      if (published !== journal.receiptSha256) {
        fail(
          'BETA_OFFLINE_BOOTSTRAP_INVALID',
          'committed artifact installation differs from its pinned journal receipt',
        );
      }
      await dependencies.load({ productDataDirectory: product });
      return Object.freeze({ status: 'already-installed-beta-unqualified', claims: FALSE_CLAIMS, releaseId: bundle.manifest.releaseId, releaseManifestSha256: bundle.manifestSha256, receiptSha256: journal.receiptSha256 });
    }
    if (journal === undefined) {
      journal = journalValue(bundle, stageDirectory, 'staging');
      await writeCanonical(journalFile, journal);
    }
    await stageBundle(bundle, stageDirectory);
    if (journal.status !== 'staged') {
      journal = journalValue(bundle, stageDirectory, 'staged');
      await writeCanonical(journalFile, journal);
    }
    const recovered = await dependencies.inspect(product, bundle);
    if (recovered !== undefined) {
      await dependencies.load({ productDataDirectory: product });
      journal = journalValue(bundle, stageDirectory, 'committed', recovered);
      await writeCanonical(journalFile, journal);
      return Object.freeze({ status: 'already-installed-beta-unqualified', claims: FALSE_CLAIMS, releaseId: bundle.manifest.releaseId, releaseManifestSha256: bundle.manifestSha256, receiptSha256: recovered });
    }
    const installed = await dependencies.install({
      productDataDirectory: product,
      sourceRuntimeDirectory: path.join(stageDirectory, 'runtime'),
      ceremonyDirectory: path.join(stageDirectory, 'ceremony'),
      nativeProverInstallationDirectory: path.join(stageDirectory, 'native'),
    });
    const published = await dependencies.inspect(product, bundle);
    await dependencies.load({ productDataDirectory: product });
    if (!HASH.test(installed?.receiptSha256) || published !== installed.receiptSha256) fail('BETA_OFFLINE_BOOTSTRAP_INVALID', 'artifact installer receipt differs from published receipt');
    journal = journalValue(bundle, stageDirectory, 'committed', published);
    await writeCanonical(journalFile, journal);
    return Object.freeze({ status: 'installed-beta-unqualified', claims: FALSE_CLAIMS, releaseId: bundle.manifest.releaseId, releaseManifestSha256: bundle.manifestSha256, receiptSha256: published });
  } finally {
    try { lock.database.exec('ROLLBACK'); } catch {}
    try { lock.database.close(); } catch {}
  }
}

export async function installV2BetaProductOfflineBundle(value) {
  return execute(value, productionDependencies(), await loadV2BetaProductTrackedReleasePin());
}

/** Isolated unit-test seam only; production always invokes the final installer above. */
export async function installV2BetaProductOfflineBundleForTest(value, dependencies, releasePin) {
  return execute(value, exactDependencies(dependencies), releasePin);
}
