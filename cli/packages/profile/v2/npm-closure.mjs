import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs } from './profile-core.mjs';

export const NPM_BUILD_CLOSURE_SCHEMA = 'shieldkit-npm-build-closure-v1';

const HASH = /^[0-9a-f]{64}$/;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;

export class NpmBuildClosureError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'NpmBuildClosureError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new NpmBuildClosureError(code, message, cause);
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalHash = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));
const compareCodepoints = (left, right) => (left < right ? -1 : (left > right ? 1 : 0));

function plainObject(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('CLOSURE_INVALID', `${label} must be an object`);
  }
  return value;
}

function exactKeys(value, label, keys) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('CLOSURE_INVALID', `${label} has an invalid property set`);
  }
}

function portableRelative(value, label) {
  if (typeof value !== 'string' || value.length === 0 || path.isAbsolute(value)) {
    fail('CLOSURE_PATH_INVALID', `${label} must be a non-empty relative path`);
  }
  const parts = value.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..' || part.includes('\\'))) {
    fail('CLOSURE_PATH_INVALID', `${label} is not a portable relative path`);
  }
  return value;
}

function packagePathParts(packagePath) {
  portableRelative(packagePath, 'package path');
  const parts = packagePath.split('/');
  const names = [];
  let index = 0;
  while (index < parts.length) {
    if (parts[index] !== 'node_modules') fail('CLOSURE_PATH_INVALID', `invalid npm package path: ${packagePath}`);
    index += 1;
    if (index >= parts.length) fail('CLOSURE_PATH_INVALID', `invalid npm package path: ${packagePath}`);
    let name = parts[index];
    if (name.startsWith('@')) {
      if (index + 1 >= parts.length) fail('CLOSURE_PATH_INVALID', `invalid npm package path: ${packagePath}`);
      name = `${name}/${parts[index + 1]}`;
      index += 2;
    } else {
      index += 1;
    }
    if (!PACKAGE_NAME.test(name)) fail('CLOSURE_PATH_INVALID', `invalid npm package name in path: ${packagePath}`);
    names.push(name);
  }
  return Object.freeze(names);
}

function normalizeRoot(root) {
  if (typeof root !== 'string' || root.length === 0) fail('CLOSURE_ROOT_INVALID', 'closure roots must be non-empty strings');
  if (root.startsWith('node_modules/')) {
    packagePathParts(root);
    return root;
  }
  if (!PACKAGE_NAME.test(root)) fail('CLOSURE_ROOT_INVALID', `invalid npm package name: ${root}`);
  return `node_modules/${root}`;
}

function npmNameForPath(packagePath) {
  const names = packagePathParts(packagePath);
  return names[names.length - 1];
}

function lockIdentity(entry, packagePath) {
  plainObject(entry, `lock entry ${packagePath}`);
  if (
    typeof entry.version !== 'string' || entry.version.length === 0
    || typeof entry.integrity !== 'string' || !entry.integrity.startsWith('sha512-')
    || typeof entry.resolved !== 'string' || !entry.resolved.startsWith('https://registry.npmjs.org/')
  ) {
    fail('CLOSURE_LOCK_INVALID', `lock entry ${packagePath} is not an immutable npm package entry`);
  }
  return Object.freeze({
    integrity: entry.integrity,
    resolved: entry.resolved,
    version: entry.version,
  });
}

function dependencyLocation(packages, from, dependency) {
  let current = from;
  for (;;) {
    const candidate = current.length === 0
      ? `node_modules/${dependency}`
      : `${current}/node_modules/${dependency}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    const parentMarker = current.lastIndexOf('/node_modules/');
    if (parentMarker === -1) {
      if (current.length === 0) return null;
      current = '';
    } else {
      current = current.slice(0, parentMarker);
    }
  }
}

function packageDependencies(entry) {
  const required = plainObject(entry.dependencies ?? {}, 'lock dependencies');
  const optional = plainObject(entry.optionalDependencies ?? {}, 'lock optionalDependencies');
  const names = new Set([...Object.keys(required), ...Object.keys(optional)]);
  for (const name of names) if (!PACKAGE_NAME.test(name)) fail('CLOSURE_LOCK_INVALID', `invalid dependency name: ${name}`);
  return [...names].sort().map((name) => Object.freeze({ name, optional: Object.hasOwn(optional, name) }));
}

function statIdentity(stat) {
  return Object.freeze({
    ctimeNs: stat.ctimeNs.toString(),
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    mode: stat.mode.toString(),
    mtimeNs: stat.mtimeNs.toString(),
    nlink: stat.nlink.toString(),
    size: stat.size.toString(),
  });
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function stableRegularFile(filename, label, { capture = false } = {}) {
  let before;
  try {
    before = await lstat(filename, { bigint: true });
  } catch (error) {
    fail('CLOSURE_FILE_MISSING', `${label} is missing`, error);
  }
  if (!before.isFile() || before.isSymbolicLink()) fail('CLOSURE_FILE_INVALID', `${label} must be a regular non-symlink file`);
  if (before.nlink !== 1n) fail('CLOSURE_HARDLINK_REJECTED', `${label} must not be hard-linked`);
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== before.dev || opened.ino !== before.ino) {
      fail('CLOSURE_IDENTITY_DRIFT', `${label} changed before it could be read`);
    }
    const hash = createHash('sha256');
    const chunk = Buffer.allocUnsafe(64 * 1024);
    const chunks = capture ? [] : null;
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, offset);
      if (bytesRead === 0) break;
      const data = chunk.subarray(0, bytesRead);
      hash.update(data);
      if (chunks !== null) chunks.push(Buffer.from(data));
      offset += bytesRead;
    }
    const after = await lstat(filename, { bigint: true });
    if (!sameIdentity(statIdentity(before), statIdentity(after))) {
      fail('CLOSURE_IDENTITY_DRIFT', `${label} changed while it was read`);
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('CLOSURE_FILE_INVALID', `${label} is too large for canonical byte accounting`);
    }
    return Object.freeze({
      bytes: Number(before.size),
      ...(chunks === null ? {} : { data: Buffer.concat(chunks) }),
      sha256: hash.digest('hex'),
    });
  } catch (error) {
    if (error instanceof NpmBuildClosureError) throw error;
    fail('CLOSURE_FILE_INVALID', `${label} cannot be read without following links`, error);
  } finally {
    await handle?.close();
  }
}

async function stableTextFile(filename, label) {
  const { data, ...evidence } = await stableRegularFile(filename, label, { capture: true });
  return Object.freeze({ data: data.toString('utf8'), evidence: Object.freeze(evidence) });
}

async function installedPackageFiles(root, packagePath) {
  const parts = packagePath.split('/');
  const directory = path.join(root, ...parts);
  let directoryStat;
  try {
    directoryStat = await lstat(directory, { bigint: true });
  } catch (error) {
    fail('CLOSURE_PACKAGE_MISSING', `installed package is missing: ${packagePath}`, error);
  }
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) fail('CLOSURE_PACKAGE_INVALID', `installed package must be a directory without symlinks: ${packagePath}`);
  const canonical = await realpath(directory).catch((error) => fail('CLOSURE_PACKAGE_INVALID', `installed package cannot be resolved: ${packagePath}`, error));
  if (canonical !== directory) fail('CLOSURE_PACKAGE_INVALID', `installed package resolves through a symlink: ${packagePath}`);
  const files = [];
  const pending = [{ directory, relative: '' }];
  while (pending.length > 0) {
    const current = pending.pop();
    let entries;
    try {
      entries = await readdir(current.directory, { withFileTypes: true });
    } catch (error) {
      fail('CLOSURE_PACKAGE_INVALID', `cannot enumerate installed package: ${packagePath}`, error);
    }
    entries.sort((left, right) => compareCodepoints(left.name, right.name));
    for (const entry of entries) {
      if (entry.name === '.' || entry.name === '..' || entry.name.includes('/') || entry.name.includes('\\')) {
        fail('CLOSURE_PACKAGE_INVALID', `installed package has an invalid entry name: ${packagePath}`);
      }
      const relative = current.relative.length === 0 ? entry.name : `${current.relative}/${entry.name}`;
      const target = path.join(current.directory, entry.name);
      if (entry.isSymbolicLink()) fail('CLOSURE_SYMLINK_REJECTED', `installed package contains a symlink: ${packagePath}/${relative}`);
      if (entry.isDirectory()) {
        pending.push({ directory: target, relative });
      } else if (entry.isFile()) {
        const evidence = await stableRegularFile(target, `installed package file ${packagePath}/${relative}`);
        files.push(Object.freeze({ bytes: evidence.bytes, path: relative, sha256: evidence.sha256 }));
      } else {
        fail('CLOSURE_PACKAGE_INVALID', `installed package contains a non-regular entry: ${packagePath}/${relative}`);
      }
    }
  }
  files.sort((left, right) => compareCodepoints(left.path, right.path));
  return Object.freeze(files);
}

async function installedPackageIdentity(root, packagePath, expected) {
  const packageJsonPath = path.join(root, ...packagePath.split('/'), 'package.json');
  const packageJson = await stableTextFile(packageJsonPath, `installed package metadata ${packagePath}`);
  let metadata;
  try {
    metadata = JSON.parse(packageJson.data);
  } catch (error) {
    fail('CLOSURE_PACKAGE_INVALID', `installed package metadata is not JSON: ${packagePath}`, error);
  }
  if (metadata?.name !== npmNameForPath(packagePath) || metadata.version !== expected.version) {
    fail('CLOSURE_PACKAGE_INVALID', `installed package metadata does not match lock identity: ${packagePath}`);
  }
  const files = await installedPackageFiles(root, packagePath);
  return Object.freeze({
    files,
    sha256: canonicalHash(files),
  });
}

function validateManifestShape(value) {
  exactKeys(value, 'npm closure', ['installedClosureSha256', 'lockClosureSha256', 'lockfile', 'packages', 'roots', 'schema']);
  if (value.schema !== NPM_BUILD_CLOSURE_SCHEMA) fail('CLOSURE_INVALID', 'unsupported npm closure schema');
  if (!Array.isArray(value.roots) || !Array.isArray(value.packages) || !HASH.test(value.lockClosureSha256) || !HASH.test(value.installedClosureSha256)) {
    fail('CLOSURE_INVALID', 'npm closure has malformed collections or hashes');
  }
  exactKeys(value.lockfile, 'npm closure lockfile', ['bytes', 'lockfileVersion', 'path', 'sha256']);
  portableRelative(value.lockfile.path, 'npm closure lockfile path');
  if (value.lockfile.lockfileVersion !== 3 || !Number.isSafeInteger(value.lockfile.bytes) || value.lockfile.bytes < 0 || !HASH.test(value.lockfile.sha256)) fail('CLOSURE_INVALID', 'npm closure lockfile evidence is invalid');
  for (const root of value.roots) packagePathParts(root);
  for (const entry of value.packages) {
    exactKeys(entry, 'npm closure package', ['installed', 'lock', 'name', 'packagePath']);
    packagePathParts(entry.packagePath);
    if (entry.name !== npmNameForPath(entry.packagePath)) fail('CLOSURE_INVALID', 'npm closure package name differs from its path');
    exactKeys(entry.lock, 'npm closure package lock identity', ['integrity', 'resolved', 'sha256', 'version']);
    exactKeys(entry.installed, 'npm closure package installed identity', ['files', 'sha256']);
    if (!HASH.test(entry.lock.sha256) || !HASH.test(entry.installed.sha256) || !Array.isArray(entry.installed.files)) fail('CLOSURE_INVALID', 'npm closure package hashes are invalid');
  }
}

/**
 * Build a portable, content-addressed npm dependency closure from a lockfile-v3
 * and the installed package trees it names. `roots` accepts package names or
 * lockfile package paths (e.g. `circom2`, `@scope/pkg`, `node_modules/pkg`).
 */
export async function collectNpmBuildClosure({
  repositoryRoot,
  lockfilePath = 'package-lock.json',
  roots,
} = {}) {
  if (typeof repositoryRoot !== 'string' || !path.isAbsolute(repositoryRoot)) fail('CLOSURE_ROOT_INVALID', 'repositoryRoot must be an absolute path');
  if (!Array.isArray(roots) || roots.length === 0) fail('CLOSURE_ROOT_INVALID', 'roots must be a non-empty array');
  const root = await realpath(repositoryRoot).catch((error) => fail('CLOSURE_ROOT_INVALID', 'repositoryRoot cannot be resolved', error));
  const rootStat = await lstat(root, { bigint: true }).catch((error) => fail('CLOSURE_ROOT_INVALID', 'repositoryRoot cannot be inspected', error));
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('CLOSURE_ROOT_INVALID', 'repositoryRoot must be a non-symlink directory');
  portableRelative(lockfilePath, 'lockfile path');
  const normalizedRoots = [...new Set(roots.map(normalizeRoot))].sort();
  const lockfile = await stableTextFile(path.join(root, ...lockfilePath.split('/')), 'npm package lockfile');
  let lock;
  try {
    lock = JSON.parse(lockfile.data);
  } catch (error) {
    fail('CLOSURE_LOCK_INVALID', 'npm package lockfile is not JSON', error);
  }
  if (lock?.lockfileVersion !== 3 || lock.packages === null || typeof lock.packages !== 'object' || Array.isArray(lock.packages)) {
    fail('CLOSURE_LOCK_INVALID', 'npm package lockfile must use lockfileVersion 3 with packages');
  }

  const discovered = new Set();
  const pending = [...normalizedRoots];
  while (pending.length > 0) {
    const packagePath = pending.pop();
    if (discovered.has(packagePath)) continue;
    const entry = lock.packages[packagePath];
    if (entry === undefined) fail('CLOSURE_PACKAGE_MISSING', `lockfile lacks required package: ${packagePath}`);
    lockIdentity(entry, packagePath);
    discovered.add(packagePath);
    for (const dependency of packageDependencies(entry)) {
      const resolved = dependencyLocation(lock.packages, packagePath, dependency.name);
      if (resolved === null) {
        if (!dependency.optional) fail('CLOSURE_DEPENDENCY_MISSING', `required dependency is absent from lockfile: ${packagePath} -> ${dependency.name}`);
      } else {
        const installedPath = path.join(root, ...resolved.split('/'));
        const installed = await lstat(installedPath, { bigint: true }).catch((error) => {
          if (error?.code === 'ENOENT') return null;
          fail('CLOSURE_PACKAGE_INVALID', `cannot inspect installed dependency: ${resolved}`, error);
        });
        if (installed === null && dependency.optional) continue;
        pending.push(resolved);
      }
    }
  }

  const packages = [];
  for (const packagePath of [...discovered].sort()) {
    const identity = lockIdentity(lock.packages[packagePath], packagePath);
    const installed = await installedPackageIdentity(root, packagePath, identity);
    packages.push(Object.freeze({
      installed,
      lock: Object.freeze({ ...identity, sha256: canonicalHash(identity) }),
      name: npmNameForPath(packagePath),
      packagePath,
    }));
  }
  const lockClosure = packages.map((entry) => Object.freeze({ lock: entry.lock, name: entry.name, packagePath: entry.packagePath }));
  const installedClosure = packages.map((entry) => Object.freeze({ installed: entry.installed, name: entry.name, packagePath: entry.packagePath }));
  return Object.freeze({
    installedClosureSha256: canonicalHash(installedClosure),
    lockClosureSha256: canonicalHash(lockClosure),
    lockfile: Object.freeze({
      bytes: lockfile.evidence.bytes,
      lockfileVersion: 3,
      path: lockfilePath,
      sha256: lockfile.evidence.sha256,
    }),
    packages: Object.freeze(packages),
    roots: Object.freeze(normalizedRoots),
    schema: NPM_BUILD_CLOSURE_SCHEMA,
  });
}

/** Recollect and compare every portable identity; rejects any post-attestation drift. */
export async function verifyNpmBuildClosure(value, { repositoryRoot } = {}) {
  validateManifestShape(value);
  const measured = await collectNpmBuildClosure({
    repositoryRoot,
    lockfilePath: value.lockfile.path,
    roots: value.roots,
  });
  if (canonicalizeJcs(measured) !== canonicalizeJcs(value)) {
    fail('CLOSURE_DRIFT', 'npm lock or installed package closure differs from its attestation');
  }
  return measured;
}
