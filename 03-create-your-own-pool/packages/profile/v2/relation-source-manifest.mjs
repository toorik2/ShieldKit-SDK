import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs } from './profile-core.mjs';

export const V2_RELATION_SOURCE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-relation-source-manifest-v2';
export const V2_RELATION_ENTRYPOINT =
  '03-create-your-own-pool/circuits/v2-direct/main-chipnet.circom';

const HASH = /^[0-9a-f]{64}$/;
const PORTABLE_COMPONENT = /^[A-Za-z0-9@+_-][A-Za-z0-9._@+-]*$/;
const COMPILER = Object.freeze({
  npmPackage: 'circom2@0.2.23',
  circom: '2.2.3',
  optimization: 'O1',
  sanityCheck: 2,
});

export class RelationSourceManifestError extends Error {
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'RelationSourceManifestError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new RelationSourceManifestError(code, message, cause);
};
const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const compareCodepoints = (left, right) =>
  (left < right ? -1 : (left > right ? 1 : 0));

function plainObject(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('RELATION_MANIFEST_INVALID', `${label} must be a plain object`);
  }
}

function exactKeys(value, label, keys) {
  plainObject(value, label);
  const actual = Object.keys(value).sort(compareCodepoints);
  const expected = [...keys].sort(compareCodepoints);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'RELATION_MANIFEST_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
}

function portablePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(value)
    || value.includes('\\')
  ) {
    fail(
      'RELATION_MANIFEST_INVALID',
      `${label} must be a portable repository-relative path`,
    );
  }
  const components = value.split('/');
  if (
    components.some((component) =>
      component.length === 0
      || component === '.'
      || component === '..'
      || !PORTABLE_COMPONENT.test(component))
  ) {
    fail(
      'RELATION_MANIFEST_INVALID',
      `${label} must be a portable repository-relative path`,
    );
  }
  return value;
}

function sortedUnique(values, label) {
  let previous;
  for (const value of values) {
    if (previous !== undefined && compareCodepoints(previous, value) >= 0) {
      fail(
        'RELATION_MANIFEST_INVALID',
        `${label} must be codepoint-sorted and unique`,
      );
    }
    previous = value;
  }
}

async function canonicalRepositoryRoot(repositoryRoot) {
  if (
    typeof repositoryRoot !== 'string'
    || !path.isAbsolute(repositoryRoot)
  ) {
    fail(
      'RELATION_ROOT_INVALID',
      'repositoryRoot must be an absolute path',
    );
  }
  const resolved = await realpath(repositoryRoot).catch((error) =>
    fail('RELATION_ROOT_INVALID', 'repositoryRoot cannot be resolved', error));
  const metadata = await lstat(repositoryRoot, { bigint: true }).catch(
    (error) =>
      fail('RELATION_ROOT_INVALID', 'repositoryRoot cannot be inspected', error),
  );
  if (
    resolved !== repositoryRoot
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
  ) {
    fail(
      'RELATION_ROOT_INVALID',
      'repositoryRoot must be a canonical non-symlink directory',
    );
  }
  return resolved;
}

function relativePortable(repositoryRoot, filename) {
  const relative = path.relative(repositoryRoot, filename);
  if (
    relative.length === 0
    || relative.startsWith(`..${path.sep}`)
    || relative === '..'
    || path.isAbsolute(relative)
  ) {
    fail(
      'RELATION_INCLUDE_OUTSIDE_PINNED_ROOTS',
      'relation source escapes the repository',
    );
  }
  return portablePath(
    relative.split(path.sep).join('/'),
    'relation source path',
  );
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  );
}

async function stableSource(repositoryRoot, filename) {
  const requested = path.resolve(filename);
  const portable = relativePortable(repositoryRoot, requested);
  const beforePath = await lstat(requested, { bigint: true }).catch((error) =>
    fail(
      'RELATION_SOURCE_INVALID',
      `relation source cannot be inspected: ${portable}`,
      error,
    ));
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n
  ) {
    fail(
      'RELATION_SOURCE_INVALID',
      `relation source must be a unique regular non-symlink file: ${portable}`,
    );
  }
  const flags = fsConstants.O_RDONLY
    | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(requested, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      fail(
        'RELATION_SOURCE_INVALID',
        `relation source identity is unsafe: ${portable}`,
      );
    }
    const data = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(requested, { bigint: true });
    if (
      !sameIdentity(beforePath, before)
      || !sameIdentity(before, after)
      || !sameIdentity(after, afterPath)
      || BigInt(data.byteLength) !== after.size
    ) {
      fail(
        'RELATION_SOURCE_CHANGED',
        `relation source changed while read: ${portable}`,
      );
    }
    return Object.freeze({
      bytes: data.byteLength,
      data,
      path: portable,
      sha256: sha256(data),
    });
  } finally {
    await handle?.close();
  }
}

function allowedSourceRoots(repositoryRoot) {
  return Object.freeze([
    path.join(
      repositoryRoot,
      '03-create-your-own-pool/circuits/v2-direct',
    ),
    path.join(repositoryRoot, 'node_modules/circomlib/circuits'),
  ]);
}

function assertAllowedSource(filename, roots) {
  if (!roots.some((root) => (
    filename === root || filename.startsWith(`${root}${path.sep}`)
  ))) {
    fail(
      'RELATION_INCLUDE_OUTSIDE_PINNED_ROOTS',
      `Circom include escapes pinned source roots: ${filename}`,
    );
  }
}

function sourceIncludes(source, filename, repositoryRoot, roots) {
  const includes = [];
  const expression = /^\s*include\s+"([^"]+)"\s*;/gm;
  for (
    let match = expression.exec(source);
    match !== null;
    match = expression.exec(source)
  ) {
    const resolved = path.resolve(path.dirname(filename), match[1]);
    assertAllowedSource(resolved, roots);
    includes.push(relativePortable(repositoryRoot, resolved));
  }
  includes.sort(compareCodepoints);
  sortedUnique(includes, `includes for ${relativePortable(
    repositoryRoot,
    filename,
  )}`);
  return Object.freeze(includes);
}

/**
 * Collect the exact, transitively reachable Circom relation source graph.
 */
export async function collectV2RelationSourceManifest({
  repositoryRoot,
} = {}) {
  const root = await canonicalRepositoryRoot(repositoryRoot);
  const sourceRoots = allowedSourceRoots(root);
  for (const sourceRoot of sourceRoots) {
    const resolved = await realpath(sourceRoot).catch((error) =>
      fail(
        'RELATION_ROOT_INVALID',
        `pinned source root cannot be resolved: ${sourceRoot}`,
        error,
      ));
    if (resolved !== sourceRoot) {
      fail(
        'RELATION_ROOT_INVALID',
        `pinned source root must not use symlink traversal: ${sourceRoot}`,
      );
    }
  }
  const pending = [path.join(root, ...V2_RELATION_ENTRYPOINT.split('/'))];
  const seen = new Set();
  const sources = [];
  while (pending.length > 0) {
    const current = path.resolve(pending.pop());
    if (seen.has(current)) continue;
    assertAllowedSource(current, sourceRoots);
    const evidence = await stableSource(root, current);
    let source;
    try {
      source = new TextDecoder('utf-8', { fatal: true }).decode(evidence.data);
    } catch {
      fail(
        'RELATION_SOURCE_INVALID',
        `relation source is not UTF-8: ${evidence.path}`,
      );
    }
    const includes = sourceIncludes(
      source,
      current,
      root,
      sourceRoots,
    );
    seen.add(current);
    sources.push(Object.freeze({
      bytes: evidence.bytes,
      includes,
      path: evidence.path,
      sha256: evidence.sha256,
    }));
    for (const include of includes) {
      pending.push(path.join(root, ...include.split('/')));
    }
  }
  sources.sort((left, right) => compareCodepoints(left.path, right.path));
  return Object.freeze({
    schema: V2_RELATION_SOURCE_MANIFEST_SCHEMA,
    entrypoint: V2_RELATION_ENTRYPOINT,
    compiler: COMPILER,
    sources: Object.freeze(sources),
  });
}

function validateManifest(value) {
  exactKeys(value, 'relation source manifest', [
    'compiler',
    'entrypoint',
    'schema',
    'sources',
  ]);
  if (
    value.schema !== V2_RELATION_SOURCE_MANIFEST_SCHEMA
    || value.entrypoint !== V2_RELATION_ENTRYPOINT
  ) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest identity is invalid',
    );
  }
  exactKeys(value.compiler, 'relation source compiler', [
    'circom',
    'npmPackage',
    'optimization',
    'sanityCheck',
  ]);
  if (canonicalizeJcs(value.compiler) !== canonicalizeJcs(COMPILER)) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source compiler identity is invalid',
    );
  }
  if (!Array.isArray(value.sources) || value.sources.length === 0) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest must contain sources',
    );
  }
  const sourcePaths = [];
  const parsedSources = value.sources.map((entry, index) => {
    const label = `relation source manifest.sources[${index}]`;
    exactKeys(entry, label, ['bytes', 'includes', 'path', 'sha256']);
    const sourcePath = portablePath(entry.path, `${label}.path`);
    if (
      !Number.isSafeInteger(entry.bytes)
      || entry.bytes <= 0
      || typeof entry.sha256 !== 'string'
      || !HASH.test(entry.sha256)
      || !Array.isArray(entry.includes)
    ) {
      fail('RELATION_MANIFEST_INVALID', `${label} is invalid`);
    }
    const includes = entry.includes.map((include, includeIndex) =>
      portablePath(include, `${label}.includes[${includeIndex}]`));
    sortedUnique(includes, `${label}.includes`);
    sourcePaths.push(sourcePath);
    return Object.freeze({
      bytes: entry.bytes,
      includes: Object.freeze(includes),
      path: sourcePath,
      sha256: entry.sha256,
    });
  });
  sortedUnique(sourcePaths, 'relation source paths');
  const sourceSet = new Set(sourcePaths);
  if (!sourceSet.has(V2_RELATION_ENTRYPOINT)) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest omits its entrypoint',
    );
  }
  for (const source of parsedSources) {
    for (const include of source.includes) {
      if (!sourceSet.has(include)) {
        fail(
          'RELATION_MANIFEST_INVALID',
          `relation source manifest omits include target: ${include}`,
        );
      }
    }
  }
  const reachable = new Set();
  const pending = [V2_RELATION_ENTRYPOINT];
  const byPath = new Map(parsedSources.map((source) => [source.path, source]));
  while (pending.length > 0) {
    const current = pending.pop();
    if (reachable.has(current)) continue;
    reachable.add(current);
    pending.push(...byPath.get(current).includes);
  }
  if (reachable.size !== parsedSources.length) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest contains unreachable files',
    );
  }
  return Object.freeze({
    schema: value.schema,
    entrypoint: value.entrypoint,
    compiler: COMPILER,
    sources: Object.freeze(parsedSources),
  });
}

export function parseV2RelationSourceManifest(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest must be UTF-8 bytes',
    );
  }
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch (error) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest is not JSON',
      error,
    );
  }
  const parsed = validateManifest(value);
  if (!Buffer.from(bytes).equals(canonicalBytes(parsed))) {
    fail(
      'RELATION_MANIFEST_INVALID',
      'relation source manifest must use exact RFC8785/JCS bytes',
    );
  }
  return parsed;
}

export function canonicalV2RelationSourceManifest(value) {
  const bytes = canonicalBytes(value);
  const parsed = parseV2RelationSourceManifest(bytes);
  return Object.freeze({
    bytes,
    sha256: sha256(bytes),
    value: parsed,
  });
}

export async function verifyV2RelationSourceManifest(
  value,
  { repositoryRoot } = {},
) {
  const parsed = validateManifest(value);
  const measured = await collectV2RelationSourceManifest({ repositoryRoot });
  if (canonicalizeJcs(parsed) !== canonicalizeJcs(measured)) {
    fail(
      'RELATION_SOURCE_DRIFT',
      'relation sources differ from their manifest',
    );
  }
  return measured;
}
