import assert from 'node:assert/strict';
import { cp, link, mkdir, mkdtemp, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  collectNpmBuildClosure,
  NPM_BUILD_CLOSURE_SCHEMA,
  NpmBuildClosureError,
  verifyNpmBuildClosure,
} from './npm-closure.mjs';

const integrity = (name) => `sha512-${Buffer.from(name).toString('base64')}`;
const TEST_TMP_PARENT = path.resolve(import.meta.dirname, '../../../../.codex-build/npm-closure-test-tmp');

const lockEntry = (name, version, dependencies = undefined, optionalDependencies = undefined) => ({
  ...(dependencies === undefined ? {} : { dependencies }),
  ...(optionalDependencies === undefined ? {} : { optionalDependencies }),
  integrity: integrity(`${name}@${version}`),
  resolved: `https://registry.npmjs.org/${name.replace('/', '%2f')}/-/${name.replace('@', '').replace('/', '-')}-${version}.tgz`,
  version,
});

async function writePackage(root, packagePath, name, version, files = {}) {
  const directory = path.join(root, ...packagePath.split('/'));
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'package.json'), `${JSON.stringify({ name, version })}\n`);
  for (const [relative, value] of Object.entries(files)) {
    const target = path.join(directory, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, value);
  }
  return directory;
}

async function temporaryDirectory(t, label) {
  await mkdir(TEST_TMP_PARENT, { recursive: true, mode: 0o700 });
  const root = await mkdtemp(path.join(TEST_TMP_PARENT, label));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function fixture(t, { omitLockDependency = false, installOptional = true } = {}) {
  const root = await temporaryDirectory(t, 'fixture-');
  const packages = {
    '': { name: 'fixture', version: '1.0.0', lockfileVersion: 3 },
    'node_modules/a': lockEntry('a', '1.0.0', { b: '1.0.0', '@scope/c': '1.0.0' }, { optional: '1.0.0' }),
    'node_modules/@scope/c': lockEntry('@scope/c', '1.0.0'),
    'node_modules/b': lockEntry('b', '1.0.0', { d: '1.0.0' }),
    'node_modules/d': lockEntry('d', '1.0.0'),
    'node_modules/optional': lockEntry('optional', '1.0.0'),
  };
  if (omitLockDependency) delete packages['node_modules/b'];
  await writeFile(path.join(root, 'package-lock.json'), `${JSON.stringify({ lockfileVersion: 3, packages })}\n`);
  await writePackage(root, 'node_modules/a', 'a', '1.0.0', { 'index.js': 'a\n', 'lib/z.js': 'z\n' });
  await writePackage(root, 'node_modules/@scope/c', '@scope/c', '1.0.0', { 'index.js': 'c\n' });
  await writePackage(root, 'node_modules/b', 'b', '1.0.0', { 'index.js': 'b\n' });
  await writePackage(root, 'node_modules/d', 'd', '1.0.0', { 'index.js': 'd\n' });
  if (installOptional) await writePackage(root, 'node_modules/optional', 'optional', '1.0.0', { 'index.js': 'optional\n' });
  return root;
}

const rejectsCode = (code) => (error) => error instanceof NpmBuildClosureError && error.code === code;

test('collects a sorted transitive lock and installed-content closure', async (t) => {
  const root = await fixture(t);
  const closure = await collectNpmBuildClosure({ repositoryRoot: root, roots: ['a'] });
  assert.equal(closure.schema, NPM_BUILD_CLOSURE_SCHEMA);
  assert.deepEqual(closure.roots, ['node_modules/a']);
  assert.deepEqual(closure.packages.map((entry) => entry.packagePath), [
    'node_modules/@scope/c',
    'node_modules/a',
    'node_modules/b',
    'node_modules/d',
    'node_modules/optional',
  ]);
  const a = closure.packages.find((entry) => entry.name === 'a');
  assert.deepEqual(a.installed.files.map((file) => file.path), ['index.js', 'lib/z.js', 'package.json']);
  assert.match(closure.lockClosureSha256, /^[0-9a-f]{64}$/);
  assert.match(closure.installedClosureSha256, /^[0-9a-f]{64}$/);
});

test('canonical closure output is deterministic and independent of its root directory', async (t) => {
  const first = await fixture(t);
  const second = await temporaryDirectory(t, 'relocated-');
  await cp(first, second, { recursive: true });
  const left = await collectNpmBuildClosure({ repositoryRoot: first, roots: ['d', 'a', 'a'] });
  const right = await collectNpmBuildClosure({ repositoryRoot: second, roots: ['a', 'd'] });
  assert.deepEqual(left, right);
});

test('optional dependencies are omitted when not installed', async (t) => {
  const root = await fixture(t, { installOptional: false });
  const closure = await collectNpmBuildClosure({ repositoryRoot: root, roots: ['node_modules/a'] });
  assert.equal(closure.packages.some((entry) => entry.name === 'optional'), false);
});

test('verification detects installed-content tampering and missing required package files', async (t) => {
  const root = await fixture(t);
  const closure = await collectNpmBuildClosure({ repositoryRoot: root, roots: ['a'] });
  await writeFile(path.join(root, 'node_modules/a/index.js'), 'tampered\n');
  await assert.rejects(
    () => verifyNpmBuildClosure(closure, { repositoryRoot: root }),
    rejectsCode('CLOSURE_DRIFT'),
  );
  await rm(path.join(root, 'node_modules/b/package.json'));
  await assert.rejects(
    () => collectNpmBuildClosure({ repositoryRoot: root, roots: ['a'] }),
    rejectsCode('CLOSURE_FILE_MISSING'),
  );
});

test('rejects symlink and hardlink package entries', async (t) => {
  const symlinkRoot = await fixture(t);
  const symlinkFile = path.join(symlinkRoot, 'node_modules/a/index.js');
  await unlink(symlinkFile);
  await symlink('../b/index.js', symlinkFile);
  await assert.rejects(
    () => collectNpmBuildClosure({ repositoryRoot: symlinkRoot, roots: ['a'] }),
    rejectsCode('CLOSURE_SYMLINK_REJECTED'),
  );

  const hardlinkRoot = await fixture(t);
  await link(
    path.join(hardlinkRoot, 'node_modules/a/index.js'),
    path.join(hardlinkRoot, 'node_modules/a/alias.js'),
  );
  await assert.rejects(
    () => collectNpmBuildClosure({ repositoryRoot: hardlinkRoot, roots: ['a'] }),
    rejectsCode('CLOSURE_HARDLINK_REJECTED'),
  );
});

test('rejects an omitted required transitive lock entry', async (t) => {
  const root = await fixture(t, { omitLockDependency: true });
  await assert.rejects(
    () => collectNpmBuildClosure({ repositoryRoot: root, roots: ['a'] }),
    rejectsCode('CLOSURE_DEPENDENCY_MISSING'),
  );
});
