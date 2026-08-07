import assert from 'node:assert/strict';
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  canonicalV2RelationSourceManifest,
  collectV2RelationSourceManifest,
  parseV2RelationSourceManifest,
  RelationSourceManifestError,
  V2_RELATION_ENTRYPOINT,
  V2_RELATION_SOURCE_MANIFEST_SCHEMA,
  verifyV2RelationSourceManifest,
} from './relation-source-manifest.mjs';

const REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../..');
const TEST_TMP_PARENT = path.join(
  REPOSITORY_ROOT,
  '.codex-build/relation-source-manifest-test-tmp',
);

const rejectsCode = (code) => (error) =>
  error instanceof RelationSourceManifestError && error.code === code;

async function temporaryDirectory(t, label) {
  await mkdir(TEST_TMP_PARENT, { recursive: true, mode: 0o700 });
  const root = await mkdtemp(path.join(TEST_TMP_PARENT, label));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function writeSource(root, relativePath, source) {
  const target = path.join(root, ...relativePath.split('/'));
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, source, 'utf8');
  return target;
}

/**
 * The collector intentionally does not compile source in this unit suite. A
 * minimal syntactically plausible graph is sufficient to exercise the pinned
 * source-root, graph, and stable-read rules.
 */
async function fixture(t, {
  mainIncludes = [
    'a.circom',
    'b.circom',
  ],
  aIncludes = [],
  bIncludes = [],
} = {}) {
  const root = await temporaryDirectory(t, 'fixture-');
  const render = (includes) => [
    'pragma circom 2.2.0;',
    ...includes.map((include) => `include "${include}";`),
    'component main = Main();',
    '',
  ].join('\n');
  await writeSource(
    root,
    V2_RELATION_ENTRYPOINT,
    render(mainIncludes),
  );
  await writeSource(
    root,
    'shieldkit-groth/circuits/v2-direct/a.circom',
    render(aIncludes),
  );
  await writeSource(
    root,
    'shieldkit-groth/circuits/v2-direct/b.circom',
    render(bIncludes),
  );
  // This directory is a required pinned root even when no test source imports
  // a circomlib relation.
  await mkdir(path.join(root, 'node_modules/circomlib/circuits'), {
    recursive: true,
  });
  return root;
}

const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

test('collects and verifies the complete real V2 relation graph with exact JCS bytes', async () => {
  const manifest = await collectV2RelationSourceManifest({
    repositoryRoot: REPOSITORY_ROOT,
  });
  assert.equal(manifest.schema, V2_RELATION_SOURCE_MANIFEST_SCHEMA);
  assert.equal(manifest.entrypoint, V2_RELATION_ENTRYPOINT);
  assert.ok(manifest.sources.length > 10);
  assert.equal(
    manifest.sources.some((source) =>
      source.path.startsWith('node_modules/circomlib/circuits/')),
    true,
  );
  assert.deepEqual(
    manifest.sources.map((source) => source.path),
    [...manifest.sources.map((source) => source.path)].sort(),
  );

  const canonical = canonicalV2RelationSourceManifest(manifest);
  assert.deepEqual(parseV2RelationSourceManifest(canonical.bytes), manifest);
  assert.deepEqual(
    await verifyV2RelationSourceManifest(manifest, {
      repositoryRoot: REPOSITORY_ROOT,
    }),
    manifest,
  );
  assert.throws(
    () => parseV2RelationSourceManifest(
      Buffer.from(JSON.stringify(manifest), 'utf8'),
    ),
    rejectsCode('RELATION_MANIFEST_INVALID'),
  );
  assert.throws(
    () => parseV2RelationSourceManifest(
      Buffer.concat([canonical.bytes, Buffer.from('\n')]),
    ),
    rejectsCode('RELATION_MANIFEST_INVALID'),
  );
});

test('collects a deterministic, codepoint-sorted reachable include graph', async (t) => {
  const root = await fixture(t, {
    mainIncludes: ['b.circom', 'a.circom'],
    aIncludes: ['../v2-direct/b.circom'],
  });
  const first = await collectV2RelationSourceManifest({ repositoryRoot: root });
  const second = await collectV2RelationSourceManifest({ repositoryRoot: root });
  assert.deepEqual(second, first);
  assert.deepEqual(first.sources.map((source) => source.path), [
    'shieldkit-groth/circuits/v2-direct/a.circom',
    'shieldkit-groth/circuits/v2-direct/b.circom',
    V2_RELATION_ENTRYPOINT,
  ]);
  assert.deepEqual(first.sources[0].includes, [
    'shieldkit-groth/circuits/v2-direct/b.circom',
  ]);
  assert.deepEqual(first.sources[2].includes, [
    'shieldkit-groth/circuits/v2-direct/a.circom',
    'shieldkit-groth/circuits/v2-direct/b.circom',
  ]);
});

test('rejects noncanonical, incomplete, and unreachable manifest graphs', async (t) => {
  const root = await fixture(t);
  const manifest = await collectV2RelationSourceManifest({ repositoryRoot: root });

  const withoutEntrypoint = structuredClone(manifest);
  withoutEntrypoint.sources = withoutEntrypoint.sources.filter(
    (source) => source.path !== V2_RELATION_ENTRYPOINT,
  );
  assert.throws(
    () => parseV2RelationSourceManifest(canonicalBytes(withoutEntrypoint)),
    rejectsCode('RELATION_MANIFEST_INVALID'),
  );

  const withoutIncludedSource = structuredClone(manifest);
  withoutIncludedSource.sources = withoutIncludedSource.sources.filter(
    (source) => !source.path.endsWith('/a.circom'),
  );
  assert.throws(
    () => parseV2RelationSourceManifest(canonicalBytes(withoutIncludedSource)),
    rejectsCode('RELATION_MANIFEST_INVALID'),
  );

  const withUnreachableSource = structuredClone(manifest);
  withUnreachableSource.sources.push({
    bytes: 1,
    includes: [],
    path: 'shieldkit-groth/circuits/v2-direct/unreachable.circom',
    sha256: '0'.repeat(64),
  });
  withUnreachableSource.sources.sort((left, right) =>
    left.path < right.path ? -1 : (left.path > right.path ? 1 : 0));
  assert.throws(
    () => parseV2RelationSourceManifest(canonicalBytes(withUnreachableSource)),
    rejectsCode('RELATION_MANIFEST_INVALID'),
  );
});

test('rejects missing and out-of-root include targets during collection', async (t) => {
  const missingRoot = await fixture(t, { mainIncludes: ['missing.circom'] });
  await assert.rejects(
    () => collectV2RelationSourceManifest({ repositoryRoot: missingRoot }),
    rejectsCode('RELATION_SOURCE_INVALID'),
  );

  const traversalRoot = await fixture(t, {
    mainIncludes: ['../../../../outside.circom'],
  });
  await writeSource(traversalRoot, 'outside.circom', 'pragma circom 2.2.0;\n');
  await assert.rejects(
    () => collectV2RelationSourceManifest({ repositoryRoot: traversalRoot }),
    rejectsCode('RELATION_INCLUDE_OUTSIDE_PINNED_ROOTS'),
  );
});

test('rejects symlinked and hardlinked relation sources', async (t) => {
  const symlinkRoot = await fixture(t);
  const symlinkTarget = path.join(
    symlinkRoot,
    'shieldkit-groth/circuits/v2-direct/a.circom',
  );
  const sourceOutsidePinnedRoot = path.join(symlinkRoot, 'outside.circom');
  await writeFile(sourceOutsidePinnedRoot, 'pragma circom 2.2.0;\n', 'utf8');
  await unlink(symlinkTarget);
  await symlink(sourceOutsidePinnedRoot, symlinkTarget);
  await assert.rejects(
    () => collectV2RelationSourceManifest({ repositoryRoot: symlinkRoot }),
    rejectsCode('RELATION_SOURCE_INVALID'),
  );

  const hardlinkRoot = await fixture(t);
  const hardlinkTarget = path.join(
    hardlinkRoot,
    'shieldkit-groth/circuits/v2-direct/a.circom',
  );
  await link(
    hardlinkTarget,
    path.join(
      hardlinkRoot,
      'shieldkit-groth/circuits/v2-direct/a-copy.circom',
    ),
  );
  await assert.rejects(
    () => collectV2RelationSourceManifest({ repositoryRoot: hardlinkRoot }),
    rejectsCode('RELATION_SOURCE_INVALID'),
  );
});

test('verification detects source-byte drift after a manifest has been collected', async (t) => {
  const root = await fixture(t);
  const manifest = await collectV2RelationSourceManifest({ repositoryRoot: root });
  const source = path.join(
    root,
    'shieldkit-groth/circuits/v2-direct/a.circom',
  );
  await writeFile(source, `${await readFile(source, 'utf8')}\n// changed\n`, 'utf8');
  await assert.rejects(
    () => verifyV2RelationSourceManifest(manifest, { repositoryRoot: root }),
    rejectsCode('RELATION_SOURCE_DRIFT'),
  );
});
