import assert from 'node:assert/strict';
import {
  chmod,
  link,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  V2B01PreFreezeError,
  V2_B01_PRE_FREEZE_SCHEMA,
  parseV2B01PreFreezeArguments,
  verifyV2B01PreFreezeBundle,
} from './v2-b01-pre-freeze.mjs';

const SHA1 = 'a'.repeat(40);
const cwd = '/tmp';

test('B-01 parser accepts only the closed public create and verify surfaces', () => {
  assert.deepEqual(
    parseV2B01PreFreezeArguments([
      '--runtime-bundle', '/runtime', '--q01-pre-bundle', '/q01',
      '--expected-commit', SHA1, '--expected-tree', 'b'.repeat(40),
      '--output-dir', '/out',
    ], cwd),
    {
      mode: 'create', runtimeRoot: '/runtime', q01Root: '/q01',
      expectedCommit: SHA1, expectedTree: 'b'.repeat(40), outputDirectory: '/out',
    },
  );
  assert.deepEqual(parseV2B01PreFreezeArguments(['--verify', '/bundle'], cwd), {
    mode: 'verify', bundlePath: '/bundle',
  });
  for (const argv of [
    ['--runtime-bundle', '/a', '--runtime-bundle', '/b', '--expected-commit', SHA1, '--expected-tree', 'b'.repeat(40), '--output-dir', '/o'],
    ['--unknown', '/a', '--q01-pre-bundle', '/b', '--expected-commit', SHA1, '--expected-tree', 'b'.repeat(40), '--output-dir', '/o'],
    ['--verify', '/bundle', '--output-dir', '/out'],
    ['--verify', 'relative-bundle'],
    ['--runtime-bundle', 'relative', '--q01-pre-bundle', '/q', '--expected-commit', SHA1, '--expected-tree', 'b'.repeat(40), '--output-dir', '/o'],
  ]) assert.throws(() => parseV2B01PreFreezeArguments(argv, cwd), V2B01PreFreezeError);
});

test('public B-01 verifier rejects ambient loader controls before opening evidence', async () => {
  const previous = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = '--import=/tmp/untrusted-loader.mjs';
  try {
    await assert.rejects(
      verifyV2B01PreFreezeBundle('/does/not/exist'),
      /refuses ambient loader, preload, or dynamic-linker controls/u,
    );
  } finally {
    if (previous === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previous;
  }
});

test('public verifier rejects malformed, unsafe-mode, linked, and noncanonical freeze fixtures before any qualification claim', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'b01-freeze-test-'));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const manifest = path.join(root, 'manifest.json');
  await writeFile(manifest, '{}', { mode: 0o600 });
  await assert.rejects(
    verifyV2B01PreFreezeBundle(root),
    V2B01PreFreezeError,
  );

  await chmod(root, 0o755);
  await assert.rejects(
    verifyV2B01PreFreezeBundle(root),
    V2B01PreFreezeError,
  );
  await chmod(root, 0o700);

  const linked = `${root}-link`;
  await symlink(root, linked);
  t.after(() => rm(linked, { force: true }));
  await assert.rejects(
    verifyV2B01PreFreezeBundle(linked),
    V2B01PreFreezeError,
  );

  const hardlink = path.join(root, 'manifest-hardlink.json');
  await link(manifest, hardlink);
  await assert.rejects(
    verifyV2B01PreFreezeBundle(root),
    V2B01PreFreezeError,
  );
  assert.equal(V2_B01_PRE_FREEZE_SCHEMA, 'shieldkit-v2-direct-b01-pre-freeze-v1');
});
