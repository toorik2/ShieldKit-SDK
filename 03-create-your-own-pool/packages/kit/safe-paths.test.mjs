import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertSafeReplaceDirectory } from './safe-paths.mjs';

test('recursive replacement rejects roots, home, cwd, and repository ancestors', () => {
  const repositoryRoot = process.cwd();
  for (const target of [
    path.parse(repositoryRoot).root,
    os.homedir(),
    repositoryRoot,
    path.dirname(repositoryRoot),
    '.',
  ]) {
    assert.throws(
      () => assertSafeReplaceDirectory(target, { repositoryRoot }),
      /refusing recursive replacement/,
    );
  }
});

test('recursive replacement accepts a scoped child or unrelated deep path', () => {
  const repositoryRoot = process.cwd();
  assert.equal(
    assertSafeReplaceDirectory(path.join(repositoryRoot, '.cache', 'artifact'), { repositoryRoot }),
    path.join(repositoryRoot, '.cache', 'artifact'),
  );
  assert.equal(
    assertSafeReplaceDirectory('/tmp/shieldkit/artifact', { repositoryRoot }),
    '/tmp/shieldkit/artifact',
  );
});
