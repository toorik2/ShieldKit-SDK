import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  SetupProfileBridgeError,
  bridgeLocalSetupToProfile,
} from './bridge.mjs';
import {
  LEGACY_PROFILE_CREATION_QUARANTINED_CODE,
  LegacyProfileCreationQuarantinedError,
} from './legacy.mjs';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));

async function absent(filename) {
  await assert.rejects(access(filename), { code: 'ENOENT' });
}

test('historical setup-to-profile bridge refuses before creating output', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-legacy-bridge-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = path.join(root, 'must-not-exist');

  await assert.rejects(
    () => bridgeLocalSetupToProfile({
      destination,
      setupMetadata: {
        sourcePath: path.join(root, 'also-missing.json'),
      },
    }),
    (error) => {
      assert.ok(error instanceof LegacyProfileCreationQuarantinedError);
      assert.ok(error instanceof SetupProfileBridgeError);
      assert.equal(error.code, LEGACY_PROFILE_CREATION_QUARANTINED_CODE);
      assert.match(error.message, /V1 legacy shielded-action-v2/);
      assert.match(error.message, /cannot create, label, convert, or migrate/);
      return true;
    },
  );
  await absent(destination);
});

test('historical bridge CLI refuses before reading its input path', async () => {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      ['bridge-cli.mjs', '--input', '/definitely/missing/legacy-input.json'],
      { cwd: here, env: {} },
    ),
    (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, '');
      assert.match(
        error.stderr,
        new RegExp(LEGACY_PROFILE_CREATION_QUARANTINED_CODE),
      );
      assert.doesNotMatch(error.stderr, /ENOENT|no such file/i);
      return true;
    },
  );
});

test('public bridge error alias remains typed', () => {
  const error = new SetupProfileBridgeError('test surface');
  assert.equal(error.name, 'LegacyProfileCreationQuarantinedError');
  assert.equal(error.code, LEGACY_PROFILE_CREATION_QUARANTINED_CODE);
});
