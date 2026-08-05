import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  LEGACY_PROFILE_CREATION_QUARANTINED_CODE,
  V1_LEGACY_PROTOCOL_ID,
  V1_LEGACY_PUBLIC_INPUT_ABI_ID,
  V1_LEGACY_RELATION_ID,
  isV1LegacyProfileIdentity,
} from './legacy.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);

async function expectQuarantinedScript(relativeScript, args, outputDirectory) {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      [path.join(repositoryRoot, relativeScript), ...args],
      { cwd: repositoryRoot, env: {} },
    ),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /LEGACY_PROFILE_CREATION_QUARANTINED|V1 legacy/);
      assert.doesNotMatch(error.stderr, /ENOENT|no such file|ECONNREFUSED/i);
      return true;
    },
  );
  await assert.rejects(access(outputDirectory), { code: 'ENOENT' });
}

test('legacy identity registry is exact and never aliases V2 Direct', () => {
  assert.equal(V1_LEGACY_PROTOCOL_ID, 'v1-legacy');
  assert.equal(V1_LEGACY_RELATION_ID, 'shielded-action-v2');
  assert.equal(
    V1_LEGACY_PUBLIC_INPUT_ABI_ID,
    'shielded-action-public-input-v1',
  );
  assert.equal(
    isV1LegacyProfileIdentity({
      relationId: V1_LEGACY_RELATION_ID,
      publicInputAbiId: V1_LEGACY_PUBLIC_INPUT_ABI_ID,
    }),
    true,
  );
  assert.equal(
    isV1LegacyProfileIdentity({
      relationId: 'shieldkit-pool-action-v2-direct',
      publicInputAbiId: 'shieldkit-sda2-sha256-be-u128x2',
    }),
    false,
  );
});

test('legacy create-pool and chain E2E scripts are outside the PF10 product tree', async () => {
  const { existsSync } = await import('node:fs');
  assert.equal(
    existsSync(path.join(repositoryRoot, 'shieldkit-groth/scripts/create-pool.mjs')),
    false,
  );
  assert.equal(
    existsSync(path.join(repositoryRoot, 'shieldkit-groth/scripts/chain-e2e-chipnet.mjs')),
    false,
  );
  assert.equal(
    existsSync(path.join(repositoryRoot, 'legacy-research/v1-seven-carrier/create-pool.mjs')),
    true,
  );
  assert.equal(
    existsSync(path.join(repositoryRoot, 'legacy-research/v1-seven-carrier/chain-e2e-chipnet.mjs')),
    true,
  );
});

test('primary shieldkit init refuses before reading a config file', async () => {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      [
        path.join(
          repositoryRoot,
          'shieldkit-groth/scripts/shieldkit.mjs',
        ),
        'init',
        '--config',
        '/definitely/missing/v1-init.json',
      ],
      { cwd: repositoryRoot, env: {} },
    ),
    (error) => {
      assert.equal(error.code, 64);
      assert.equal(error.stderr, '');
      const result = JSON.parse(error.stdout);
      assert.equal(
        result.error.code,
        LEGACY_PROFILE_CREATION_QUARANTINED_CODE,
      );
      assert.match(result.error.message, /V1 legacy shielded-action-v2/);
      return true;
    },
  );
});
