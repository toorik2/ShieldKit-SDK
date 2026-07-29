import assert from 'node:assert/strict';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { init, ProfileInitError } from '../init.mjs';
import {
  LEGACY_PROFILE_CREATION_QUARANTINED_CODE,
  LegacyProfileCreationQuarantinedError,
} from '../legacy.mjs';

test('generic ceremony init is quarantined before setup or bundle publication', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-legacy-init-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const setup = path.join(root, 'setup-must-not-exist');
  const bundle = path.join(root, 'bundle-must-not-exist');

  await assert.rejects(
    () => init({
      mode: 'local-contribution-simulation',
      setup: { destination: setup },
      bundle: { destination: bundle },
    }),
    (error) => {
      assert.ok(error instanceof LegacyProfileCreationQuarantinedError);
      assert.ok(error instanceof ProfileInitError);
      assert.equal(error.code, LEGACY_PROFILE_CREATION_QUARANTINED_CODE);
      assert.match(error.message, /V1 legacy shielded-action-v2/);
      return true;
    },
  );
  await assert.rejects(access(setup), { code: 'ENOENT' });
  await assert.rejects(access(bundle), { code: 'ENOENT' });
});
