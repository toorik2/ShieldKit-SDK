import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadInstance,
  instanceToKitConfig,
  CHIPNET_PLAYGROUND_ID,
  InstanceError,
  playgroundInstancePath,
} from './instance.mjs';

// packages/profile → create-your-own-pool → monorepo
const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = monorepoRoot;

test('playground instance.json loads coordinates without bundle', async () => {
  const instance = await loadInstance(CHIPNET_PLAYGROUND_ID, { loadBundle: false });
  assert.equal(instance.network, 'chipnet');
  assert.equal(instance.role, 'playground');
  assert.match(instance.profileId, /^sha256:[0-9a-f]{64}$/);
  assert.match(instance.instanceId, /^sha256:[0-9a-f]{64}$/);
  assert.ok(instance.warnings.some((w) => /playground/i.test(w) || /Work In Progress/i.test(w)));
  assert.equal(instance.expectedProfile.profileId, instance.profileId);
});

test('loadInstance playground alias', async () => {
  const a = await loadInstance('playground', { loadBundle: false });
  const b = await loadInstance(CHIPNET_PLAYGROUND_ID, { loadBundle: false });
  assert.equal(a.profileId, b.profileId);
  assert.equal(a.instanceId, b.instanceId);
});

test('loadInstance path to instance.json', async () => {
  const instance = await loadInstance(playgroundInstancePath(), { loadBundle: false });
  assert.equal(instance.id, 'chipnet-playground');
});

test('missing bundle fails closed for playground with clear code', async () => {
  // Force miss by using nonexistent override
  await assert.rejects(
    () => loadInstance('chipnet-playground', {
      bundleDirectory: path.join(root, 'does-not-exist-bundle'),
    }),
    (e) => e instanceof InstanceError && (e.code === 'BUNDLE_AUTH_FAILED' || e.code === 'PLAYGROUND_BUNDLE_MISSING'),
  );
});

test('instanceToKitConfig requires loaded bundle', () => {
  assert.throws(
    () => instanceToKitConfig({ network: 'chipnet' }),
    (e) => e instanceof InstanceError && e.code === 'INSTANCE_INCOMPLETE',
  );
});

test('full playground load when local lab bundle present', async (t) => {
  const lab = path.join(root, '.cache/profile-build-live/profile-bundle');
  try {
    await import('node:fs/promises').then((fs) => fs.access(path.join(lab, 'manifest.json')));
  } catch {
    t.skip('lab profile bundle not present');
    return;
  }
  const instance = await loadInstance('chipnet-playground', { bundleDirectory: lab });
  assert.equal(instance.bundleDirectory, lab);
  assert.ok(instance.loaded);
  const cfg = instanceToKitConfig(instance);
  assert.equal(cfg.network, 'chipnet');
  assert.equal(cfg.expectedProfile.instanceId, instance.instanceId);
});
