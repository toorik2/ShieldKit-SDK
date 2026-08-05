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

// packages/profile → shieldkit-groth → monorepo
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
  assert.equal(instance.id, '02-use-chipnet-demo-pool');
});

test('missing bundle fails closed for playground with clear code', async () => {
  // Force miss by using nonexistent override
  await assert.rejects(
    () => loadInstance('02-use-chipnet-demo-pool', {
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

test('full playground load when matching profile bundle present', async () => {
  // Prefer playground/local ticket10-shaped bundle (instanceId must match instance.json).
  const candidates = [
    path.join(root, '02-use-chipnet-demo-pool/bundle'),
    path.join(root, '.cache/ticket10-e2e-20260726/pool/bundle'),
  ];
  let bundleDir = null;
  for (const candidate of candidates) {
    try {
      await import('node:fs/promises').then((fs) => fs.access(path.join(candidate, 'manifest.json')));
      bundleDir = candidate;
      break;
    } catch {
      // try next
    }
  }
  assert.ok(
    bundleDir,
    'PREREQUISITE_MISSING: materialize an authenticated playground-matching profile bundle '
      + `at one of: ${candidates.map((candidate) => path.join(candidate, 'manifest.json')).join(', ')}`,
  );
  const instance = await loadInstance('02-use-chipnet-demo-pool', { bundleDirectory: bundleDir });
  assert.equal(instance.bundleDirectory, bundleDir);
  assert.ok(instance.loaded);
  const cfg = instanceToKitConfig(instance);
  assert.equal(cfg.network, 'chipnet');
  assert.equal(cfg.expectedProfile.instanceId, instance.instanceId);
  assert.equal(
    instance.instanceId,
    'sha256:cfe741f64d0e47cf995a3c22bb7070e1afcf5c8a277594124d8ea445cde4a8ea',
  );
});
