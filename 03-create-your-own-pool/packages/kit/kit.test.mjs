import assert from 'node:assert/strict';
import test from 'node:test';
import { createKit, KitError, assertBroadcastAllowed } from './kit.mjs';
import { AppKitNetworkError } from './network.mjs';
import { loadVerifierProfileBundle } from '../profile/load.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// packages/kit → 03-create-your-own-pool → monorepo
const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const BUNDLE = path.join(monorepoRoot, '.cache/profile-build-live/profile-bundle');

async function requireLiveCoords() {
  try {
    const loaded = await loadVerifierProfileBundle(BUNDLE);
    return {
      bundleDirectory: BUNDLE,
      expectedProfile: {
        network: 'chipnet',
        profileId: loaded.profileId,
        instanceId: loaded.instanceId,
      },
    };
  } catch (error) {
    throw new Error(
      `PREREQUISITE_MISSING: authenticated local profile bundle required at ${BUNDLE}`,
      { cause: error },
    );
  }
}

test('createKit requires bundle and profile', async () => {
  await assert.rejects(() => createKit({ network: 'chipnet' }), KitError);
});

test('network mismatch fails before profile load', async () => {
  await assert.rejects(
    () => createKit({
      network: 'mainnet',
      bundleDirectory: BUNDLE,
      expectedProfile: {
        network: 'chipnet',
        profileId: 'sha256:' + '11'.repeat(32),
        instanceId: 'sha256:' + '22'.repeat(32),
      },
    }),
    (e) => e instanceof KitError && e.code === 'NETWORK_MISMATCH',
  );
});

test('createKit chipnet with live bundle', async () => {
  const coords = await requireLiveCoords();
  const kit = await createKit({ network: 'chipnet', ...coords });
  assert.equal(kit.network.name, 'chipnet');
  assert.equal(kit.profile.setupMode, 'development-only');
  kit.assertCanBroadcast();
  assert.match(kit.explorerTxUrl('11'.repeat(32)), /chipnet/);
});

test('broadcastRaw invokes callback after gate', async () => {
  const coords = await requireLiveCoords();
  let seen = null;
  const kit = await createKit({
    network: 'chipnet',
    ...coords,
    broadcast: async (hex) => {
      seen = hex;
      return 'ok';
    },
  });
  assert.equal(await kit.broadcastRaw('deadbeef'), 'ok');
  assert.equal(seen, 'deadbeef');
});

test('mainnet gates pure functions (no mainnet bundle required)', () => {
  assert.throws(
    () => assertBroadcastAllowed({ network: 'mainnet' }),
    (e) => e.code === 'MAINNET_ACK_REQUIRED',
  );
  assert.throws(
    () => assertBroadcastAllowed({
      network: 'mainnet',
      mainnetAcknowledged: true,
      setupMode: 'development-only',
    }),
    (e) => e.code === 'UNQUALIFIED_PROFILE_ON_MAINNET',
  );
});
