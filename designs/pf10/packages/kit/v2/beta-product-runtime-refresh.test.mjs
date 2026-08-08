import assert from 'node:assert/strict';
import test from 'node:test';

import {
  recordV2BetaRuntimeWork,
} from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  refreshV2BetaProductRuntimeForTest,
  V2BetaProductRuntimeRefreshError,
  V2_BETA_PRODUCT_RUNTIME_REFRESH_RESULT_SCHEMA,
} from './beta-product-runtime-refresh.mjs';

const H = (character) => character.repeat(64);
const profileId = H('1');
const instanceId = H('2');
const genesisTransactionId = H('3');
const descriptorSha256 = H('4');
const manifestSha256 = H('5');
const materialSha256 = H('6');

function dependencies(events, {
  initialLoad = 'unavailable', install = 'success', runtime = undefined,
} = {}) {
  const genesis = Object.freeze({
    profileId,
    instanceId,
    zeroConfEvidenceSha256: descriptorSha256,
    genesisOutpoint: Object.freeze({ txid: genesisTransactionId, vout: 0 }),
  });
  const loadedRuntime = runtime ?? Object.freeze({
    identity: Object.freeze({
      profileId,
      instanceId,
      maximumLiveNotes: '100000',
      denominationSats: '10000000',
    }),
    runtimeManifestSha256: manifestSha256,
    runtimeMaterialSha256: materialSha256,
  });
  let loadCount = 0;
  return Object.freeze({
    assertGenesis: (value) => { assert.equal(value, genesis); events.push('genesis:assert'); return value; },
    assertRuntime: (value) => { assert.equal(value, loadedRuntime); events.push('runtime:assert'); return value; },
    attestTemplate: async ({ linkedTemplate }) => { assert.equal(linkedTemplate.template, true); events.push('template:attest'); return Object.freeze({ attested: true }); },
    installRuntime: async ({ artifactInstallation, cacheRoot, specializedRuntime }) => {
      assert.equal(artifactInstallation.installation, true);
      assert.equal(cacheRoot, '/private/data/runtime-cache');
      assert.equal(specializedRuntime.specialized, true);
      events.push('runtime:install');
      if (install === 'race') throw new Error('EEXIST simulated concurrent immutable generation');
      return Object.freeze({ installed: true });
    },
    loadArtifactInstallation: async ({ productDataDirectory }) => { assert.equal(productDataDirectory, '/private/data'); events.push('artifacts'); return Object.freeze({ installation: true }); },
    loadCommittedGenesis: ({ deploymentDirectory }) => { assert.equal(deploymentDirectory, '/private/data/deployment'); events.push('genesis:load'); return genesis; },
    loadConfig: ({ dataHome } = {}) => { assert.equal(dataHome, '/private/home'); events.push('config'); return Object.freeze({ config: Object.freeze({ dataDirectory: '/private/data', deploymentDirectory: '/private/data/deployment', runtimeCacheRoot: '/private/data/runtime-cache' }) }); },
    loadRuntime: async ({ artifactInstallation, cacheRoot, instanceId: requested }) => {
      assert.equal(artifactInstallation.installation, true);
      assert.equal(cacheRoot, '/private/data/runtime-cache');
      assert.equal(requested, instanceId);
      loadCount += 1;
      events.push(`runtime:load:${loadCount}`);
      if (loadCount === 1 && initialLoad !== 'current') {
        if (initialLoad === 'unavailable') {
          throw Object.assign(new Error('no current linked runtime generation'), {
            code: 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE',
          });
        }
        throw initialLoad;
      }
      recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
      return loadedRuntime;
    },
    loadTemplate: async ({ artifactInstallation }) => { assert.equal(artifactInstallation.installation, true); events.push('template:load'); return Object.freeze({ template: true }); },
    specializeRuntime: async ({ instanceId: requested, templateCapability }) => {
      assert.equal(requested, instanceId);
      assert.equal(templateCapability.attested, true);
      events.push('runtime:specialize');
      recordV2BetaRuntimeWork({ type: 'instance-specialization' });
      return Object.freeze({ specialized: true });
    },
  });
}

test('refreshes a committed pool runtime locally with a fixed specializer-to-exact-load work trace', async () => {
  const events = [];
  const result = await refreshV2BetaProductRuntimeForTest(
    { dataHome: '/private/home' }, dependencies(events),
  );
  assert.equal(result.schema, V2_BETA_PRODUCT_RUNTIME_REFRESH_RESULT_SCHEMA);
  assert.equal(result.command, 'pool-refresh-runtime');
  assert.equal(result.status, 'linked-runtime-refreshed-beta-unqualified');
  assert.deepEqual(result.claims, {
    broadcasted: false, confirmed: false, mined: false, productionQualified: false,
  });
  assert.equal(result.profileId, profileId);
  assert.equal(result.instanceId, instanceId);
  assert.equal(result.genesisTransactionId, genesisTransactionId);
  assert.equal(result.runtimeManifestSha256, manifestSha256);
  assert.equal(result.runtimeMaterialSha256, materialSha256);
  assert.equal(result.cacheInstalled, true);
  assert.deepEqual(result.runtimeWork.events, [
    { type: 'instance-specialization' }, { type: 'linked-runtime-cache-load' },
  ]);
  assert.deepEqual(result.runtimeWork.counts, {
    'linked-runtime-cache-load': 1,
    'cold-runtime-build': 0,
    'full-runtime-verification': 0,
    'compiler-child-spawn': 0,
    'instance-specialization': 1,
  });
  assert.ok(Object.values(result.timingsMs).every((value) => typeof value === 'number' && value >= 0));
  assert.deepEqual(events, [
    'config', 'genesis:load', 'genesis:assert', 'artifacts', 'runtime:load:1', 'template:load',
    'template:attest', 'runtime:specialize', 'runtime:install', 'runtime:load:2',
    'runtime:assert',
  ]);
  assert.doesNotMatch(JSON.stringify(result), /\/private\//u);
});

test('an exact current generation is a one-load no-write idempotent hit', async () => {
  const events = [];
  const result = await refreshV2BetaProductRuntimeForTest(
    { dataHome: '/private/home' }, dependencies(events, { initialLoad: 'current' }),
  );
  assert.equal(result.cacheInstalled, false);
  assert.deepEqual(result.runtimeWork.events, [{ type: 'linked-runtime-cache-load' }]);
  assert.deepEqual(result.runtimeWork.counts, {
    'linked-runtime-cache-load': 1,
    'cold-runtime-build': 0,
    'full-runtime-verification': 0,
    'compiler-child-spawn': 0,
    'instance-specialization': 0,
  });
  assert.deepEqual(events, [
    'config', 'genesis:load', 'genesis:assert', 'artifacts',
    'runtime:load:1', 'runtime:assert',
  ]);
  assert.equal(result.timingsMs.templateLoad, 0);
  assert.equal(result.timingsMs.templateReceiptAttestation, 0);
  assert.equal(result.timingsMs.instanceSpecialization, 0);
  assert.equal(result.timingsMs.runtimeCacheInstall, 0);
});

test('an ambiguous current cache is terminal before specialization or installation', async () => {
  const events = [];
  const ambiguous = Object.assign(new Error('multiple current generations'), {
    code: 'BETA_LINKED_RUNTIME_CACHE_AMBIGUOUS',
  });
  await assert.rejects(
    () => refreshV2BetaProductRuntimeForTest(
      { dataHome: '/private/home' }, dependencies(events, { initialLoad: ambiguous }),
    ),
    (error) => error === ambiguous,
  );
  assert.deepEqual(events, [
    'config', 'genesis:load', 'genesis:assert', 'artifacts', 'runtime:load:1',
  ]);
});

test('accepts only an exact reload as the safe immutable-cache publication race recovery', async () => {
  const events = [];
  const result = await refreshV2BetaProductRuntimeForTest(
    { dataHome: '/private/home' }, dependencies(events, { install: 'race' }),
  );
  assert.equal(result.cacheInstalled, false);
  assert.deepEqual(result.runtimeWork.events, [
    { type: 'instance-specialization' }, { type: 'linked-runtime-cache-load' },
  ]);
  assert.deepEqual(events.slice(-3), ['runtime:install', 'runtime:load:2', 'runtime:assert']);
});

test('rejects a reloaded runtime whose public identity differs from committed genesis', async () => {
  const events = [];
  const wrongRuntime = Object.freeze({
    identity: Object.freeze({
      profileId,
      instanceId: H('7'),
      maximumLiveNotes: '100000',
      denominationSats: '10000000',
    }),
    runtimeManifestSha256: manifestSha256,
    runtimeMaterialSha256: materialSha256,
  });
  await assert.rejects(
    () => refreshV2BetaProductRuntimeForTest(
      { dataHome: '/private/home' }, dependencies(events, { runtime: wrongRuntime }),
    ),
    (error) => error instanceof V2BetaProductRuntimeRefreshError
      && error.code === 'BETA_RUNTIME_REFRESH_REJECTED',
  );
  assert.deepEqual(events.slice(-2), ['runtime:load:2', 'runtime:assert']);
});

test('requires only the fixed data-home input and no network capability', async () => {
  const events = [];
  await assert.rejects(
    () => refreshV2BetaProductRuntimeForTest({ dataHome: 'relative' }, dependencies(events)),
    (error) => error instanceof V2BetaProductRuntimeRefreshError
      && error.code === 'BETA_RUNTIME_REFRESH_INVALID',
  );
  await assert.rejects(
    () => refreshV2BetaProductRuntimeForTest({ dataHome: '/private/../private/home' }, dependencies(events)),
    (error) => error instanceof V2BetaProductRuntimeRefreshError
      && error.code === 'BETA_RUNTIME_REFRESH_INVALID',
  );
  await assert.rejects(
    () => refreshV2BetaProductRuntimeForTest({ dataHome: '/private/home', rpc: {} }, dependencies(events)),
    (error) => error instanceof V2BetaProductRuntimeRefreshError
      && error.code === 'BETA_RUNTIME_REFRESH_INVALID',
  );
  assert.deepEqual(events, []);
});
