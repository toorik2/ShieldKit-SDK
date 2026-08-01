import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import path from 'node:path';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  runV2Pf10BetaRuntime,
} from '../../../scripts/v2-pf10-beta-runtime.mjs';
import {
  createV2BetaChipnetGenesisRuntimeFromResolution,
  V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
} from './genesis.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  bindV2BetaChipnetRuntimeResolution,
  deriveV2BetaChipnetProfileCore,
  deriveV2BetaChipnetSettlementPins,
  deriveV2BetaChipnetStoreRuntimeMaterialsSha256,
  installV2BetaChipnetRuntimeCache,
  loadCachedV2BetaChipnetRuntime,
  loadV2BetaChipnetRuntime,
  V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA,
  V2BetaChipnetRuntimeError,
} from './beta-chipnet-runtime.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const defaultRuntime = path.join(
  repositoryRoot,
  '.codex-build',
  'v2-beta-local-100000-r1',
  'runtime',
);
const runtimeDirectory = process.env.SHIELDKIT_V2_BETA_RUNTIME_TEST_DIR
  ? path.resolve(process.env.SHIELDKIT_V2_BETA_RUNTIME_TEST_DIR)
  : defaultRuntime;

async function requireQualificationRuntimeFixture(directory) {
  let metadata;
  try { metadata = await lstat(directory); }
  catch (error) {
    assert.fail(`BETA_RUNTIME_QUALIFICATION_FIXTURE_REQUIRED: ${directory} is unavailable; provide the exact private runtime with SHIELDKIT_V2_BETA_RUNTIME_TEST_DIR`);
  }
  assert.equal(metadata.isDirectory(), true, `BETA_RUNTIME_QUALIFICATION_FIXTURE_REQUIRED: ${directory} must be a runtime directory`);
}

async function exerciseRuntime(runtime, temporaryRoot) {
  const resolution = await loadV2BetaChipnetRuntime({
    allowedOutputRoot: runtime,
    runtimeDirectory: runtime,
    temporaryRoot,
  });
  assert.equal(resolution.schema, V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA);
  assert.equal(resolution.eligibility, 'beta-single-contributor-unqualified');
  assert.equal(resolution.claims.betaSingleContributor, true);
  assert.equal(resolution.claims.finalKey, false);
  assert.equal(resolution.identity.maximumLiveNotes, '100000');
  assert.equal(resolution.identity.denominationSats, '10000000');
  assert.equal(resolution.runtimeMaterial.schema, DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA);
  assert.equal(
    resolution.runtimeMaterial.materialSha256,
    resolution.runtimeMaterialSha256,
  );
  assert.equal(assertV2BetaChipnetRuntimeResolution(resolution), resolution);
  const profileCore = deriveV2BetaChipnetProfileCore(resolution);
  const genesisRuntime = createV2BetaChipnetGenesisRuntimeFromResolution({
    profileCore,
    runtimeResolution: resolution,
  });
  assert.equal(genesisRuntime.schema, V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA);
  assert.equal(genesisRuntime.profileId, resolution.identity.profileId);
  assert.equal(genesisRuntime.instanceId, resolution.identity.instanceId);
  assert.equal(genesisRuntime.runtimeMaterialSha256, resolution.runtimeMaterialSha256);
  assert.deepEqual(genesisRuntime.baseValues.verifierSats, Array(10).fill('1200'));
  // The public resolution contains presentation copies. Warm genesis must
  // consume only fresh private pin copies and never rebuild from this mutable
  // lookalike surface.
  resolution.settlementPins.stateHelperBytecode[0] ^= 1;
  resolution.settlementPins.stateLockingBytecode[0] ^= 1;
  const genesisAfterPublicMutation = createV2BetaChipnetGenesisRuntimeFromResolution({
    profileCore,
    runtimeResolution: resolution,
  });
  assert.equal(genesisAfterPublicMutation.finalLocksSha256, genesisRuntime.finalLocksSha256);
  assert.deepEqual(
    [...deriveV2BetaChipnetStoreRuntimeMaterialsSha256(resolution)],
    [...Buffer.from(resolution.runtimeMaterialSha256, 'hex')],
  );
  const pins = deriveV2BetaChipnetSettlementPins(resolution);
  assert.equal(pins.topologyId, DIRECT_V2_PF10_FUSED_TOPOLOGY_ID);
  assert.deepEqual(pins.verifierRoles, DIRECT_V2_PF10_FUSED_VERIFIER_ROLES);
  assert.equal(pins.verifierCarriers.length, 10);
  assert.equal(pins.bindingBaseSats, '1200');
  assert.equal(pins.stateBaseSats, '2500');

  // Returned byte copies must not mutate the branded private capability.
  pins.verifierCarriers[0].lockingBytecode[0] ^= 1;
  assert.notEqual(
    pins.verifierCarriers[0].lockingBytecode[0],
    deriveV2BetaChipnetSettlementPins(resolution)
      .verifierCarriers[0].lockingBytecode[0],
  );

  const clone = structuredClone(resolution);
  assert.throws(
    () => assertV2BetaChipnetRuntimeResolution(clone),
    V2BetaChipnetRuntimeError,
  );
  assert.throws(
    () => deriveV2BetaChipnetSettlementPins(clone),
    V2BetaChipnetRuntimeError,
  );
  assert.throws(
    () => createV2BetaChipnetGenesisRuntimeFromResolution({
      profileCore,
      runtimeResolution: clone,
    }),
  );
  assert.throws(
    () => deriveV2BetaChipnetStoreRuntimeMaterialsSha256({
      schema: 'shieldkit-v2-direct-pf10-runtime-resolution-v1',
      eligibility: 'development-only',
    }),
    V2BetaChipnetRuntimeError,
  );

  const bound = bindV2BetaChipnetRuntimeResolution(resolution, {
    descriptorSha256: '1'.repeat(64),
    manifestSha256: '2'.repeat(64),
  });
  assert.equal(bound.descriptorSha256, '1'.repeat(64));
  assert.equal(bound.manifestSha256, '2'.repeat(64));
  assert.equal(bound.runtimeMaterialSha256, resolution.runtimeMaterialSha256);
  assert.throws(
    () => bindV2BetaChipnetRuntimeResolution(resolution, {
      descriptorSha256: '3'.repeat(64),
      manifestSha256: '4'.repeat(64),
    }),
    V2BetaChipnetRuntimeError,
  );
  assert.throws(
    () => bindV2BetaChipnetRuntimeResolution(bound, {
      descriptorSha256: '3'.repeat(64),
      manifestSha256: '4'.repeat(64),
    }),
    V2BetaChipnetRuntimeError,
  );
  return resolution;
}

async function exerciseWarmCache(runtimeDirectory, temporaryRoot) {
  const cacheRoot = path.join(temporaryRoot, 'cache');
  await mkdir(cacheRoot, { mode: 0o700 });
  const coldStarted = performance.now();
  const installed = await installV2BetaChipnetRuntimeCache({
    allowedOutputRoot: runtimeDirectory,
    cacheRoot,
    runtimeDirectory,
    temporaryRoot,
  });
  const warmStarted = performance.now();
  const warm = await loadCachedV2BetaChipnetRuntime({ cacheRoot, runtimeDirectory });
  const genesisStarted = performance.now();
  const warmGenesis = createV2BetaChipnetGenesisRuntimeFromResolution({
    profileCore: deriveV2BetaChipnetProfileCore(warm),
    runtimeResolution: warm,
  });
  return Object.freeze({
    runtimeMaterialSha256: warm.runtimeMaterialSha256,
    genesisRuntimeMaterialSha256: warmGenesis.runtimeMaterialSha256,
    verification: installed.verification.status,
    timingsMs: Object.freeze({
      coldVerificationAndCacheInstall: performance.now() - coldStarted,
      warmCacheLoad: genesisStarted - warmStarted,
      warmGenesisIssuance: performance.now() - genesisStarted,
    }),
  });
}

function runChild(argv) {
  return new Promise((resolve, reject) => {
    const environment = { ...process.env };
    delete environment.NODE_OPTIONS;
    const child = spawn(process.execPath, argv, {
      cwd: repositoryRoot,
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stderr, stdout }));
  });

}

if (process.argv[2] === '--beta-runtime-generate-child') {
  const [allowedOutputRoot, outputDirectory, profileCore, profilePackage, qualificationEvidence, temporaryRoot, instanceId] = process.argv.slice(3);
  try {
    const result = await runV2Pf10BetaRuntime([
      '--instance-id', instanceId, '--output', outputDirectory,
      '--profile-core', profileCore, '--profile-package', profilePackage,
      '--qualification-evidence', qualificationEvidence, '--temporary-root', temporaryRoot,
    ], { allowedOutputRoot, cwd: repositoryRoot });
    process.stdout.write(JSON.stringify(result)); process.exit(0);
  } catch (error) { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exit(1); }
} else if (process.argv[2] === '--beta-chipnet-runtime-child') {
  const [runtime, temporaryRoot] = process.argv.slice(3);
  try {
    const resolution = await exerciseRuntime(runtime, temporaryRoot);
    await new Promise((resolve, reject) => {
      process.stdout.write(JSON.stringify({
        instanceId: resolution.identity.instanceId,
        runtimeMaterialSha256: resolution.runtimeMaterialSha256,
      }), (error) => (error === undefined || error === null) ? resolve() : reject(error));
    });
    // The retained CashC compilation stack owns worker handles after a
    // successful independent rebuild. This branch is a one-shot child only.
    process.exit(0);
  } catch (error) {
    await new Promise((resolve) => {
      process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`, resolve);
    });
    process.exit(1);
  }
} else if (process.argv[2] === '--beta-chipnet-warm-cache-child') {
  const [runtime, temporaryRoot] = process.argv.slice(3);
  try {
    const result = await exerciseWarmCache(runtime, temporaryRoot);
    process.stdout.write(JSON.stringify(result));
    process.exit(0);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exit(1);
  }
} else {
  const { default: test } = await import('node:test');
  test('beta Chipnet runtime is independently rebuilt, branded, and descriptor-neutral', async () => {
  await requireQualificationRuntimeFixture(runtimeDirectory);
  const parent = path.join(repositoryRoot, '.codex-build', 'test-tmp');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const temporaryRoot = await mkdtemp(path.join(parent, 'beta-chipnet-runtime-'));
  try {
    const result = await runChild([
      path.join(import.meta.dirname, 'beta-chipnet-runtime.test.mjs'),
      '--beta-chipnet-runtime-child',
      runtimeDirectory,
      temporaryRoot,
    ]);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.code, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.match(output.instanceId, /^[0-9a-f]{64}$/u);
    assert.match(output.runtimeMaterialSha256, /^[0-9a-f]{64}$/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
  });

  test('beta Chipnet warm cache restores only a fresh branded resolution', async () => {
    await requireQualificationRuntimeFixture(runtimeDirectory);
    const parent = path.join(repositoryRoot, '.codex-build', 'test-tmp');
    await mkdir(parent, { recursive: true, mode: 0o700 });
    const temporaryRoot = await mkdtemp(path.join(parent, 'beta-chipnet-runtime-cache-'));
    try {
      const result = await runChild([
        path.join(import.meta.dirname, 'beta-chipnet-runtime.test.mjs'),
        '--beta-chipnet-warm-cache-child',
        runtimeDirectory,
        temporaryRoot,
      ]);
      assert.equal(result.signal, null, result.stderr);
      assert.equal(result.code, 0, result.stderr);
      const warm = JSON.parse(result.stdout);
      assert.equal(warm.verification, 'beta-runtime-reverified-unqualified');
      assert.equal(warm.genesisRuntimeMaterialSha256, warm.runtimeMaterialSha256);
      assert.throws(
        () => assertV2BetaChipnetRuntimeResolution(structuredClone(warm)),
        V2BetaChipnetRuntimeError,
      );
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
}
