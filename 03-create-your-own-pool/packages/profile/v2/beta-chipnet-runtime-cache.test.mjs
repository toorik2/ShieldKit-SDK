import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  assertV2BetaChipnetNativeProofArtifacts,
  V2BetaChipnetRuntimeError,
  loadCachedV2BetaChipnetRuntime,
} from './beta-chipnet-runtime.mjs';
import {
  deriveV2BetaRuntimeCacheDirectoryNameForTest,
  extractV2BetaRuntimeImportsForTest,
  V2_BETA_CHIPNET_RUNTIME_CACHE_FILE,
  V2_BETA_CHIPNET_RUNTIME_CACHE_SCHEMA,
} from './beta-chipnet-runtime-cache.mjs';

test('cache generations bind both the artifact manifest and runtime source', () => {
  const manifest = 'a'.repeat(64);
  const source = 'b'.repeat(64);
  const name = deriveV2BetaRuntimeCacheDirectoryNameForTest(manifest, source);
  assert.match(name, /^[0-9a-f]{64}$/u);
  assert.equal(
    deriveV2BetaRuntimeCacheDirectoryNameForTest(manifest, source),
    name,
  );
  assert.notEqual(
    deriveV2BetaRuntimeCacheDirectoryNameForTest('c'.repeat(64), source),
    name,
  );
  assert.notEqual(
    deriveV2BetaRuntimeCacheDirectoryNameForTest(manifest, 'd'.repeat(64)),
    name,
  );
});

test('runtime source closure ignores import examples held in strings', () => {
  const imports = extractV2BetaRuntimeImportsForTest(`
import first from './first.mjs';
import {
  second,
} from './second.mjs';
export { third } from './third.mjs';
const generated = "import { fake } from './does-not-exist.mjs';";
const alsoGenerated = [
  "import { fakeAgain } from './also-does-not-exist.mjs';",
];
`);
  assert.deepEqual(imports, ['./first.mjs', './second.mjs', './third.mjs']);
});

test('beta runtime cache is a separate unqualified warm-load boundary', async () => {
  assert.equal(
    V2_BETA_CHIPNET_RUNTIME_CACHE_SCHEMA,
    'shieldkit-v2-direct-pf10-beta-chipnet-runtime-cache-v1',
  );
  assert.equal(V2_BETA_CHIPNET_RUNTIME_CACHE_FILE, 'beta-runtime-cache.json');
  const source = await readFile(
    new URL('./beta-chipnet-runtime-cache.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /verifyV2Pf10BetaRuntime/u);
  assert.match(source, /allowedOutputRoot === undefined \? \{\} : \{ allowedOutputRoot \}/u);
  assert.match(source, /validateDirectV2Pf10BetaRuntimeMaterial/u);
  assert.match(source, /O_NOFOLLOW/u);
  assert.match(source, /mkdtemp/u);
  assert.match(source, /await rename\(stage, destination\)/u);
  assert.match(source, /V2_BETA_LOCAL_FALSE_CLAIMS/u);
  assert.doesNotMatch(source, /buildDirectV2Pf10BetaRuntime/u);
  assert.doesNotMatch(source, /buildDirectV2StateHelper/u);
  assert.doesNotMatch(source, /buildDirectV2StateTrampolineLock/u);
  assert.match(source, /not a signature/u);
});

test('the literal cache-load body cannot reach the cold verifier or PF10 builder', async () => {
  const [source, runtime, genesis] = await Promise.all([
    readFile(new URL('./beta-chipnet-runtime-cache.mjs', import.meta.url), 'utf8'),
    readFile(new URL('./beta-chipnet-runtime.mjs', import.meta.url), 'utf8'),
    readFile(new URL('./genesis.mjs', import.meta.url), 'utf8'),
  ]);
  const warmLoad = source.slice(
    source.indexOf('export async function loadV2BetaChipnetRuntimeCache'),
    source.indexOf('/**\n * Require a process-local capability'),
  );
  assert.match(warmLoad, /warmSettlementPins/u);
  assert.doesNotMatch(warmLoad, /verifyV2Pf10BetaRuntime|buildDirectV2Pf10BetaRuntime|runBetaProofQualification/u);
  const resolutionWarmLoad = runtime.slice(
    runtime.indexOf('export async function loadCachedV2BetaChipnetRuntime'),
    runtime.indexOf('export function assertV2BetaChipnetRuntimeResolution'),
  );
  assert.doesNotMatch(resolutionWarmLoad, /buildDirectV2Pf10BetaRuntime|buildDirectV2StateHelper|buildDirectV2StateTrampolineLock/u);
  const warmGenesis = genesis.slice(
    genesis.indexOf('export function createV2BetaChipnetGenesisRuntimeFromResolution'),
    genesis.indexOf('function genesisRuntimePins'),
  );
  assert.doesNotMatch(warmGenesis, /buildDirectV2Pf10BetaRuntime|buildDirectV2StateHelper|buildDirectV2StateTrampolineLock/u);
  assert.match(warmGenesis, /stateHelperBytecode/u);
  assert.match(warmGenesis, /stateUnlockingBytecode/u);
  assert.throws(() => assertV2BetaChipnetNativeProofArtifacts({
    schema: 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1', artifacts: {},
  }), V2BetaChipnetRuntimeError);
});

test('receipt-bound linked cache loader records only its one warm-load boundary', async () => {
  const source = await readFile(
    new URL('./beta-chipnet-runtime.mjs', import.meta.url),
    'utf8',
  );
  const linkedLoad = source.slice(
    source.indexOf('export async function loadV2BetaProductLinkedRuntimeCache'),
    source.indexOf('/** Reject lookalikes'),
  );
  assert.match(linkedLoad, /recordV2BetaRuntimeWork\(\{ type: 'linked-runtime-cache-load' \}\)/u);
  assert.doesNotMatch(linkedLoad, /cold-runtime-build|full-runtime-verification|compiler-child-spawn|instance-specialization/u);
});

test('cached beta runtime load has no cold fallback', async () => {
  await assert.rejects(
    loadCachedV2BetaChipnetRuntime({
      cacheRoot: path.join(import.meta.dirname, 'cache-does-not-exist'),
      runtimeDirectory: path.join(import.meta.dirname, 'runtime-does-not-exist'),
    }),
    (error) => error instanceof V2BetaChipnetRuntimeError
      && error.code === 'BETA_RUNTIME_CACHE_UNAVAILABLE',
  );
});
