import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  normalizeLegacyC7Environment,
  readLegacyC7Config,
} from '../src/legacy-c7-config.mjs';
import { validateBuild } from '../src/build-adapter.mjs';
import { readBuildProfile, sanitizeLegacyEnvironment, toLegacyEnvironment } from '../src/build-profile.mjs';

const paths = { here: '/repo/build/chunked/pairing', repoRoot: '/repo' };
const readJson = (url) => JSON.parse(readFileSync(url, 'utf8'));

test('legacy generator defaults preserve explicit narrow and specialization choices', () => {
  const environment = { SEAMNARROW: '0', KSPEC: 'custom', SZ_ALLAFF: '0' };
  normalizeLegacyC7Environment(environment);
  assert.deepEqual(environment, {
    SEAMNARROW: '0',
    KSPEC: 'custom',
    SZ_ALLAFF: '1',
    L17SEL: '1',
    SIBLING_READ: '1',
  });
});

test('legacy C7 configuration has portable defaults and typed switches', () => {
  const environment = {
    DP: '1',
    STRIPED: '1',
    KWIN: '9',
    C7_MAXTRY: '6',
    ELIG_IDX: '3',
    TMPDIR: '/work/tmp',
  };
  const configuration = readLegacyC7Config(environment, paths);

  assert.deepEqual(configuration.paths, {
    generated: '/repo/build/chunked/pairing/generated',
    tool: '/repo/tools/singleton-artifact',
    temp: '/work/tmp/verifier-cash-c7',
  });
  assert.equal(configuration.mode.directPort, true);
  assert.equal(configuration.mode.striped, true);
  assert.equal(configuration.layout.windowSize, 9);
  assert.equal(configuration.optimization.maxTry, 6);
  assert.equal(configuration.proofSelection.index, 3);
  assert.equal(Object.isFrozen(configuration), true);
  assert.equal(Object.isFrozen(configuration.mode), true);
  assert.deepEqual(environment, {
    DP: '1',
    STRIPED: '1',
    KWIN: '9',
    C7_MAXTRY: '6',
    ELIG_IDX: '3',
    TMPDIR: '/work/tmp',
  });
});

test('legacy C7 configuration rejects invalid lane inputs at the boundary', () => {
  assert.throws(() => readLegacyC7Config({ KWIN: '6' }, paths), /KWIN/);
  assert.throws(() => readLegacyC7Config({ C7_MAXTRY: '-1' }, paths), /C7_MAXTRY/);
  assert.throws(() => readLegacyC7Config({ STRIPED_FRAGS: 'none' }, paths), /STRIPED_FRAGS/);
  assert.throws(() => readLegacyC7Config({ ELIG_INSTANCE: 'file' }, paths), /ELIG_FILE/);
  assert.throws(() => readLegacyC7Config({ C7_SHIELD_ADAPTER_FILE: '/tmp/adapter.json' }, paths), /SHA256/);
  assert.throws(() => readLegacyC7Config({ C7_SHIELD_ADAPTER_FILE: '/tmp/adapter.json', C7_SHIELD_ADAPTER_SHA256: '0'.repeat(64), ELIG_INSTANCE: 'file', ELIG_FILE: '/tmp/proof.json' }, paths), /cannot be combined/);
  assert.throws(() => readLegacyC7Config({ C7_SHIELD_ADAPTER_FILE: '/tmp/adapter.json', C7_SHIELD_ADAPTER_SHA256: '0'.repeat(64), ELIG_IDX: '1' }, paths), /ELIG_IDX/);
  assert.throws(() => readLegacyC7Config({ C7_STRUCTURAL_ROLE_COUNT: '2' }, paths), /0 or 3/);
  assert.throws(() => readLegacyC7Config({ C7_STRUCTURAL_ROLE_COUNT: '3' }, paths), /pinned shield action packet/);
  assert.throws(() => readLegacyC7Config({ C7_SHIELD_ACTION_PACKET_FILE: '/tmp/action.packet', C7_SHIELD_ACTION_PACKET_SHA256: '0'.repeat(64) }, paths), /requires C7_STRUCTURAL_ROLE_COUNT=3/);
  assert.throws(() => readLegacyC7Config({ C7_STRUCTURAL_ROLE_COUNT: '3', C7_SHIELD_ACTION_PACKET_FILE: '/tmp/action.packet' }, paths), /supplied together/);
  const action = readLegacyC7Config({
    C7_STRUCTURAL_ROLE_COUNT: '3',
    C7_SHIELD_ACTION_PACKET_FILE: '/tmp/action.packet',
    C7_SHIELD_ACTION_PACKET_SHA256: '0'.repeat(64),
  }, paths);
  assert.equal(action.mode.structuralRoleCount, 3);
  assert.deepEqual(action.shieldAction.packet, {
    path: '/tmp/action.packet',
    sha256: '0'.repeat(64),
  });
});

test('the source candidate uses a complete typed profile with deterministic legacy translation', () => {
  const candidate = readJson(new URL('../candidates/bn254-onetx-directstate-10-source-r25.json', import.meta.url));
  const profile = readBuildProfile(candidate.build.profile);
  const environment = toLegacyEnvironment(profile, '/repo/fixture.json');

  assert.equal(profile.layout.windowSize, 9);
  assert.equal(Object.isFrozen(profile.packing), true);
  assert.equal(environment.ELIG_INSTANCE, 'file');
  assert.equal(environment.ELIG_FILE, '/repo/fixture.json');
  assert.equal(environment.DP, '1');
  assert.equal(environment.STRIPED, '1');
  assert.equal(environment.STRIPED_FRAGS, '7');
  assert.equal(environment.CDNW, '1');
  assert.equal(environment.CDWIDTH, '34');
  assert.equal(environment.C7_MAXTRY, '8');
  assert.equal(environment.C7_DBG, undefined);
  assert.equal(environment.C7_STUB, undefined);
});

test('typed profiles reject omitted and unknown build controls', () => {
  const candidate = readJson(new URL('../candidates/bn254-onetx-directstate-10-source-r25.json', import.meta.url));
  const missing = structuredClone(candidate.build.profile);
  delete missing.mode.directPort;
  assert.throws(() => readBuildProfile(missing), /must define exactly/);

  const unknown = structuredClone(candidate.build.profile);
  unknown.packing.experimental = true;
  assert.throws(() => readBuildProfile(unknown), /must define exactly/);
});

test('bounded ten-input builds require an absolute SHA-pinned action packet', () => {
  const candidate = readJson(new URL('../candidates/bn254-onetx-pf7-sub62-r1.json', import.meta.url));
  const build = structuredClone(candidate.build);
  build.structuralRoleCount = 3;
  assert.throws(() => validateBuild(build), /requires shieldActionPacket/);
  build.shieldActionPacket = { path: 'relative.packet', sha256: '0'.repeat(64) };
  assert.throws(() => validateBuild(build), /absolute path/);
  build.shieldActionPacket.path = '/tmp/action.packet';
  assert.throws(() => validateBuild(build), /shieldActionPacketAbi/);
  build.shieldActionPacketAbi = 'sda2-v2-direct';
  validateBuild(build);
  delete build.structuralRoleCount;
  assert.throws(() => validateBuild(build), /requires structuralRoleCount=3/);
});

test('typed build translation pins one complete ShieldKit adapter instead of legacy selectors', () => {
  const candidate = readJson(new URL('../candidates/bn254-onetx-pf7-sub62-r1.json', import.meta.url));
  const shieldAdapter = {
    path: '/tmp/v2-adapter.json',
    sha256: '1'.repeat(64),
  };
  const environment = toLegacyEnvironment(
    candidate.build.profile,
    '/repo/unused-legacy-fixture.json',
    shieldAdapter,
  );
  assert.equal(environment.ELIG_INSTANCE, undefined);
  assert.equal(environment.ELIG_FILE, undefined);
  assert.equal(environment.C7_SHIELD_ADAPTER_FILE, shieldAdapter.path);
  assert.equal(
    environment.C7_SHIELD_ADAPTER_SHA256,
    shieldAdapter.sha256,
  );

  const build = structuredClone(candidate.build);
  build.shieldAdapter = shieldAdapter;
  validateBuild(build);
  build.shieldAdapter.path = 'relative.json';
  assert.throws(() => validateBuild(build), /absolute path/);
});

test('ambient legacy experiment flags are scrubbed without removing host process controls', () => {
  const clean = sanitizeLegacyEnvironment({
    PATH: '/usr/bin',
    HOME: '/home/worker',
    C7_DBG: '1',
    C7_STUB: 'both',
    KWIN: '7',
    T7: '1',
    VKX_NOFR: '1',
    C7_STRUCTURAL_ROLE_COUNT: '3',
    C7_SHIELD_ACTION_PACKET_FILE: '/tmp/action.packet',
    C7_SHIELD_ACTION_PACKET_SHA256: '0'.repeat(64),
    C7_SHIELD_ACTION_PACKET_ABI: 'sda2-v2-direct',
  });
  assert.deepEqual(clean, { PATH: '/usr/bin', HOME: '/home/worker' });
});
