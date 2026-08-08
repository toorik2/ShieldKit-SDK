import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, symlinkSync, linkSync, chmodSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  resolveHomeContext,
  writeHomeManifest,
  migrateFromLegacyDataHome,
  isLegacyDataHome,
  acquireHomeLock,
  readLegacyPf10Pointer,
  HOME_SCHEMA,
} from './resolve.mjs';
import { loadClosedCatalog } from '../registry/designs.mjs';
import { CliError } from '../contracts/errors.mjs';
import { derivePf10LegacyMigrationReceiptForTest } from './pf10-context-bridge.mjs';

const catalog = loadClosedCatalog();
const pf10 = catalog.designs.find((d) => d.id === 'pf10');
const pf6 = catalog.designs.find((d) => d.alias === 'pf6');
const PROFILE = 'cc'.repeat(32);
const INSTANCE = 'aa'.repeat(32);
const GENESIS_DESCRIPTOR = 'bb'.repeat(32);

function boundHome(overrides = {}) {
  return {
    backendId: pf10.backendId,
    profileId: PROFILE,
    designId: pf10.id,
    instanceId: INSTANCE,
    genesisDescriptorHash: GENESIS_DESCRIPTOR,
    ...overrides,
  };
}

test('existing home wins; conflicting design fails closed', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-home-'));
  try {
    writeHomeManifest(dir, boundHome());
    const ok = resolveHomeContext({
      homePath: dir,
      design: 'pf10',
    });
    assert.equal(ok.homeWins, true);
    assert.equal(ok.home.schema, HOME_SCHEMA);
    assert.equal(ok.design.profileId, PROFILE);
    assert.equal(ok.design.profileStatus, 'frozen');
    assert.equal(ok.design.networkGenesis, '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b');

    assert.throws(
      () => resolveHomeContext({ homePath: dir, design: 'fri' }),
      (e) => e instanceof CliError && (
        e.code === 'HOME_PROFILE_MISMATCH' || e.code === 'HOME_DESIGN_MISMATCH'
      ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('legacy data-home is not auto-treated as new home', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-legacy-'));
  try {
    writeFileSync(path.join(dir, 'session.json'), JSON.stringify({ ok: true }));
    assert.equal(isLegacyDataHome(dir), true);
    assert.throws(
      () => resolveHomeContext({ homePath: dir }),
      (e) => e instanceof CliError && e.code === 'LEGACY_DATA_HOME_NOT_AUTO',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('explicit migration from legacy data-home is reversible (no delete)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-mig-'));
  try {
    writeFileSync(path.join(dir, 'session.json'), JSON.stringify({
      genesisTxid: 'bb'.repeat(32),
    }));
    const dest = path.join(dir, 'new-home');
    await assert.rejects(
      migrateFromLegacyDataHome({ dataHome: dir, destHome: dest, design: pf10 }),
      (e) => e instanceof CliError && e.code === 'MIGRATION_REQUIRED' && /committed zero-conf deployment authority/.test(e.message),
    );
    assert.equal(isLegacyDataHome(dir), true); // legacy preserved and not relabelled
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('PF10 migration receipt comes only from the committed product authority', () => {
  const dataHome = path.resolve(mkdtempSync(path.join(tmpdir(), 'sk-pf10-authority-')));
  const expectedDataDirectory = path.join(dataHome, 'shieldkit', 'v2-beta-product');
  try {
    const receipt = derivePf10LegacyMigrationReceiptForTest({
      dataHome,
      design: pf10,
      loadConfig: ({ dataHome: supplied }) => {
        assert.equal(supplied, dataHome);
        return { config: {
          dataDirectory: expectedDataDirectory,
          deploymentDirectory: path.join(expectedDataDirectory, 'deployment'),
        } };
      },
      loadGenesis: ({ deploymentDirectory }) => {
        assert.equal(deploymentDirectory, path.join(expectedDataDirectory, 'deployment'));
        return {
          profileId: '12'.repeat(32),
          instanceId: '34'.repeat(32),
          zeroConfEvidenceSha256: '56'.repeat(32),
          genesisOutpoint: { txid: '78'.repeat(32), vout: 0 },
          // This untrusted decoration must never become part of the receipt.
          designId: 'fri-stark-96kb',
        };
      },
    });
    assert.deepEqual(receipt, {
      schema: 'shieldkit-pf10-legacy-migration-receipt/v1',
      backendId: 'pf10-v2-beta',
      designId: 'pf10',
      profileId: '12'.repeat(32),
      instanceId: '34'.repeat(32),
      network: 'bch-chipnet',
      genesisDescriptorHash: '56'.repeat(32),
      genesisOutpoint: { txid: '78'.repeat(32), vout: 0 },
      sourceDataHome: dataHome,
      sourceDataDirectory: expectedDataDirectory,
    });

    assert.throws(() => derivePf10LegacyMigrationReceiptForTest({
      dataHome,
      design: { ...pf10, id: 'fri-stark-96kb' },
      loadConfig: () => { throw new Error('must not open non-PF10 source'); },
      loadGenesis: () => { throw new Error('must not open non-PF10 source'); },
    }), (e) => e instanceof CliError && e.code === 'MIGRATION_REQUIRED');

    assert.throws(() => derivePf10LegacyMigrationReceiptForTest({
      dataHome,
      design: pf10,
      loadConfig: () => ({ config: {
        dataDirectory: expectedDataDirectory,
        deploymentDirectory: path.join(expectedDataDirectory, 'deployment'),
      } }),
      loadGenesis: () => ({
        profileId: '12'.repeat(32), instanceId: '34'.repeat(32),
        zeroConfEvidenceSha256: '56'.repeat(32),
        genesisOutpoint: { txid: '78'.repeat(32), vout: 1 },
      }),
    }), (e) => e instanceof CliError && e.code === 'MIGRATION_REQUIRED');
  } finally {
    rmSync(dataHome, { recursive: true, force: true });
  }
});

test('exact profile is an assertion even for the same backend family', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-profile-'));
  try {
    writeHomeManifest(dir, boundHome({ profileId: '11'.repeat(32) }));
    assert.throws(
      () => resolveHomeContext({ homePath: dir, design: 'pf10', profile: '22'.repeat(32) }),
      (e) => e instanceof CliError && e.code === 'HOME_PROFILE_MISMATCH',
    );
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a bound home requires exact instance, accepted-genesis descriptor, canonical Chipnet genesis, and a publishable catalog design', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-bound-home-'));
  try {
    assert.throws(
      () => writeHomeManifest(dir, boundHome({ instanceId: undefined })),
      (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND' && /instanceId/.test(e.message),
    );
    assert.throws(
      () => writeHomeManifest(dir, boundHome({ genesisDescriptorHash: undefined })),
      (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND' && /descriptor hash/.test(e.message),
    );
    assert.throws(
      () => writeHomeManifest(dir, boundHome({
        backendId: pf6.backendId,
        designId: pf6.id,
      })),
      (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND' && /unfrozen design/.test(e.message),
    );

    writeHomeManifest(dir, boundHome());
    const manifest = path.join(dir, 'home.json');
    const raw = JSON.parse(readFileSync(manifest, 'utf8'));
    raw.networkGenesis = '00'.repeat(32);
    writeFileSync(manifest, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(
      () => resolveHomeContext({ homePath: dir }),
      (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND' && /invalid immutable fields/.test(e.message),
    );
    raw.networkGenesis = '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';
    raw.designId = pf6.id;
    raw.backendId = pf6.backendId;
    writeFileSync(manifest, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(
      () => resolveHomeContext({ homePath: dir }),
      (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND' && /unfrozen design/.test(e.message),
    );
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('manifest rejects symlink, unsafe modes, malformed fields and overwrite', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-hardening-'));
  const outside = mkdtempSync(path.join(tmpdir(), 'sk-outside-'));
  try {
    writeHomeManifest(dir, boundHome());
    assert.throws(() => writeHomeManifest(dir, boundHome()), CliError);

    const manifest = path.join(dir, 'home.json');
    chmodSync(manifest, 0o644);
    assert.throws(() => resolveHomeContext({ homePath: dir }), (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND');
    chmodSync(manifest, 0o600);
    const raw = JSON.parse(readFileSync(manifest, 'utf8'));
    raw.path = outside; // must not override the resolver's computed path
    writeFileSync(manifest, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(() => resolveHomeContext({ homePath: dir }), (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND');

    // A hard-link turns the manifest into a multi-name race surface.
    const second = path.join(outside, 'manifest-copy.json');
    linkSync(manifest, second);
    assert.throws(() => resolveHomeContext({ homePath: dir }), (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND');

    const linked = path.join(outside, 'linked-home');
    symlinkSync(dir, linked);
    assert.throws(() => resolveHomeContext({ homePath: linked }), (e) => e instanceof CliError && e.code === 'HOME_NOT_FOUND');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('single-writer home lock rejects concurrent holder', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-lock-'));
  try {
    writeHomeManifest(dir, boundHome());
    const a = acquireHomeLock(dir);
    assert.throws(() => acquireHomeLock(dir), (e) => e instanceof CliError && e.code === 'LOCK_HELD');
    a.release();
    const b = acquireHomeLock(dir);
    b.release();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('legacy PF10 pointer is private, strict, and identity-bound to the home', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sk-pointer-'));
  try {
    const home = writeHomeManifest(dir, boundHome());
    const legacyDataHome = path.join(dir, 'legacy-source');
    const pointerPath = path.join(dir, 'runtime', 'legacy-pf10-pointer.json');
    writeFileSync(pointerPath, `${JSON.stringify({
      schema: 'shieldkit-pf10-legacy-pointer/v1',
      backendId: home.backendId,
      designId: home.designId,
      profileId: home.profileId,
      instanceId: home.instanceId,
      network: home.network,
      genesisDescriptorHash: home.genesisDescriptorHash,
      genesisOutpoint: { txid: 'dd'.repeat(32), vout: 0 },
      legacyDataHome,
      sourceDataDirectory: path.join(legacyDataHome, 'shieldkit', 'v2-beta-product'),
    }, null, 2)}\n`, { mode: 0o600 });
    const pointer = readLegacyPf10Pointer(home);
    assert.equal(pointer.legacyDataHome, legacyDataHome);
    assert.equal(pointer.profileId, home.profileId);

    const raw = JSON.parse(readFileSync(pointerPath, 'utf8'));
    raw.profileId = 'ee'.repeat(32);
    writeFileSync(pointerPath, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(
      () => readLegacyPf10Pointer(home),
      (error) => error instanceof CliError && error.code === 'HOME_NOT_FOUND',
    );
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
