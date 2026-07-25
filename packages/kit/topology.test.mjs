/**
 * Structural beauty gates: domain topology + createKit surface + no gate-era public names.
 */
import assert from 'node:assert/strict';
import { readdirSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const allowed = new Set(['kit', 'profile', 'action', 'prove', 'recover']);

test('product packages are only domain peers', () => {
  const peers = readdirSync(packagesRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((n) => !n.startsWith('.'));
  for (const p of peers) {
    assert.ok(allowed.has(p), `unexpected top-level package peer: ${p}`);
  }
  for (const need of ['kit', 'profile', 'action', 'prove', 'recover']) {
    assert.ok(peers.includes(need), `missing domain ${need}`);
  }
  for (const gone of [
    'app-kit', 'sdk', 'local-setup', 'core', 'g2-complete-assembler',
    'setup-profile-bridge', 'profile-builder', 'action-packet', 'recovery',
  ]) {
    assert.equal(existsSync(path.join(packagesRoot, gone)), false, `${gone} must not be a top-level peer`);
  }
});

test('createKit is the product facade export', async () => {
  const kit = await import('./index.mjs');
  assert.equal(typeof kit.createKit, 'function');
  assert.equal(typeof kit.createAppKit, 'undefined');
  assert.equal(typeof kit.createDesktopComposition, 'undefined');
});

test('public action index has zero g2/G2 export names', async () => {
  const action = await import('../action/index.mjs');
  const keys = Object.keys(action);
  const bad = keys.filter((k) => /g2|G2/i.test(k));
  assert.deepEqual(bad, [], `public g2 names must be absent, got: ${bad.join(',')}`);
  assert.equal(typeof action.planCompleteSettlement, 'function');
  assert.equal(typeof action.assembleCompleteSettlement, 'function');
});

test('ceremony + development setup modules exist', () => {
  assert.ok(existsSync(path.join(packagesRoot, 'profile/setup/development.mjs')));
  assert.ok(existsSync(path.join(packagesRoot, 'profile/setup/ceremony.mjs')));
  assert.ok(existsSync(path.join(packagesRoot, 'profile/init.mjs')));
  assert.ok(existsSync(path.join(packagesRoot, 'prove/unlock.mjs')));
  assert.ok(existsSync(path.join(packagesRoot, 'prove/groth16.mjs')));
});

test('package scope is @shieldkit/*', () => {
  for (const name of ['kit', 'profile', 'action', 'prove', 'recover']) {
    const pkg = JSON.parse(readFileSync(path.join(packagesRoot, name, 'package.json'), 'utf8'));
    assert.equal(pkg.name, `@shieldkit/${name}`);
  }
});
