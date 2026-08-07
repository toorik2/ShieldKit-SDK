/**
 * Product profile-fixed role locks gate.
 * Drives shipped profile.mjs against real settlement-prod assemblies.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCT_PROFILE,
  profileIdFromProduct,
  extractRoleLocks,
  compareKindLocks,
  freezeProfileLocks,
  assertSameRoleLocks,
} from './profile.mjs';
import {
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
} from './settlement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EVID = path.join(ROOT, 'evidence/settlement-prod');
const paths = {
  deposit: path.join(EVID, 'assemble-deposit-d4-b32.json'),
  transfer: path.join(EVID, 'assemble-transfer-d4-b32.json'),
  withdrawal: path.join(EVID, 'assemble-withdrawal-d4-b32.json'),
};

test('product flags remain production', () => {
  assert.equal(SETTLEMENT_PRODUCTION_VERIFIERS, true);
  assert.equal(PLACEHOLDER_SETTLEMENT, false);
});

test('product profile id is stable', () => {
  const a = profileIdFromProduct();
  const b = profileIdFromProduct(PRODUCT_PROFILE);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('extractRoleLocks from production transfer assembly', () => {
  assert.ok(existsSync(paths.transfer));
  const locks = extractRoleLocks(paths.transfer);
  assert.equal(locks.productionVerifiers, true);
  assert.equal(locks.placeholder, false);
  assert.equal(locks.lockingHexes.length, PRODUCT_PROFILE.roleCount);
  assert.ok(locks.lockSetSha256.length === 64);
  for (const h of locks.lockingHexes) {
    assert.match(h, /^aa20[0-9a-f]{64}87$/);
  }
});

test('profile-fixed locks: D/T/W must share lock hashes (product gate)', () => {
  for (const p of Object.values(paths)) {
    assert.ok(existsSync(p), p);
  }
  const cmp = compareKindLocks(paths);
  // Durable product requirement: when this fails, publication is blocked.
  // Write-through is handled by production report scripts; test encodes the gate.
  if (!cmp.ok) {
    // Fail closed with actionable detail (do not soft-pass).
    const sample = cmp.drifts.slice(0, 5).map(
      (d) =>
        `role[${d.index}] ${d.role}: ${d.redeemSha256[0].slice(0, 12)}≠${d.redeemSha256[1].slice(0, 12)}`,
    );
    assert.fail(
      `PROFILE_FIXED_LOCKS_FAIL: ${cmp.drifts.length} drifts (vendor redeems still proof-tied). ` +
        `sample: ${sample.join('; ')}. Fix: move proof constants to unlocks so redeems are param-only.`,
    );
  }
  assert.equal(cmp.ok, true);
  assertSameRoleLocks(cmp.extracted.deposit, cmp.extracted.transfer);
  assertSameRoleLocks(cmp.extracted.transfer, cmp.extracted.withdrawal);
});

test('freezeProfileLocks writes PROFILE_LOCKS.json', () => {
  const outDir = path.join(ROOT, 'evidence/production');
  const doc = freezeProfileLocks(paths.transfer, outDir);
  assert.equal(doc.locks.length, 19);
  assert.ok(existsSync(path.join(outDir, 'PROFILE_LOCKS.json')));
  assert.equal(doc.profileId, profileIdFromProduct());
});
