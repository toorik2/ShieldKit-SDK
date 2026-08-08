import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildSignedSettlement,
  assemblePlaceholderOracle,
  assembleProductionSettlement,
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
  PRODUCTION_FLOOR,
  friDomainPreflight,
  resolveProductionFloorDomain,
  isPowerOf8,
  MAX_UNLOCK_BYTES,
  MAX_TX_BYTES,
  VERIFIER_ROLES,
} from './settlement.mjs';
import { runVmGate } from '../vm/corpus.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ART = process.env.SETTLEMENT_ARTIFACT
  || path.join(ROOT, 'evidence/settlement-prod/assemble-transfer-latest.json');

test('product flags: production verifiers on, placeholder off', () => {
  assert.equal(SETTLEMENT_PRODUCTION_VERIFIERS, true);
  assert.equal(PLACEHOLDER_SETTLEMENT, false);
});

test('placeholder oracle is explicitly non-product', () => {
  const tx = assemblePlaceholderOracle({ statement: { kind: 'deposit' } });
  assert.equal(tx.placeholder, true);
  assert.equal(tx.productionVerifiers, false);
  assert.equal(tx.oracleOnly, true);
  assert.equal(VERIFIER_ROLES.length, 17);
  assert.equal(tx.roleLayout.inputCount, 18);
});

test('independent structural VM corpus accepts honest and rejects adversarial', () => {
  const r = runVmGate();
  assert.equal(r.honest.ok, true);
  assert.equal(r.corpus.ok, true);
  assert.ok(r.corpus.count >= 10);
  assert.equal(r.ok, true);
});

test('production sound settlement from artifact when present', { skip: !existsSync(ART) }, () => {
  const raw = JSON.parse(readFileSync(ART, 'utf8'));
  const tx = buildSignedSettlement({
    statement: raw.statement || { kind: 'transfer' },
    assemblyArtifact: ART,
    skipAssemble: true,
  });
  assert.equal(tx.productionVerifiers, true);
  assert.equal(tx.placeholder, false);
  assert.ok(tx.verifierRoles.length >= 10);
  assert.equal(tx.lockingHexes.length, tx.verifierRoles.length);
  assert.ok(tx.sizes.maxUnlockBytes <= MAX_UNLOCK_BYTES);
  if (tx.sizes.txBytesMeasured != null) {
    assert.ok(tx.sizes.txBytesMeasured <= MAX_TX_BYTES, `txBytes ${tx.sizes.txBytesMeasured}`);
  }
  if (tx.vm) {
    assert.equal(tx.vm.allAccept, true);
    assert.equal(tx.vm.txBarOk, true);
    assert.equal(tx.vm.unlockBarOk, true);
  }
  if (tx.forge?.omit_final) {
    assert.equal(tx.forge.omit_final.rejectOk, true);
  }
  for (const h of tx.lockingHexes) {
    const b = Buffer.from(h, 'hex');
    assert.equal(b[0], 0xaa);
    assert.equal(b[1], 0x20);
    assert.equal(b[34], 0x87);
  }
});

test('live assemble production settlement (optional long)', {
  skip: process.env.SETTLEMENT_LIVE_ASSEMBLE !== '1',
}, () => {
  const depth = Number(process.env.SETTLEMENT_DEPTH || 4);
  const blowup = Number(process.env.SETTLEMENT_BLOWUP || 32);
  const grind = Number(process.env.SETTLEMENT_GRIND || 8);
  const nq = Number(process.env.SETTLEMENT_NQ || 8);
  const out = path.join(ROOT, 'evidence/settlement-prod', `assemble-transfer-d${depth}-b${blowup}.json`);
  const assembly = assembleProductionSettlement({
    kind: 'transfer',
    depth,
    blowup,
    grind,
    nq,
    seed: 1,
    outPath: out,
  });
  assert.equal(assembly.productionVerifiers, true);
  assert.equal(assembly.placeholder, false);
  assert.ok(assembly.vm?.allAccept);
  assert.ok(assembly.vm?.txBytes <= MAX_TX_BYTES);
  assert.ok(assembly.vm?.maxUnlockBytes <= MAX_UNLOCK_BYTES);
});

test('Rust prove statement matches sound assembly artifact (same kind/depth/seed)', {
  skip: !(
    existsSync(
      process.env.SHIELDKIT_FRI_WORKER ||
        path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker'),
    ) && existsSync(ART)
  ),
}, () => {
  // Drive real Rust worker + precomputed sound assembly (same pool_witness seed path).
  const worker =
    process.env.SHIELDKIT_FRI_WORKER ||
    path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker');
  const r = spawnSync(
    worker,
    [],
    {
      input: JSON.stringify({
        cmd: 'prove',
        kind: 'transfer',
        depth: 4,
        seed: 1,
        blowup: 32,
        queries: 8,
        grindBits: 8,
        foldStep: 3,
        deep: true,
      }) + '\n',
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const rust = JSON.parse(r.stdout.trim());
  assert.equal(rust.verifyOk, true);
  assert.equal(rust.usesPython, false);
  const art = JSON.parse(readFileSync(ART, 'utf8'));
  assert.equal(art.productionVerifiers, true);
  assert.equal(art.placeholder, false);
  assert.equal(String(rust.statement.root), String(art.statement.root));
  assert.equal(String(rust.statement.nf), String(art.statement.nf));
  assert.equal(String(rust.statement.depth), String(art.statement.depth));
  assert.ok(art.vm?.allAccept === true);
  assert.ok(art.vm?.txBytes <= MAX_TX_BYTES);
  assert.ok(art.vm?.maxUnlockBytes <= MAX_UNLOCK_BYTES);
});

test('exact production floor domain is fail-closed (not 8^m)', () => {
  assert.equal(PRODUCTION_FLOOR.depth, 32);
  assert.equal(PRODUCTION_FLOOR.blowup, 2048);
  const pre = friDomainPreflight(PRODUCTION_FLOOR);
  assert.equal(pre.T, 2048);
  assert.equal(pre.N, 4_194_304);
  assert.equal(pre.N_is_8m, false);
  assert.equal(pre.ok, false);
  assert.equal(isPowerOf8(4_194_304), false);
  assert.equal(isPowerOf8(16_777_216), true); // 8^8 after T-pad or blowup 8192
});

test('production floor domain pad resolves to 8^m without security weaken', () => {
  const r = resolveProductionFloorDomain(PRODUCTION_FLOOR);
  assert.equal(r.ok, true);
  assert.equal(r.T, 2048);
  assert.equal(r.blowup, 8192);
  assert.equal(r.N, 16_777_216);
  assert.equal(isPowerOf8(r.N), true);
  assert.ok(r.securityBits >= 100);
  assert.equal(r.pad?.kind, 'blowup');
  assert.equal(r.pad?.from, 2048);
  assert.equal(r.pad?.to, 8192);
  const padded = friDomainPreflight({ ...PRODUCTION_FLOOR, resolvePad: true });
  assert.equal(padded.ok, true);
  assert.equal(padded.blowup, 8192);
  assert.equal(padded.N_is_8m, true);
});

test('python assemble preflight rejects exact production floor without proving', () => {
  const r = spawnSync(
    'python3',
    [
      path.join(ROOT, 'packages/settlement/python/assemble_sound_settlement.py'),
      'preflight',
      '--depth', '32',
      '--blowup', '2048',
      '--fold-step', '3',
    ],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
  );
  assert.equal(r.status, 4, (r.stderr || r.stdout || '').slice(-500));
  // Vendor imports print fold self-tests before JSON; take the trailing object.
  const m = (r.stdout || '').match(/\{[\s\S]*\}\s*$/);
  assert.ok(m, 'expected trailing JSON preflight object');
  const doc = JSON.parse(m[0]);
  assert.equal(doc.ok, false);
  assert.equal(doc.infeasible, true);
  assert.equal(doc.preflight.N_is_8m, false);
  assert.equal(doc.preflight.N, 4_194_304);
  // Domain pad path is documented and green (clears DOMAIN_8M without security weaken).
  assert.equal(doc.domainPadOk, true);
  assert.equal(doc.withPad.ok, true);
  assert.equal(doc.withPad.blowup, 8192);
  assert.ok(doc.resolved.securityBits >= 100);
});

test('evidence package does not claim production-floor green', () => {
  const reportPath = path.join(ROOT, 'evidence/settlement-prod/SETTLEMENT_PROD_REPORT.json');
  const attemptPath = path.join(ROOT, 'evidence/settlement-prod/PRODUCTION_FLOOR_ATTEMPT.json');
  assert.ok(existsSync(reportPath), 'SETTLEMENT_PROD_REPORT.json');
  assert.ok(existsSync(attemptPath), 'PRODUCTION_FLOOR_ATTEMPT.json');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  const attempt = JSON.parse(readFileSync(attemptPath, 'utf8'));
  assert.equal(report.productFlags.SETTLEMENT_PRODUCTION_VERIFIERS, true);
  assert.equal(report.productFlags.PLACEHOLDER_SETTLEMENT, false);
  assert.equal(report.productionFloor.green, false);
  assert.equal(report.productionFloor.ok, false);
  assert.equal(report.offline.ok, true);
  assert.equal(report.chipnet.ok, true);
  assert.equal(attempt.infeasible, true);
  assert.equal(attempt.ok, false);
  for (const row of report.offline.rows) {
    assert.equal(row.placeholder, false);
    assert.equal(row.productionVerifiers, true);
    assert.ok(row.txBytes <= MAX_TX_BYTES);
    assert.ok(row.maxUnlockBytes <= MAX_UNLOCK_BYTES);
    assert.equal(row.allAccept, true);
  }
});
