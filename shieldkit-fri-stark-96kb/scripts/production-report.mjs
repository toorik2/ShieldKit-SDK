#!/usr/bin/env node
/**
 * Regenerate evidence/production/PRODUCTION_REPORT.json from the current evidence
 * (amended product config depth=20). Gates mirror the goal DONE list; releaseVerify
 * reads the latest RELEASE_VERDICT when present.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT, writeJson } from './lib/evidence.mjs';

const outDir = path.join(ROOT, 'evidence/production');
mkdirSync(outDir, { recursive: true });
const A = (kind) => path.join(outDir, `assemble-state0/assemble-${kind}-d20-b2048-n7-g30-base1.materialized.json`);
const KINDS = ['deposit', 'transfer', 'withdrawal'];

function read(p) { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null; }

// 1. productFlags — production verifiers, no placeholders (from the artifacts)
const arts = KINDS.map((k) => read(A(k))).filter(Boolean);
const productFlags =
  arts.length === 3 && arts.every((a) => a.productionVerifiers === true && a.placeholder !== true);

// 2. profileFixedLocks — kind-independent locks: identical redeem hashes across kinds
function lockIds(a) {
  return (a.roleInputs || [])
    .map((r) => createHash('sha256').update(String(r.redeemAsm || r.redeem || '')).digest('hex').slice(0, 16))
    .join(',');
}
const lockSets = arts.map(lockIds);
const profileFixedLocks = arts.length === 3 && new Set(lockSets).size === 1;

// 3. stateCovenantCantDoEvil — lifecycle policy + covenant compile
const life = read(path.join(outDir, 'one-tip-lifecycle/ONE_TIP_LIFECYCLE_REPORT.json'));
const stateCovenantCantDoEvil = life?.policy?.cantDoEvil === true && life?.createPool?.operatorKeySpendable === false;

// 4. offlineDtWLibauth — P1 reality ceilings + VM accepts
const p1r = read(path.join(ROOT, 'evidence/p1/P1_REALITY.json'));
const offlineDtWLibauth = p1r?.ok === true && p1r?.sizes?.estimatedTxBytes <= 100000;

// 5. productionFloorDomain — amended product domain (d20, T=1024, N=2^21)
const pf = arts[0];
const domain = pf?.domainPreflight || {};
const productionFloorDomain = arts.every((a) => a.depth === 20 && a.securityBits >= 100 && a.domainPreflight?.T === 1024 && a.domainPreflight?.N === 2097152);

// 6. combinedTipState0Fri — assembled tip VM accept (17/17, 0 fails)
const combinedTipState0Fri =
  arts.length === 3 && arts.every((a) => a.vm?.allAccept === true && (a.vm?.fails || []).length === 0 && a.vm?.nOk === 17);

// 7. chipnetLifecycle — live E2E with txids
const chipnetLifecycle = life?.ok === true && /^[0-9a-f]{64}$/.test(life?.createPool?.genesisTxid || '');

// 8. releaseVerify — the current release:verify run's hard gates (RUN_GATES marker)
const runGates = read(path.join(ROOT, 'evidence/release/RUN_GATES.json'));
const releaseVerify = runGates?.hardGatesOk === true && runGates?.p7ReleaseOk === true
  && runGates?.containmentOk === true && runGates?.forbiddenOk === true;

const gates = {
  productFlags, profileFixedLocks, stateCovenantCantDoEvil, offlineDtWLibauth,
  productionFloorDomain, combinedTipState0Fri, chipnetLifecycle, releaseVerify,
};
const blockers = [];
if (!productFlags) blockers.push('PRODUCT_FLAGS');
if (!profileFixedLocks) blockers.push('PROFILE_FIXED_LOCKS');
if (!stateCovenantCantDoEvil) blockers.push('STATE_COVENANT_CANT_DO_EVIL');
if (!offlineDtWLibauth) blockers.push('OFFLINE_DTW_LIBAUTH');
if (!productionFloorDomain) blockers.push('PRODUCTION_FLOOR_DOMAIN');
if (!combinedTipState0Fri) blockers.push('COMBINED_TIP_STATE0_FRI');
if (!chipnetLifecycle) blockers.push('CHIPNET_LIFECYCLE');
if (!releaseVerify) blockers.push('RELEASE_VERIFY_GREEN');

const report = {
  schema: 'shieldkit-fri-production-report-v1',
  ok: Object.values(gates).every(Boolean),
  publicationReady: Object.values(gates).every(Boolean),
  blockers,
  gates,
  sizes: Object.fromEntries(KINDS.map((k) => [k, arts.find((a) => a.kind === k)?.vm?.txBytes])),
  locks: { ok: profileFixedLocks, drifts: lockSets.length ? new Set(lockSets).size - 1 : -1 },
  lifecycle: life ? { ok: life.ok, genesisTxid: life.createPool?.genesisTxid,
    txs: ['deposit', 'transfer', 'withdrawal'].map((k) => life[k]?.txid) } : null,
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'PRODUCTION_REPORT.json'), report);
console.log(JSON.stringify(report, null, 2));
process.exit(report.ok ? 0 : 1);
