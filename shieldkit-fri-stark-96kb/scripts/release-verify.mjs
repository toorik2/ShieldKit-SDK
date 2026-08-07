#!/usr/bin/env node
/**
 * release:verify — run P0–P7 acceptance commands; emit RELEASE_VERDICT.json
 * and plan-required INFEASIBILITY_REPORT.json when hard bars fail.
 *
 * Never green-washes placeholders, tip-only Chipnet, or SLA misses.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT, writeJson, forbiddenScan, containmentAssert } from './lib/evidence.mjs';
import { buildInfeasibilityReport } from './lib/infeasibility.mjs';

const outDir = path.join(ROOT, 'evidence/release');
mkdirSync(outDir, { recursive: true });

const gates = [
  { id: 'P0', cmd: ['npm', 'run', 'qualify:bootstrap'] },
  { id: 'P1', cmd: ['npm', 'run', 'qualify:security'] },
  { id: 'P1b', cmd: ['npm', 'run', 'qualify:reality'] },
  { id: 'P2', cmd: ['npm', 'run', 'qualify:corpus'] },
  { id: 'P3P4', cmd: ['npm', 'run', 'qualify:clean-host'] },
  { id: 'P5', cmd: ['npm', 'run', 'qualify:scale'] },
  { id: 'P6', cmd: ['npm', 'run', 'qualify:package'] },
  { id: 'P7', cmd: ['node', 'scripts/qualify-p7-chipnet.mjs'] },
  { id: 'RN', cmd: ['node', 'scripts/qualify-randomness-gates.mjs'] },
];

const results = [];
for (const g of gates) {
  console.error(`[release:verify] ${g.id}: ${g.cmd.join(' ')}`);
  const r = spawnSync(g.cmd[0], g.cmd.slice(1), {
    cwd: ROOT,
    encoding: 'utf8',
    env: process.env,
    timeout: 15_000_000,
  });
  results.push({
    id: g.id,
    cmd: g.cmd.join(' '),
    status: r.status,
    ok: r.status === 0,
    stdoutTail: (r.stdout || '').slice(-2000),
    stderrTail: (r.stderr || '').slice(-2000),
  });
  // Continue through all gates so infeasibility package is complete (do not early-break).
}

const cont = containmentAssert();
const forbid = forbiddenScan();
let p7soft = false;
let p7ok = false;
let p7OutOfScope = false;
let p7OutOfScopeBy = null;
const p7path = path.join(ROOT, 'evidence/p7/P7_REPORT.json');
const oosPath = path.join(ROOT, 'evidence/p7/OUT_OF_SCOPE.json');
if (existsSync(p7path)) {
  try {
    const p7 = JSON.parse(readFileSync(p7path, 'utf8'));
    p7soft = p7.softEnvironmental === true;
    p7ok = p7.ok === true && p7.fullDualHostJourney?.ok === true;
  } catch {
    p7soft = false;
    p7ok = false;
  }
}
// Goal contract: P0-P7 green OR documented infeasible/out-of-scope with evidence.
// The operator decision lives in OUT_OF_SCOPE.json (not touched by the gate).
if (existsSync(oosPath)) {
  try {
    const oos = JSON.parse(readFileSync(oosPath, 'utf8'));
    p7OutOfScope = oos.outOfScope === true;
    p7OutOfScopeBy = oos.outOfScopeBy || null;
  } catch {
    p7OutOfScope = false;
  }
}

const hard = results.filter((r) => r.id !== 'P7');

// Run-gates marker for the production report (breaks the report<->verdict cycle).
{
  const marker = {
    schema: 'shieldkit-fri-release-run-gates-v1',
    hardGatesOk: hard.every((r) => r.ok),
    p7ReleaseOk: p7ok === true || p7OutOfScope === true,
    containmentOk: cont.ok,
    forbiddenOk: forbid.ok,
    timestamp: new Date().toISOString(),
  };
  writeJson(path.join(ROOT, 'evidence/release/RUN_GATES.json'), marker);
}
// Regenerate the production report from the fresh gate evidence, then read it.
{
  const pr = spawnSync('node', [path.join(ROOT, 'scripts/production-report.mjs')], {
    cwd: ROOT, encoding: 'utf8', timeout: 120_000,
  });
  if (pr.status !== 0) {
    console.error(`[release:verify] production-report regeneration failed rc=${pr.status}: ${(pr.stderr || '').slice(0, 500)}`);
  }
}
// Production publication report (profile-fixed locks + lifecycle honesty) — read AFTER regeneration.
let prodOk = false;
let prodBlockers = [];
const prodPath = path.join(ROOT, 'evidence/production/PRODUCTION_REPORT.json');
if (existsSync(prodPath)) {
  try {
    const prod = JSON.parse(readFileSync(prodPath, 'utf8'));
    prodOk = prod.publicationReady === true && prod.ok === true;
    prodBlockers = prod.blockers || [];
  } catch {
    prodOk = false;
    prodBlockers = ['PRODUCTION_REPORT_UNREADABLE'];
  }
} else {
  prodBlockers = ['PRODUCTION_REPORT_MISSING'];
}
const p7cmd = results.find((r) => r.id === 'P7');
// Hard gates must pass; P7 passes as a REAL full journey OR as a documented
// operator out-of-scope decision with evidence (goal contract). Soft env alone
// is not release green.
// Publication also requires production report green (profile-fixed locks + one-tip lifecycle).
const hardOk = hard.every((r) => r.ok);
const p7ReleaseOk = p7ok === true || p7OutOfScope === true;
const ok = hardOk && p7ReleaseOk && cont.ok && forbid.ok && prodOk === true;

const infeasibility = buildInfeasibilityReport({ gateResults: results });

const verdict = {
  schema: 'shieldkit-fri-stark-release-verdict-v1',
  ok,
  infeasibilityStop: !ok && infeasibility.releaseBlocking === true,
  package: 'shieldkit-fri-stark@0.1.0-beta.1',
  claim: ok
    ? 'ShieldKit-FRI Beta — unaudited, Chipnet-only, fresh-genesis experimental profile; zero-conf admission/readback; no mainnet, production, encrypted-note privacy, or Groth-pool compatibility claim.'
    : null,
  claimForbidden: !ok,
  gates: results,
  containment: cont,
  forbiddenScan: forbid,
  p7EnvironmentalSoft: p7soft,
  p7FullJourneyOk: p7ok,
  p7OutOfScope,
  p7OutOfScopeBy,
  productionPublicationOk: prodOk,
  productionBlockers: prodBlockers,
  infeasibilityPath: 'evidence/infeasibility/INFEASIBILITY_REPORT.json',
  infeasibilityBlockingIds: infeasibility.blockingIds,
  evidenceDir: 'evidence/',
  timestamp: new Date().toISOString(),
};

writeJson(path.join(outDir, 'RELEASE_VERDICT.json'), verdict);
// Also copy verdict into infeasibility dir for stable stop package
writeJson(path.join(ROOT, 'evidence/infeasibility/RELEASE_VERDICT.json'), verdict);

console.log(JSON.stringify(verdict, null, 2));
// Exit 0 only for true release green. Exit 2 = measured infeasibility stop (consistent).
// Exit 1 = unexpected tool failure without infeasibility package.
if (ok) process.exit(0);
if (verdict.infeasibilityStop) process.exit(2);
process.exit(1);
