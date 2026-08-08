#!/usr/bin/env node
/** P0 — Containment, provenance, legal, baseline freeze */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { ROOT, writeJson, containmentAssert, sha256File } from './lib/evidence.mjs';

const outDir = path.join(ROOT, 'evidence/p0');
mkdirSync(outDir, { recursive: true });

const checks = [];

// plan present
const plan = path.join(ROOT, 'FRI_STARK_REPLACEMENT_PLAN.md');
checks.push({
  id: 'plan-present',
  ok: existsSync(plan),
  sha256: existsSync(plan) ? sha256File(plan) : null,
});

// containment
const cont = containmentAssert();
checks.push({ id: 'containment', ok: cont.ok, root: cont.root, bad: cont.bad });

// vendor pin
const pinPath = path.join(ROOT, 'vendor/bch-fri-stark/VENDORED_COMMIT');
const pin = existsSync(pinPath) ? readFileSync(pinPath, 'utf8').trim() : null;
checks.push({
  id: 'vendor-pin',
  ok: pin === 'a600e828d68eb41840049cb16d0c21850ff9df57',
  pin,
});

// baseline inventory
const inv = path.join(ROOT, 'vendor/BASELINE_INVENTORY.sha256');
checks.push({
  id: 'baseline-inventory',
  ok: existsSync(inv) && readFileSync(inv, 'utf8').split('\n').filter(Boolean).length > 10,
  lines: existsSync(inv) ? readFileSync(inv, 'utf8').split('\n').filter(Boolean).length : 0,
  sha256: existsSync(inv) ? sha256File(inv) : null,
});

// 98k vectors
const bench = path.join(ROOT, 'vendor/goldilocks-98k-baseline/vectors/sound-secure-bench-result.json');
let benchOk = false;
let benchMeta = null;
if (existsSync(bench)) {
  benchMeta = JSON.parse(readFileSync(bench, 'utf8'));
  benchOk = benchMeta?.config?.nq === 7
    && benchMeta?.config?.blowup === 2048
    && benchMeta?.config?.grind_b === 30;
}
checks.push({ id: 'baseline-98k-config', ok: benchOk, benchMeta: benchMeta?.config ?? null });

// license / source grant notice
const license = path.join(ROOT, 'LICENSE');
const notices = path.join(ROOT, 'THIRD_PARTY_NOTICES.md');
if (!existsSync(license)) {
  writeFileSync(license, `UNLICENSED — internal Chipnet beta only until explicit source grant materializes (P0 legal).\n`);
}
if (!existsSync(notices)) {
  writeFileSync(
    notices,
    `# Third-party notices\n\n- BCH-FRI-STARK-Verifier lineage @ a600e828d68eb41840049cb16d0c21850ff9df57 (research; not production-hardened upstream).\n- @bitauth/libauth (BCH VM primitives).\n`,
  );
}
checks.push({ id: 'license-notices', ok: existsSync(license) && existsSync(notices) });

// wire size constants in code
const stateSrc = readFileSync(path.join(ROOT, 'packages/core/codecs/state.mjs'), 'utf8');
const packetSrc = readFileSync(path.join(ROOT, 'packages/core/codecs/packet.mjs'), 'utf8');
checks.push({
  id: 'wire-constants',
  ok: stateSrc.includes('STATE_BYTES = 128') && packetSrc.includes('PACKET_BYTES = 424'),
});

const ok = checks.every((c) => c.ok);
const report = {
  gate: 'P0',
  name: 'containment-provenance-legal',
  ok,
  checks,
  command: 'npm run qualify:bootstrap',
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'P0_REPORT.json'), report);
console.log(JSON.stringify(report, null, 2));
process.exit(ok ? 0 : 1);
