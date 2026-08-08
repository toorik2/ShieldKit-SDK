#!/usr/bin/env node
/**
 * measure-residual-baseline.mjs — extract PF7 residual anchors from a green run.
 *
 *   node lanes/bn254-onetx/src/c7/measure-residual-baseline.mjs
 *   node lanes/bn254-onetx/src/c7/measure-residual-baseline.mjs --run .vc/runs/gen6-7in-r3
 *
 * Pure measurement: no build. Writes lanes/bn254-onetx/reports/pf7-residual-baseline.json
 * and a short markdown next to residual experiments note.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(__dirname, '../..');
const REPO = resolve(LANE, '../..');
const MAX_UNLOCK = 10000;

const runIdx = process.argv.indexOf('--run');
const runDir = resolve(REPO, runIdx >= 0 ? process.argv[runIdx + 1] : '.vc/runs/gen6-7in-r3');

function die(msg) {
  console.error(msg);
  process.exit(1);
}

if (!existsSync(runDir)) die(`run dir missing: ${runDir}`);
const result = JSON.parse(readFileSync(join(runDir, 'build/result.json'), 'utf8'));
const opmargin = existsSync(join(runDir, 'build/c7_opmargin.json'))
  ? JSON.parse(readFileSync(join(runDir, 'build/c7_opmargin.json'), 'utf8'))
  : null;
const log = existsSync(join(runDir, 'build.log')) ? readFileSync(join(runDir, 'build.log'), 'utf8') : '';

let roles = null;
let bqBytes = null;
let identity = null;
{
  const rm = log.match(/"pairfoldRoles":(\[.*?\])(?=,|\n|\}|\s*$)/s)
    || log.match(/pairfoldRoles":(\[.*?\])(?=\})/s);
  if (rm) {
    try { roles = JSON.parse(rm[1]); } catch { /* ignore */ }
  }
  // Fallback: line-oriented scan for the JSON blob printed by build.ts
  if (!roles) {
    const line = log.split('\n').find((l) => l.includes('pairfoldRoles'));
    if (line) {
      try {
        const start = line.indexOf('[');
        const end = line.lastIndexOf(']');
        if (start >= 0 && end > start) roles = JSON.parse(line.slice(start, end + 1));
      } catch { /* ignore */ }
    }
  }
  const bm = log.match(/"bqBytes":(\d+)/);
  if (bm) bqBytes = Number(bm[1]);
  const im = log.match(/=== (BN254 PairFold-\d+[^=]+) ===/);
  if (im) identity = im[1].trim();
}

const unlocks = (result.manual || []).map((m) => ({
  name: m.name,
  unlockLen: m.unlockLen,
  headroom: MAX_UNLOCK - m.unlockLen,
  knifeEdge: (MAX_UNLOCK - m.unlockLen) <= 50,
}));

const totalRecords = roles ? roles.reduce((s, r) => s + r.records, 0) : null;
const totalTables = roles ? roles.reduce((s, r) => s + r.table, 0) : null;
const modes = roles ? roles.reduce((s, r) => s + r.modes, 0) : null;

const baseline = {
  schema: 'verifier.cash/pf7-residual-baseline/v1',
  runDir,
  measuredAt: new Date().toISOString(),
  identity,
  score: result.score,
  gateOk: result.gateOk,
  wire: result.wire,
  sigmaLock: result.sigmaLock,
  sigmaUnlock: result.sigmaUnlock,
  unlocks,
  knifeEdge: unlocks.filter((u) => u.knifeEdge),
  roles,
  totals: {
    records: totalRecords,
    tables: totalTables,
    modes,
    meanRecordPerMode: totalRecords && modes ? Math.round(totalRecords / modes) : null,
    meanRecordPerPairApprox: totalRecords ? Math.round(totalRecords / 31) : null,
  },
  bqBytes,
  opmargin,
  residualImplications: {
    scoreIdentity: 'score tracks scriptBytes + tx overhead; unlock is density capacity',
    knifeEdgeNote: 'Only knife-edge unlocks convert residual unlock cuts into density pressure relief',
    recordPassThroughHint: 0.12,
    bqPassThroughHint: 0.08,
    opCutScorePerPercentHint: 25,
    maxCredibleSingleLeverDelta: 1200,
  },
};

const reports = join(LANE, 'reports');
mkdirSync(reports, { recursive: true });
writeFileSync(join(reports, 'pf7-residual-baseline.json'), JSON.stringify(baseline, null, 2));
writeFileSync(join(reports, 'pf7-residual-experiments.md'), [
  '# PF7 residual experiments (measured baseline)',
  '',
  `Run: \`${runDir}\``,
  `Score: **${baseline.score}** gateOk=${baseline.gateOk}`,
  identity ? `Identity: ${identity}` : '',
  '',
  '## Unlocks',
  '',
  ...unlocks.map((u) =>
    `- **${u.name}**: ${u.unlockLen} (headroom ${u.headroom})${u.knifeEdge ? ' **KNIFE-EDGE**' : ''}`),
  '',
  '## Records / tables',
  '',
  roles
    ? roles.map((r) => `- role${r.i} ${JSON.stringify(r.range)} records=${r.records} table=${r.table} modes=${r.modes}`).join('\n')
    : '_pairfoldRoles not found in build.log_',
  '',
  `Totals: records=${totalRecords} tables=${totalTables} mean≈${baseline.totals.meanRecordPerPairApprox} B/pair`,
  `BQ: ${bqBytes ?? 'unknown'}`,
  '',
  '## Credible residual program (ordered)',
  '',
  '1. **Op-cost on shared composed body** (~25 score / 1% if density-bound) — hard, highest class',
  '2. **Table rebalance** (top-up / witness table bytes) — runnable realTx probe',
  '3. **Thin records on knife-edge roles only** — partial; measure unlock first',
  '4. **BQ carriage** (not raw byte delete) — terminal headroom ≈ '
    + `${unlocks.find((u) => u.name === 'terminal')?.headroom ?? '?'} B`,
  '5. **Frag rebalance** — careful; exec0/4 already tight',
  '',
  'Do **not** claim multi-kB score from 1:1 record or BQ cuts. Pass-through ≪ 1.',
  '',
  'Companion surface vault: `zk-verifier-surface/ideas/vault/residual/EXPERIMENTS.md`',
  '',
].join('\n'));

console.log(JSON.stringify({
  ok: true,
  score: baseline.score,
  knifeEdge: baseline.knifeEdge,
  totals: baseline.totals,
  bqBytes,
  reports: join(reports, 'pf7-residual-baseline.json'),
}, null, 2));
