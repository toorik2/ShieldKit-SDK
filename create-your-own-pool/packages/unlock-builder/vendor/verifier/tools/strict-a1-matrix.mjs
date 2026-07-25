// Run the same no-placeholder A1 battery against the frozen BASE/P1/P2/WORST
// candidate roots and fail closed on skipped rows or whole-tx false accepts.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';

const REPO = process.env.REPO || process.cwd();
const OUT = process.env.OUT || '/tmp/verifier-cash-strict-a1-matrix';
const BATTERY = `${REPO}/tools/strict-a1-battery.mjs`;
const names = ['BASE', 'P1', 'P2', 'WORST'];
const roots = Object.fromEntries(names.map((name) => [name, process.env[`${name}_ROOT`]]));
const missing = names.filter((name) => !roots[name]);
if (missing.length) throw new Error(`strict A1 matrix requires ${missing.map((x) => `${x}_ROOT`).join(', ')}`);
mkdirSync(OUT, { recursive: true });

const sourceCommit = process.env.SOURCE_COMMIT
  || spawnSync('git', ['-C', REPO, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
if (!/^[0-9a-f]{40}$/.test(sourceCommit)) throw new Error(`invalid source commit: ${sourceCommit}`);

const run = (name) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [BATTERY], {
    cwd: REPO,
    env: { ...process.env, ROOT: roots[name], OUT: `${OUT}/${name.toLowerCase()}`, SOURCE_COMMIT: sourceCommit },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', (x) => { stdout += x; });
  child.stderr.on('data', (x) => { stderr += x; });
  child.on('error', reject);
  child.on('close', (code) => code === 0 ? resolve({ name, stdout, stderr }) : reject(new Error(`${name} A1 exit=${code}\n${stderr}\n${stdout}`)));
});

const results = await Promise.all(names.map(run));
const requiredEncodingClasses = ['OP_0', 'DIRECT', 'PUSHDATA1', 'PUSHDATA2', 'PUSHDATA4', 'OP_1NEGATE', 'OP_1_TO_16'];
const reports = results.map(({ name }) => {
  const path = `${OUT}/${name.toLowerCase()}/a1-results.json`;
  const summary = JSON.parse(readFileSync(path, 'utf8'));
  const counts = Object.values(summary.counts);
  const gate = {
    total: counts.reduce((n, x) => n + x.total, 0),
    executed: counts.reduce((n, x) => n + x.executed, 0),
    skipped: counts.reduce((n, x) => n + x.skipped, 0),
    noOps: summary.noOps.length,
    falseAccepts: summary.falseAccepts.length,
    standardFalseAccepts: summary.standardFalseAccepts.length,
    encodingClassesMissing: summary.coverage.encodingClassesMissing,
    artifactSha256: summary.artifactSha256,
  };
  if (gate.total !== 89 || gate.executed !== 89 || gate.skipped !== 0 || gate.noOps !== 0
    || gate.falseAccepts !== 0 || gate.standardFalseAccepts !== 0
    || JSON.stringify(gate.encodingClassesMissing) !== '[]'
    || !/^[0-9a-f]{64}$/.test(gate.artifactSha256)) {
    throw new Error(`${name} A1 gate failed: ${JSON.stringify(gate)}`);
  }
  for (const klass of requiredEncodingClasses) {
    if (!summary.coverage.encodingClassesExercised.includes(klass)) throw new Error(`${name} missing encoding class ${klass}`);
  }
  return { name, root: roots[name], report: path, gate, targetOnlyFalseAccepts: summary.targetOnlyFalseAccepts };
});

const matrix = {
  schema: 'verifier.cash/strict-a1-matrix/v1',
  sourceCommit,
  generatedAt: new Date().toISOString(),
  requiredEncodingClasses,
  fixtures: reports,
  gate: {
    fixtureCount: reports.length,
    allGreen: reports.length === 4,
    totalRows: reports.reduce((n, x) => n + x.gate.total, 0),
    totalSkipped: reports.reduce((n, x) => n + x.gate.skipped, 0),
    totalNoOps: reports.reduce((n, x) => n + x.gate.noOps, 0),
    totalGlobalFalseAccepts: reports.reduce((n, x) => n + x.gate.falseAccepts, 0),
    totalStandardFalseAccepts: reports.reduce((n, x) => n + x.gate.standardFalseAccepts, 0),
  },
};
if (!matrix.gate.allGreen || matrix.gate.totalSkipped || matrix.gate.totalNoOps
  || matrix.gate.totalGlobalFalseAccepts || matrix.gate.totalStandardFalseAccepts) {
  throw new Error(`strict A1 matrix failed: ${JSON.stringify(matrix.gate)}`);
}
writeFileSync(`${OUT}/matrix.json`, JSON.stringify(matrix, null, 2));
console.log(JSON.stringify({ out: `${OUT}/matrix.json`, gate: matrix.gate, fixtures: reports.map((x) => ({ name: x.name, rows: x.gate.total, targetOnlyFalseAccepts: x.targetOnlyFalseAccepts })) }, null, 2));
