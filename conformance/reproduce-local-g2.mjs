// Reproduce only the locally executable G2-adjacent checks. This intentionally
// does not contact BCH nodes, broadcast, load wallet material, or claim that a
// structural fixture is a complete PF7/Chipnet action.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const suites = Object.freeze([
  {
    id: 'settlement-context',
    directory: 'packages/settlement-context',
    tier: 'structural',
    limitation: 'Canonical SCCT encoding and negative binding checks only; no BCH VM or proof claim.',
  },
  {
    id: 'settlement-transaction',
    directory: 'packages/settlement-transaction',
    tier: 'structural',
    limitation: 'Canonical transaction builder and negative role/context checks only; no BCH VM or proof claim.',
  },
  {
    id: 'preparation-transaction',
    directory: 'packages/preparation-transaction',
    tier: 'libauth-bch2026-vm',
    limitation: 'Local Libauth standard-VM preparation P2PKH checks; not BCHN relay/inclusion or complete settlement evidence.',
  },
  {
    id: 'compressed-covenants',
    directory: 'bch/g2-compressed-covenants',
    tier: 'libauth-bch2026-vm',
    limitation: 'Local Libauth covenant fixtures; excludes real PF7 proof roles, full standardness, BCHN, and Chipnet.',
  },
]);

const sha256 = (filename) => `sha256:${createHash('sha256').update(readFileSync(filename)).digest('hex')}`;
const command = (program, args, options = {}) => execFileSync(program, args, {
  cwd: root,
  encoding: 'utf8',
  stdio: 'pipe',
  ...options,
}).trim();

const git = (args) => command('git', args);
const status = git(['status', '--porcelain=v1']);
const rows = [];
for (const suite of suites) {
  const directory = resolve(root, suite.directory);
  const packageJson = resolve(directory, 'package.json');
  if (!existsSync(resolve(directory, 'node_modules'))) {
    throw new Error(
      `${suite.id}: dependencies are absent; run `
      + `TMPDIR=/home/toorik/Projects/ZK-Proofs/.codex-artifacts/tmp `
      + `npm ci --no-audit --no-fund in ${suite.directory}`,
    );
  }
  command('npm', ['test'], { cwd: directory });
  rows.push(Object.freeze({
    id: suite.id,
    tier: suite.tier,
    packageJsonSha256: sha256(packageJson),
    limitation: suite.limitation,
    verdict: 'PASS',
  }));
}

console.log(JSON.stringify({
  schema: 'shield.cash/local-g2-reproduction/v1',
  qualification: 'local reproducibility transcript only; G1 remains OPEN and G2 remains NOT ENTERED',
  source: Object.freeze({
    commit: git(['rev-parse', 'HEAD']),
    dirty: status.length !== 0,
    node: process.version,
  }),
  suites: rows,
  excluded: Object.freeze([
    'LeanBCH: not run by this self-contained runner; use a clean pinned checkout and a separately recorded differential.',
    'BCHN standardness, peer relay, miner inclusion, and Chipnet execution.',
    'Complete real PF7 proof-role execution and proof corpus qualification.',
  ]),
}, null, 2));
