import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(resolve(root, path));
const json = (path) => JSON.parse(read(path));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const fail = (message) => {
  console.error(`policy check failed: ${message}`);
  process.exitCode = 1;
};
const git = (...args) => {
  try {
    return execFileSync('git', args, {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return undefined;
  }
};

const lock = json('policy/g0-lock.json');
const gates = json('policy/gates.json');
const decisions = read('docs/OPEN_QUESTIONS.md').toString('utf8');
const killGates = read('docs/KILL_GATES.md').toString('utf8');

if (lock.schema !== 'shield.cash/g0-lock/v1') fail('unsupported lock schema');
if (gates.schema !== 'shield.cash/gates/v1') fail('unsupported gates schema');
if (lock.freezeId !== gates.gates.G0.freeze) fail('G0 freeze identifiers differ');
if (lock.status !== gates.gates.G0.status) fail('G0 lock and gate statuses differ');
if (lock.baseline.scoreBytes !== 54949 || lock.baseline.wireBytes !== 54739) {
  fail('verifier baseline drifted');
}
if (lock.feeModel.type !== 'transparent-input-with-change') {
  fail('fee model drifted');
}

for (const id of lock.lockedDecisions) {
  if (!decisions.includes(`| ${id} | LOCKED`)) fail(`missing locked decision ${id}`);
}

for (const document of lock.documents) {
  const actual = sha256(read(document.path));
  if (actual !== document.sha256) {
    fail(`${document.path} hash ${actual} != frozen ${document.sha256}`);
  }
}

for (const [gate, record] of Object.entries(gates.gates)) {
  const row = `| ${gate} | ${record.status} |`;
  if (!killGates.includes(row)) fail(`human gate table disagrees for ${gate}`);
}

if (gates.gates.G0.status === 'PASS') {
  const head = git('rev-parse', '--verify', 'HEAD');
  const tagged = git('rev-parse', '--verify', `refs/tags/${lock.freezeTag}`);
  if (head && !tagged) {
    fail(`G0 is PASS but freeze tag ${lock.freezeTag} is missing`);
  }
  if (tagged) {
    const frozenManifest = git('show', `${lock.freezeTag}:policy/g0-lock.json`);
    if (frozenManifest !== read('policy/g0-lock.json').toString('utf8').trim()) {
      fail(`PASS lock manifest differs from ${lock.freezeTag}`);
    }
  }
}

if (!process.exitCode) {
  console.log(
    `policy check passed: ${lock.freezeId}, ${lock.lockedDecisions.length} decisions, `
      + `${lock.documents.length} frozen documents`,
  );
}
