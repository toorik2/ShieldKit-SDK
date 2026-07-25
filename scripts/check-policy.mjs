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

const lock = json('dev/protocol/policy/g0-lock.json');
const gates = json('dev/protocol/policy/gates.json');
const decisions = read('docs/OPEN_QUESTIONS.md').toString('utf8');
const killGates = read('docs/KILL_GATES.md').toString('utf8');

if (lock.schema !== 'shield.cash/g0-lock/v1') fail('unsupported lock schema');
if (gates.schema !== 'shield.cash/gates/v1') fail('unsupported gates schema');
if (lock.freezeId !== gates.gates.G0.freeze) fail('G0 freeze identifiers differ');
if (lock.status !== gates.gates.G0.status) fail('G0 lock and gate statuses differ');
if (lock.baseline.scoreBytes !== 54949 || lock.baseline.wireBytes !== 54739) {
  fail('verifier baseline drifted');
}
if (
  lock.selectedVerifier.candidate !== 'bn254-onetx-pf7-sub62-r1'
  || lock.selectedVerifier.commit !== '26468ae29004d2401619032de2a6ec8de269a4d6'
  || lock.selectedVerifier.inputs !== 7
  || lock.selectedVerifier.measuredReferenceWireBytes !== 54296
  || lock.selectedVerifier.measuredReferenceScoreBytes !== 54541
  || lock.selectedVerifier.measuredMaxUnlockingBytes !== 9176
  || lock.selectedVerifier.perInputUnlockingLimitBytes !== 10000
  || lock.selectedVerifier.completeTransactionWireLimitBytes !== 59000
  || lock.selectedVerifier.percentageHeadroomRequired !== false
  || lock.selectedVerifier.largerGenericFallbackAllowed !== false
) {
  fail('selected seven-input verifier boundary drifted');
}
if (lock.feeModel.type !== 'transparent-input-with-change') {
  fail('fee model drifted');
}
if (
  lock.verifierProfile.interface !== 'shield.cash/verifier-profile/v1'
  || lock.verifierProfile.selection !== 'profile-bound-at-genesis'
  || lock.verifierProfile.developmentSetup.allowed !== true
  || lock.verifierProfile.developmentSetup.mode !== 'development-only'
  || lock.verifierProfile.developmentSetup.initializer !== 'local'
  || lock.verifierProfile.productionSetup.required !== true
  || lock.verifierProfile.productionSetup.mode !== 'ceremony-production'
  || lock.verifierProfile.productionSetup.multiPartyRandomness !== true
  || lock.verifierProfile.productionSetup.transcriptRequired !== true
  || lock.verifierProfile.replacement.newProfileRequired !== true
  || lock.verifierProfile.replacement.newGenesisRequired !== true
  || lock.verifierProfile.replacement.hotSwapExistingInstance !== false
) {
  fail('verifier profile boundary drifted');
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
  const candidateFreeze = process.env.SHIELD_FREEZE_CANDIDATE === lock.freezeId;
  if (head && !tagged && !candidateFreeze) {
    fail(`G0 is PASS but freeze tag ${lock.freezeTag} is missing`);
  }
  // Byte-compare lock only when the freeze tag still contains the *current* path.
  // After a layout migration (policy/ → dev/protocol/policy/), re-tag or set
  // SHIELD_FREEZE_CANDIDATE=g0-v3 until a new freeze tag is cut.
  if (tagged && !candidateFreeze) {
    const frozenManifest = git('show', `${lock.freezeTag}:dev/protocol/policy/g0-lock.json`);
    const current = read('dev/protocol/policy/g0-lock.json').toString('utf8').trim();
    if (frozenManifest && frozenManifest !== current) {
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
