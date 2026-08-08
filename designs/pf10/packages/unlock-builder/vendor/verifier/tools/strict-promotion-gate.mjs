// Promotion gate for the strict fixed-deployment profile. It consumes only
// frozen build/envelope/battery manifests and fails closed on any drift.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const OUT = process.env.OUT || '/tmp/verifier-cash-strict-promotion';
const MATRIX = process.env.MATRIX || `${OUT}/a1-matrix/matrix.json`;
const names = ['BASE', 'P1', 'P2', 'WORST'];
const roots = Object.fromEntries(names.map((name) => [name, process.env[`${name}_ROOT`]]));
const envelopes = Object.fromEntries(names.map((name) => [name, process.env[`${name}_ENVELOPE`]]));
const roles = Object.fromEntries(names.map((name) => [name, process.env[`${name}_ROLE`]]));
const deployments = Object.fromEntries(names.map((name) => [name, process.env[`${name}_DEPLOYMENT`]]));
const missing = names.flatMap((name) => [
  !roots[name] && `${name}_ROOT`, !envelopes[name] && `${name}_ENVELOPE`,
  !roles[name] && `${name}_ROLE`, !deployments[name] && `${name}_DEPLOYMENT`,
].filter(Boolean));
if (!process.env.MATRIX) missing.push('MATRIX');
if (missing.length) throw new Error(`strict promotion gate requires ${missing.join(', ')}`);
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const matrix = readJson(MATRIX);
if (matrix.schema !== 'verifier.cash/strict-a1-matrix/v1' || !matrix.gate.allGreen
  || matrix.gate.totalSkipped !== 0 || matrix.gate.totalNoOps !== 0
  || matrix.gate.totalGlobalFalseAccepts !== 0 || matrix.gate.totalStandardFalseAccepts !== 0) {
  throw new Error(`A1 matrix is not green: ${JSON.stringify(matrix.gate)}`);
}

const expected = { BASE: 82209, P1: 82086, P2: 82146, WORST: 82140 };
const fixtures = names.map((name) => {
  const result = readJson(`${roots[name]}/result.json`);
  const envelope = readJson(`${envelopes[name]}/manifest.json`);
  const role = readJson(`${roles[name]}/role-battery.json`);
  const deployment = readJson(`${deployments[name]}/strict-deployment-battery.json`);
  const accepts = result.manual?.length === 10 && result.manual.every((x) => x.accepts)
    && result.gateOk && result.score === expected[name] && result.wire < 100000
    && result.manual.every((x) => x.unlockLen < 10000);
  const envelopeGreen = envelope.gates.parentConsensusWholeTxAccept
    && envelope.gates.parentStandardWholeTxAccept
    && envelope.gates.parentLeanAccept
    && envelope.gates.parentOpCostParity
    && envelope.gates.spendConsensusWholeTxAccept
    && envelope.gates.spendStandardWholeTxAccept
    && envelope.gates.spendLeanAll
    && envelope.gates.spendOpCostParity
    && envelope.gates.vmbconfAll
    && envelope.vmbconf.standardTrue === 11
    && envelope.vmbconf.standardFalse === 0
    && envelope.gates.sourceResolutionExact
    && envelope.parent.outputValues.every((x) => x === '10000')
    && envelope.spend.outpointIndices.join(',') === '0,1,2,3,4,5,6,7,8,9'
    && envelope.spend.outpointParentTxid.length === 1;
  const roleGreen = role.globalAccepts.length === 0;
  const deploymentGreen = deployment.total === 12
    && deployment.globalAccepts.length === 0
    && deployment.standardGlobalAccepts.length === 0;
  const gate = { accepts, envelopeGreen, roleGreen, deploymentGreen, green: accepts && envelopeGreen && roleGreen && deploymentGreen };
  if (!gate.green) throw new Error(`${name} strict promotion gate failed: ${JSON.stringify(gate)}`);
  return {
    name,
    score: result.score,
    wire: result.wire,
    parentTxid: envelope.parent.internalTxid,
    candidateTxSha256: envelope.candidateWire.txSha256,
    sourceOutputsSha256: envelope.candidateWire.sourceOutputsSha256,
    a1: matrix.fixtures.find((x) => x.name === name)?.gate,
    gate,
  };
});

const parentTxids = [...new Set(fixtures.map((x) => x.parentTxid))];
if (parentTxids.length !== 1) throw new Error(`fixture parent txid drift: ${parentTxids.join(',')}`);
mkdirSync(OUT, { recursive: true });
const report = {
  schema: 'verifier.cash/strict-promotion-gate/v1',
  generatedAt: new Date().toISOString(),
  sourceCommit: matrix.sourceCommit,
  profile: 'strict fixed deployment envelope; common-parent exact-output family; no literal parent-txid pin',
  fixtures,
  gate: { allGreen: true, fixtureCount: fixtures.length, parentTxids },
};
writeFileSync(`${OUT}/promotion.json`, JSON.stringify(report, null, 2));
console.log(JSON.stringify({ out: `${OUT}/promotion.json`, gate: report.gate, fixtures: fixtures.map(({ name, score, wire, gate }) => ({ name, score, wire, gate })) }, null, 2));
