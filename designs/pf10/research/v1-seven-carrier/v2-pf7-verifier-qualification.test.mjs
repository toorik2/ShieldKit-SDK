import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  canonicalJson,
  parseV2Pf7QualificationArguments,
  runV2Pf7VerifierQualification,
  V2Pf7VerifierQualificationError,
} from './v2-pf7-verifier-qualification.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const write = async (filename, contents) => {
  await mkdir(path.dirname(filename), { recursive: true });
  await writeFile(filename, contents);
  return { path: filename, bytes: Buffer.byteLength(contents), sha256: hash(contents) };
};

async function fixture({ differingWidth = false } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-pf7-test-'));
  const verifierRoot = path.join(root, 'verifier');
  const entrypoint = 'fake-build.mjs';
  const fake = `#!/usr/bin/env node\nimport { mkdir, writeFile } from 'node:fs/promises';\nimport path from 'node:path';\nconst action = process.env.C7_SHIELD_ACTION_PACKET_FILE.includes('transfer') ? 'transfer' : process.env.C7_SHIELD_ACTION_PACKET_FILE.includes('withdrawal') ? 'withdrawal' : 'deposit';\nconst width = action === 'transfer' && ${differingWidth ? 'true' : 'false'} ? 7001 : 7000;\nconst manual = Array.from({length: 10}, (_, i) => ({ name: i < 7 ? 'verifier-' + i : ['packet','state','fee'][i - 7], accepts: i < 7, unlockLen: i < 7 ? width + i : 0, operationCost: i < 7 ? 100 + i : null }));\nawait mkdir(process.env.C7_TMP, {recursive:true});\nawait writeFile(path.join(process.env.C7_TMP, 'result.json'), JSON.stringify({built:true,gateOk:true,verifierInputCount:7,structuralRoleCount:3,structuralRolesUnevaluated:true,wire:54321,score:55000,manual}));\nconsole.log('fake PF7 build ' + action);\n`;
  const executable = await write(path.join(verifierRoot, entrypoint), fake);
  await chmod(executable.path, 0o755);
  const setupPath = path.join(root, 'setup.json');
  const setup = { schema: 'shieldkit-v2-pf7-verifier-qualification-setup-v1', qualificationClass: 'test-fixture', executable: entrypoint, entrypoint, environment: { PATH: process.env.PATH, C7_STRUCTURAL_ROLE_COUNT: '3', C7_SHIELD_ACTION_PACKET_ABI: 'sda2-v2-direct', C7_UNLOCK_LENGTH_STABILIZE: '1', C7_MAXTRY: '0' } };
  const setupEvidence = await write(setupPath, JSON.stringify(setup));
  const artifactsPath = path.join(root, 'artifacts.json');
  await write(artifactsPath, JSON.stringify({ schema: 'shieldkit-v2-pf7-verifier-qualification-artifacts-v1', files: [{ path: entrypoint, bytes: executable.bytes, sha256: executable.sha256 }] }));
  const actions = {};
  for (const action of ['deposit', 'transfer', 'withdrawal']) {
    const packet = Buffer.concat([Buffer.from('SDA2'), Buffer.alloc(548, action.charCodeAt(0))]);
    const packetEvidence = await write(path.join(root, `${action}-packet.bin`), packet);
    const adapterEvidence = await write(path.join(root, `${action}-v2-direct-groth16-adapter.json`), JSON.stringify({ action }));
    actions[action] = { packetDigest: packetEvidence.sha256, witnessValid: true, proofVerified: true, files: { packet: packetEvidence, v2DirectGroth16Adapter: adapterEvidence } };
  }
  const evidencePath = path.join(root, 'qualification-evidence.json');
  await write(evidencePath, JSON.stringify({ schema: 'shieldkit-v2-direct-development-groth16-qualification-v4', actions }));
  return {
    root,
    verifierRoot,
    setup: setupPath,
    setupEvidence,
    artifacts: artifactsPath,
    qualificationEvidence: evidencePath,
    outputDirectory: path.join(root, 'output'),
  };
}

test('requires explicit absolute paths and stable canonical JSON', () => {
  assert.throws(() => parseV2Pf7QualificationArguments(['--verifier-root', 'relative']), /missing required|absolute/);
  const parsed = parseV2Pf7QualificationArguments(['--verifier-root', '/root', '--qualification-evidence', '/evidence', '--setup', '/setup', '--artifacts', '/artifacts', '--output', '/output']);
  assert.equal(parsed.outputDirectory, '/output');
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{\n  "a": {\n    "b": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test('runs a fake child only as non-qualification fixture and records all measured roles', async () => {
  const config = await fixture();
  const result = await runV2Pf7VerifierQualification(config);
  assert.equal(result.manifest.qualificationStatus, 'not-qualification-test-fixture');
  assert.equal(result.manifest.claims.bch2026SevenVerifierRoles, false);
  assert.equal(result.manifest.actions.deposit.verifierRoles.length, 7);
  assert.deepEqual(result.manifest.actions.deposit.structuralRoles.map((role) => role.status), ['unevaluated', 'unevaluated', 'unevaluated']);
  const persisted = JSON.parse(await readFile(result.manifestPath, 'utf8'));
  assert.equal(persisted.frozenBuild.noRunnerRetries, true);
});

test('fails closed on pinned verifier drift and fixed-width mismatch', async () => {
  const drift = await fixture();
  await writeFile(path.join(drift.verifierRoot, 'fake-build.mjs'), '#!/usr/bin/env node\nprocess.exit(0)\n');
  await assert.rejects(() => runV2Pf7VerifierQualification(drift), /artifact hash drift/);
  const mismatch = await fixture({ differingWidth: true });
  await assert.rejects(() => runV2Pf7VerifierQualification(mismatch), V2Pf7VerifierQualificationError);
});

test('rejects the superseded development-evidence schema without fallback', async () => {
  const config = await fixture();
  await writeFile(
    config.qualificationEvidence,
    JSON.stringify({ schema: 'shieldkit-v2-direct-development-groth16-qualification-v2', actions: {} }),
  );
  await assert.rejects(
    () => runV2Pf7VerifierQualification(config),
    /qualification evidence schema must be shieldkit-v2-direct-development-groth16-qualification-v4/,
  );
});
