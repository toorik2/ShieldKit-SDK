import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA,
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from './pf10-action-witness.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
  buildDirectV2Pf10BetaRuntime,
} from './pf10-development-runtime-builder.mjs';
import { assertPf10BetaRuntimeLane } from './pf10-beta-runtime-assertions.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const verificationKeyFixture = path.join(
  repositoryRoot,
  '03-create-your-own-pool/packages/prove/test-fixtures/two-public/verification_key.json',
);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function generatedBetaInputs(root) {
  const artifactsDirectory = path.join(root, 'proof-artifacts');
  await mkdir(artifactsDirectory, { mode: 0o700 });
  const fixtures = Object.freeze({
    provingKey: Buffer.from('deterministic PF10 beta proving-key fixture\n'),
    r1cs: Buffer.from('deterministic PF10 beta r1cs fixture\n'),
    verificationKey: await readFile(verificationKeyFixture),
    wasm: Buffer.from('deterministic PF10 beta witness-wasm fixture\n'),
  });
  const filenames = Object.freeze({
    provingKey: 'fixture.zkey',
    r1cs: 'fixture.r1cs',
    verificationKey: 'verification_key.json',
    wasm: 'fixture.wasm',
  });
  return Object.freeze({
    profileId: 'ab'.repeat(32),
    proofArtifacts: Object.freeze(Object.fromEntries(await Promise.all(
      Object.entries(fixtures).map(async ([name, bytes]) => {
        const filename = path.join(artifactsDirectory, filenames[name]);
        await writeFile(filename, bytes, { flag: 'wx', mode: 0o600 });
        return [name, Object.freeze({ path: filename, sha256: sha256(bytes) })];
      }),
    ))),
  });
}

test('PF10 beta runtime has a distinct material/build/witness lane with generated portable artifacts', async () => {
  assert.equal(DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA, 'shieldkit-v2-direct-pf10-beta-runtime-material-v1');
  assert.equal(DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA, 'shieldkit-v2-direct-pf10-beta-runtime-build-v1');
  assert.equal(DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA, 'shieldkit-v2-direct-pf10-beta-action-witness-v1');
  assert.equal(DIRECT_V2_PF10_BETA_ELIGIBILITY, 'beta-single-contributor-unqualified');
  const buildRoot = path.join(repositoryRoot, '.codex-build');
  await mkdir(buildRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = await mkdtemp(path.join(buildRoot, 'pf10-beta-runtime-test-'));
  try {
    const inputs = await generatedBetaInputs(temporaryRoot);
    const runtime = await buildDirectV2Pf10BetaRuntime({
      repositoryRoot,
      temporaryRoot,
      profileId: inputs.profileId,
      instanceId: 'be'.repeat(32),
      proofArtifacts: inputs.proofArtifacts,
    });
    assertPf10BetaRuntimeLane(runtime, inputs);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
        libauthEvidence: inputs.proofArtifacts.r1cs,
      }),
      /does not accept Libauth evidence/u,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
