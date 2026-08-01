import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA,
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  buildDirectV2Pf10ActionWitness,
  validateDirectV2Pf10BetaRuntimeMaterial,
  validateDirectV2Pf10RuntimeMaterial,
} from './pf10-action-witness.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
  buildDirectV2Pf10BetaRuntime,
} from './pf10-development-runtime-builder.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const profilePackagePath = path.join(
  repositoryRoot,
  '.codex-build/v2-development-profile/profile-package.json',
);
const profileCorePath = path.join(
  repositoryRoot,
  '.codex-build/v2-development-profile/profile-core.json',
);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function betaInputs() {
  const profilePackage = JSON.parse(await readFile(profilePackagePath, 'utf8'));
  const proofArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(profilePackage.proofArtifacts)
      .filter(([name]) => [
        'provingKey', 'r1cs', 'verificationKey', 'witnessWasm',
      ].includes(name))
      .map(([name, record]) => [
        name === 'witnessWasm' ? 'wasm' : name,
        Object.freeze({
          path: path.resolve(repositoryRoot, record.path),
          sha256: record.sha256,
        }),
      ]),
  ));
  return Object.freeze({ profileId: profilePackage.profileId, proofArtifacts });
}

test('PF10 beta runtime has a distinct material/build/witness lane', async (t) => {
  for (const required of [profileCorePath, profilePackagePath]) {
    if (!existsSync(required)) {
      t.skip(`requires locally generated PF10 development artifact: ${required}`);
      return;
    }
  }
  assert.equal(
    DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
    'shieldkit-v2-direct-pf10-beta-runtime-material-v1',
  );
  assert.equal(
    DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
    'shieldkit-v2-direct-pf10-beta-runtime-build-v1',
  );
  assert.equal(
    DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA,
    'shieldkit-v2-direct-pf10-beta-action-witness-v1',
  );
  assert.equal(
    DIRECT_V2_PF10_BETA_ELIGIBILITY,
    'beta-single-contributor-unqualified',
  );

  const inputs = await betaInputs();
  const temporaryRoot = await mkdtemp(path.join(
    repositoryRoot,
    '.codex-build/pf10-beta-runtime-test-',
  ));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const runtime = await buildDirectV2Pf10BetaRuntime({
    repositoryRoot,
    temporaryRoot,
    profileId: inputs.profileId,
    instanceId: 'be'.repeat(32),
    proofArtifacts: inputs.proofArtifacts,
  });

  assert.equal(runtime.schema, DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA);
  assert.equal(runtime.eligibility, DIRECT_V2_PF10_BETA_ELIGIBILITY);
  assert.equal(Object.hasOwn(runtime, 'libauthEvidence'), false);
  assert.equal(runtime.runtimeMaterial.schema, DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA);
  assert.equal(
    runtime.runtimeMaterialInput.schema,
    DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  );
  assert.equal(
    runtime.runtimeMaterialInput.eligibility,
    DIRECT_V2_PF10_BETA_ELIGIBILITY,
  );
  assert.equal(
    runtime.runtimeMaterial.proofArtifactHashes.verificationKey,
    sha256(await readFile(inputs.proofArtifacts.verificationKey.path)),
  );
  assert.equal(
    validateDirectV2Pf10BetaRuntimeMaterial(runtime.runtimeMaterialInput)
      .materialSha256,
    runtime.runtimeMaterial.materialSha256,
  );

  assert.throws(
    () => validateDirectV2Pf10RuntimeMaterial(runtime.runtimeMaterialInput),
    /eligibility|schema/u,
  );
  assert.throws(
    () => validateDirectV2Pf10RuntimeMaterial({
      ...runtime.runtimeMaterialInput,
      schema: 'shieldkit-v2-direct-pf10-runtime-material-v1',
      eligibility: undefined,
    }),
    /eligibility/u,
  );
  assert.throws(
    () => buildDirectV2Pf10ActionWitness({
      runtimeMaterial: runtime.runtimeMaterial,
    }),
    /validateDirectV2Pf10RuntimeMaterial/u,
  );
  assert.throws(
    () => validateDirectV2Pf10BetaRuntimeMaterial({
      ...runtime.runtimeMaterialInput,
      schema: 'shieldkit-v2-direct-pf10-runtime-material-v1',
      eligibility: 'development-only',
    }),
    /schema|eligibility/u,
  );
  await assert.rejects(
    buildDirectV2Pf10BetaRuntime({
      repositoryRoot,
      temporaryRoot,
      profileId: inputs.profileId,
      instanceId: 'be'.repeat(32),
      proofArtifacts: inputs.proofArtifacts,
      libauthEvidence: {
        path: inputs.proofArtifacts.r1cs.path,
        sha256: inputs.proofArtifacts.r1cs.sha256,
      },
    }),
    /does not accept Libauth evidence/u,
  );
});
